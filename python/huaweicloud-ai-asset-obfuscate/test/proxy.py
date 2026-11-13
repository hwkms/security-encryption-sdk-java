from flask import Flask, request, jsonify, Response, stream_with_context
from transformers import AutoTokenizer
import requests
import json
import time
import os
import logging
import threading
from dotenv import load_dotenv
from ai_asset_obfuscate import DataAssetObfuscation
from ai_asset_obfuscate.vision_api import ImageDataAssetObfuscation, VideoDataAssetObfuscation

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_thread_local = threading.local()

# 使用零宽空格作为分段分隔符，避免token decode自带空格导致split边界错乱
# 必须与 start_vllm_space.py 中的 SEGMENT_SEPARATOR 保持一致
SEGMENT_SEPARATOR = '\u200b'

'''
V5版本：在V4基础上增加混淆开关，通过 ENABLE_OBFUSCATION 控制：
- 开启混淆(obf_flag=True)：保持V4原有流程，输入混淆，输出解混淆
- 关闭混淆(obf_flag=False)：
  - 请求侧：文本 → tokenize → 按token逐个decode → 空格拼接分段文本发送（不混淆）
  - 响应侧：仅做 token_ids → 文本 转换（不解混淆）
  - 图像/视频：正常读取和base64编码，不做混淆
'''
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

app = Flask(__name__)

load_dotenv()
model_path = os.getenv('TOKENIZER_PATH', '/data/Qwen3-1.7B/')
server_ip = os.getenv('SERVER_IP', '0.0.0.0')
service_port = int(os.getenv('SERVICE_PORT', '8111'))
obf_flag = os.getenv('ENABLE_OBFUSCATION', 'True').lower() == 'true'
data_obf_seed = os.getenv('DATA_OBFUSCATION_SEED', '22222222222222222222222222222222')
white_list_str = os.getenv('WHITE_LIST',
                           '[151643,151644,151645,151646,151647,151648,151649,151650,151651,151652,151653,151654,151655,151656,151657,151658,151659,151660,151661,151662,151663,151664,151665,151666,151667,151668,198,2610,525,264,10950,17847,13,872,77091,8948]')
input_mode = os.getenv('INPUT_MODE', 'text').lower()

if input_mode not in ('token', 'text'):
    logger.error(f"INPUT_MODE must be 'token' or 'text', got: {input_mode}, fallback to 'text'")
    input_mode = 'text'

logger.info(f"model_path: {model_path}, input_mode: {input_mode}, obf_flag: {obf_flag}")

# BPE分词器用于输入侧编码，SpaceTokenizer用于解混淆时按空格精确还原token_id
_bpe_tokenizer = AutoTokenizer.from_pretrained(model_path)


class SpaceTokenizer:
    """基于空格分词的Tokenizer，通过反向词表精确还原token_id

    反向词表支持多token映射（UTF-8多字节截断）：
    单token映射：decoded_text → int
    多token映射：decoded_text → list[int]（连续\ueffd的token合并decode后的文本）
    """

    def __init__(self, real_tokenizer):
        self._real_tokenizer = real_tokenizer
        self._text_to_id = {}
        vocab_size = getattr(real_tokenizer, 'vocab_size', len(real_tokenizer.get_vocab()))
        for tid in range(vocab_size):
            decoded = real_tokenizer.decode([tid], skip_special_tokens=True)
            if decoded and decoded not in self._text_to_id:
                self._text_to_id[decoded] = tid

        # 补充多token序列映射：2-token、3-token组合
        partial_ids = []
        for tid in range(vocab_size):
            decoded = real_tokenizer.decode([tid], skip_special_tokens=True)
            if decoded.endswith("\ufffd") or not decoded:
                partial_ids.append(tid)

        multi_count = 0
        for n in (2, 3):
            for i in range(len(partial_ids) - n + 1):
                combo = partial_ids[i:i + n]
                decoded = real_tokenizer.decode(combo, skip_special_tokens=True)
                if decoded and not decoded.endswith("\ufffd") and decoded not in self._text_to_id:
                    self._text_to_id[decoded] = combo
                    multi_count += 1

        logger.info(f"SpaceTokenizer: reverse vocab built, {len(self._text_to_id)} mappings (multi-token: {multi_count})")

    def encode(self, text, add_special_tokens=False):
        token_ids = []
        for part in text.split(SEGMENT_SEPARATOR):
            if not part:
                continue
            if part in self._text_to_id:
                val = self._text_to_id[part]
                if isinstance(val, list):
                    token_ids.extend(val)
                else:
                    token_ids.append(val)
            else:
                token_ids.extend(self._real_tokenizer.encode(part, add_special_tokens=False))
        return token_ids

    def decode(self, token_ids, skip_special_tokens=True):
        return self._real_tokenizer.decode(token_ids, skip_special_tokens=skip_special_tokens)

    def __getattr__(self, name):
        return getattr(self._real_tokenizer, name)


tokenizer = SpaceTokenizer(_bpe_tokenizer)

token_infer_url = f"http://{server_ip}:{service_port}/v1/chat/completions"
server_url = f"http://{server_ip}:{service_port}"

prev_token_id = []
combine_flag = False


if obf_flag:
    model_config_path = os.path.join(model_path, 'config.json')
    with open(model_config_path, "r", encoding="utf-8") as f:
        model_config = json.load(f)
    vocab_size = model_config.get('text_config', model_config).get('vocab_size')
    try:
        white_list = json.loads(white_list_str)
    except json.JSONDecodeError as e:
        logger.error(f"JSON parse failed: {e}")

    data_obf_obj = DataAssetObfuscation(vocab_size, white_list)
    result = data_obf_obj.set_seed_content(data_obf_seed)
    print(f"DSC 上报结果: {result}")
    image_obf_obj = ImageDataAssetObfuscation()
    image_obf_obj.set_seed_content(data_obf_seed)
    video_obf_obj = VideoDataAssetObfuscation()
    video_obf_obj.set_seed_content(data_obf_seed)


# ============================================================
# 共享工具函数
# ============================================================

def extract_text_tokens(messages):
    """从messages中提取每条消息的BPE token_ids"""
    result = []
    for msg in messages:
        msg_tokens = []
        content = msg.get("content", "")
        if isinstance(content, str):
            msg_tokens.extend(_bpe_tokenizer.encode(content, add_special_tokens=False))
        elif isinstance(content, list):
            for item in content:
                if item.get("type") == "text":
                    msg_tokens.extend(_bpe_tokenizer.encode(item.get("text", ""), add_special_tokens=False))
        result.append(msg_tokens)
    return result


def count_image_urls_per_message(messages):
    result = []
    for msg in messages:
        count = 0
        content = msg.get("content", "")
        if isinstance(content, list):
            for item in content:
                if item.get("type") in ("image_url", "imageurl"):
                    count += 1
        result.append(count)
    return result


def build_obf_tokens(text_tokens, image_url_counts):
    obf_text_tokens = []
    for tokens, img_count in zip(text_tokens, image_url_counts):
        obf_text_tokens.append(data_obf_obj.data_1d_obf(tokens) if tokens else [])
    return obf_text_tokens


def process_image_video_item(item):
    """处理图像/视频项：读取文件/base64编码；混淆仅当obf_flag开启时执行"""
    if item.get("type") not in ("image_url", "video_url"):
        return item

    data_key = "image_url" if item.get("type") == "image_url" else "video_url"
    url_data = item.get(data_key, {})
    if not isinstance(url_data, dict):
        return item

    url = url_data.get("url", "")

    if url.startswith("file:///"):
        file_path = url.replace("file:///", "/")
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            import base64 as b64
            base64_data = b64.b64encode(file_data).decode('utf-8')
            if item.get("type") == "image_url":
                ext = os.path.splitext(file_path)[1].lower().lstrip('.') or 'jpg'
                mime = f'image/{ext}' if ext != 'jpg' else 'image/jpeg'
            else:
                ext = os.path.splitext(file_path)[1].lower().lstrip('.') or 'mp4'
                mime = f'video/{ext}' if ext else 'video/mp4'
            data_prefix = f"data:{mime};base64,"
            if obf_flag:
                obf_fn = image_obf_obj.image_base64_obf if item.get("type") == "image_url" else video_obf_obj.video_base64_obf
                new_url = data_prefix + obf_fn(base64_data)
            else:
                new_url = data_prefix + base64_data
            return {**item, data_key: {**url_data, "url": new_url}}
        except Exception as e:
            logger.error(f"Failed to process file {file_path}: {e}")
            return item
    elif url.startswith("data:"):
        try:
            comma_idx = url.find(",")
            if comma_idx == -1:
                return item
            data_prefix = url[:comma_idx + 1]
            base64_data = url[comma_idx + 1:]
            if obf_flag:
                obf_fn = image_obf_obj.image_base64_obf if item.get("type") == "image_url" else video_obf_obj.video_base64_obf
                new_url = data_prefix + obf_fn(base64_data)
            else:
                new_url = url
            return {**item, data_key: {**url_data, "url": new_url}}
        except Exception as e:
            logger.error(f"Failed to process base64 data: {e}")
            return item
    else:
        return item


def obfuscate_text_to_text(text):
    """text -> BPE tokens -> obfuscate -> space-separated text. Returns (obf_text, orig_ids, obf_ids)

    处理UTF-8多字节截断：连续产生\ufffd的token合并decode，
    确保每个空格分隔片段都能通过反向词表正确映射回token_id序列。
    """
    tokens = _bpe_tokenizer.encode(text, add_special_tokens=False)
    if obf_flag and tokens:
        obf_tokens = data_obf_obj.data_1d_obf(tokens)
        parts = []
        pending_ids = []
        for tid in obf_tokens:
            decoded = _bpe_tokenizer.decode([tid], skip_special_tokens=True)
            if decoded.endswith("\ufffd") or not decoded:
                # 截断或空，累积待合并
                pending_ids.append(tid)
            else:
                # 先输出累积的截断token（合并decode）
                if pending_ids:
                    combined = _bpe_tokenizer.decode(pending_ids, skip_special_tokens=True)
                    if combined:
                        parts.append(combined)
                    pending_ids = []
                parts.append(decoded)
        # 处理末尾剩余
        if pending_ids:
            combined = _bpe_tokenizer.decode(pending_ids, skip_special_tokens=True)
            if combined:
                parts.append(combined)
        # 首尾加SEGMENT_SEPARATOR，确保chat template包裹后内容段与模板文本分离
        obf_text = SEGMENT_SEPARATOR + SEGMENT_SEPARATOR.join(parts) + SEGMENT_SEPARATOR

        # ── Pipeline诊断：输入侧混淆 ──
        logger.debug(f"[PIPELINE-REQ] 原始文本: {text!r}")
        logger.debug(f"[PIPELINE-REQ] 原始token_ids({len(tokens)}): {tokens}")
        logger.debug(f"[PIPELINE-REQ] 混淆token_ids({len(obf_tokens)}): {obf_tokens}")
        logger.debug(f"[PIPELINE-REQ] 混淆分段文本: {obf_text!r}")
        # 反向验证：从混淆分段文本还原token_ids → 解混淆 → 对比
        restored_ids = tokenizer.encode(obf_text, add_special_tokens=False)
        deobf_ids = [data_obf_obj.token_deobf(tid) for tid in restored_ids]
        deobf_text = tokenizer.decode(deobf_ids, skip_special_tokens=True)
        logger.debug(f"[PIPELINE-REQ] SpaceTokenizer还原ids({len(restored_ids)}): {restored_ids}")
        logger.debug(f"[PIPELINE-REQ] 还原ids==混淆ids: {restored_ids == obf_tokens}")
        logger.debug(f"[PIPELINE-REQ] 解混淆token_ids({len(deobf_ids)}): {deobf_ids}")
        logger.debug(f"[PIPELINE-REQ] 解混淆文本: {deobf_text!r}")
        logger.debug(f"[PIPELINE-REQ] 解混淆文本==原始文本: {deobf_text == text}")
        if deobf_text != text or deobf_ids != tokens:
            logger.warning(f"[PIPELINE-REQ] ⚠ ROUNDTRIP MISMATCH!")
            if restored_ids != obf_tokens:
                for i in range(max(len(restored_ids), len(obf_tokens))):
                    a = obf_tokens[i] if i < len(obf_tokens) else None
                    b = restored_ids[i] if i < len(restored_ids) else None
                    if a != b:
                        logger.warning(f"  首个还原差异: idx={i}, 混淆id={a}, 还原id={b}")
                        break
            if deobf_ids != tokens:
                for i in range(max(len(deobf_ids), len(tokens))):
                    a = tokens[i] if i < len(tokens) else None
                    b = deobf_ids[i] if i < len(deobf_ids) else None
                    if a != b:
                        logger.warning(f"  首个解混淆差异: idx={i}, 原始id={a}, 解混淆id={b}")
                        break

        return obf_text, tokens, obf_tokens
    return text, tokens, tokens


def tokenize_to_segmented_text(text):
    """text -> BPE tokens -> 逐token decode -> 空格拼接分段文本（不混淆）

    与 obfuscate_text_to_text 类似的分段逻辑，但跳过混淆步骤，
    返回按token边界空格分隔的原始文本，用于混淆关闭时仍保持token级分段。
    处理UTF-8多字节截断：连续产生\ufffd的token合并decode。
    Returns (segmented_text, orig_ids, token_ids)  其中 orig_ids == token_ids
    """
    tokens = _bpe_tokenizer.encode(text, add_special_tokens=False)
    if not tokens:
        return text, [], []

    parts = []
    pending_ids = []
    for tid in tokens:
        decoded = _bpe_tokenizer.decode([tid], skip_special_tokens=True)
        if decoded.endswith("\ufffd") or not decoded:
            pending_ids.append(tid)
        else:
            if pending_ids:
                combined = _bpe_tokenizer.decode(pending_ids, skip_special_tokens=True)
                if combined:
                    parts.append(combined)
                pending_ids = []
            parts.append(decoded)
    if pending_ids:
        combined = _bpe_tokenizer.decode(pending_ids, skip_special_tokens=True)
        if combined:
            parts.append(combined)

    # 首尾加SEGMENT_SEPARATOR，确保chat template包裹后内容段与模板文本分离
    segmented_text = SEGMENT_SEPARATOR + SEGMENT_SEPARATOR.join(parts) + SEGMENT_SEPARATOR

    # ── Pipeline诊断：输入侧分段（不混淆）──
    logger.debug(f"[PIPELINE-REQ] 原始文本: {text!r}")
    logger.debug(f"[PIPELINE-REQ] 原始token_ids({len(tokens)}): {tokens}")
    logger.debug(f"[PIPELINE-REQ] 分段文本(不混淆): {segmented_text!r}")
    restored_ids = tokenizer.encode(segmented_text, add_special_tokens=False)
    restored_text = tokenizer.decode(restored_ids, skip_special_tokens=True)
    logger.debug(f"[PIPELINE-REQ] SpaceTokenizer还原ids({len(restored_ids)}): {restored_ids}")
    logger.debug(f"[PIPELINE-REQ] 还原ids==原始ids: {restored_ids == tokens}")
    logger.debug(f"[PIPELINE-REQ] 还原文本: {restored_text!r}")
    logger.debug(f"[PIPELINE-REQ] 还原文本==原始文本: {restored_text == text}")

    return segmented_text, tokens, tokens


def deobf_text(text):
    """space-separated text -> SpaceTokenizer restore ids -> deobfuscate -> text"""
    if not obf_flag or not text:
        return text, [], []
    token_ids = tokenizer.encode(text, add_special_tokens=False)
    deobf_ids = [data_obf_obj.token_deobf(tid) for tid in token_ids]
    return tokenizer.decode(deobf_ids, skip_special_tokens=True), token_ids, deobf_ids


def decode_token_ids(token_ids):
    """batch decode token_ids to text

    VLLM的lm_head已混淆：VLLM输出的是混淆空间id，
    需先token_deobf还原原始id，再用原始BPE tokenizer decode得到正确文本。
    不混淆时直接decode。
    """
    if not token_ids:
        return ""
    if obf_flag:
        deobf_ids = [data_obf_obj.token_deobf(tid) for tid in token_ids]
    else:
        deobf_ids = token_ids
    return _bpe_tokenizer.decode(deobf_ids, skip_special_tokens=True)


def decode_token_id_stream(token_id):
    """streaming single-token decode，含UTF-8多字节截断处理。

    VLLM的lm_head已混淆：需先token_deobf还原原始id，再BPE decode。
    """
    global combine_flag, prev_token_id

    if obf_flag:
        token_id = data_obf_obj.token_deobf(token_id)

    if combine_flag:
        combined_text = _bpe_tokenizer.decode(prev_token_id + [token_id], skip_special_tokens=True)
        if combined_text.endswith("\ufffd"):
            prev_token_id = prev_token_id + [token_id]
            return ""
        combine_flag = False
        prev_token_id = []
        return combined_text

    curr_text = _bpe_tokenizer.decode([token_id], skip_special_tokens=True)
    if curr_text.endswith("\ufffd"):
        prev_token_id = prev_token_id + [token_id]
        combine_flag = True
        return ""
    return curr_text


# ============================================================
# 请求构建
# ============================================================

DONE_SIGNAL = "data: [DONE]"


def build_base_req(original_req, is_stream):
    """构建两种模式共用的请求字段"""
    return {
        "messages": original_req.get("messages", [{}]),
        "max_tokens": original_req.get("max_tokens", 512),
        "return_token_ids": original_req.get("return_token_ids", True),
        "frequency_penalty": original_req.get("frequency_penalty", 0.0),
        "ignore_eos": original_req.get("ignore_eos", False),
        "logprobs": original_req.get("logprobs", False),
        "n": original_req.get("n", 1),
        "presence_penalty": original_req.get("presence_penalty", 0.0),
        "response_format": original_req.get("response_format"),
        "stop": original_req.get("stop"),
        "stream": is_stream,
        "temperature": original_req.get("temperature", 1.0),
        "top_p": original_req.get("top_p", 1.0),
        "tools": original_req.get("tools"),
        "tool_choice": original_req.get("tool_choice"),
        "user": original_req.get("user"),
    }


def convert_to_token_req_token_mode(original_req, is_stream):
    """Token模式：文本置空，混淆token通过token字段传递给VLLM（仅混淆开启时）"""
    messages = original_req.get("messages", [{}])
    text_tokens = extract_text_tokens(messages)

    if obf_flag:
        image_url_counts = count_image_urls_per_message(messages)
        text_tokens = build_obf_tokens(text_tokens, image_url_counts)
        req_messages = []
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                req_messages.append({**msg, "content": ""})
            elif isinstance(content, list):
                new_content = []
                for item in content:
                    if item.get("type") == "text":
                        new_content.append({"type": "text", "text": ""})
                    elif item.get("type") in ("image_url", "video_url"):
                        new_content.append(process_image_video_item(item))
                    else:
                        new_content.append(item)
                req_messages.append({**msg, "content": new_content})
            else:
                req_messages.append(msg)
    else:
        # V5: 混淆关闭时，仍做tokenize分段，置空文本，传原始token
        req_messages = []
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                req_messages.append({**msg, "content": ""})
            elif isinstance(content, list):
                new_content = []
                for item in content:
                    if item.get("type") == "text":
                        new_content.append({"type": "text", "text": ""})
                    elif item.get("type") in ("image_url", "video_url"):
                        new_content.append(process_image_video_item(item))
                    else:
                        new_content.append(item)
                req_messages.append({**msg, "content": new_content})
            else:
                req_messages.append(msg)

    token_req = build_base_req(original_req, is_stream)
    token_req["messages"] = req_messages
    token_req["token"] = text_tokens

    logger.info(f"Proxy->VLLM(token mode, obf={obf_flag}): {len(req_messages)} messages")
    return token_req


def convert_to_token_req_text_mode(original_req, is_stream):
    """Text模式：
    - 混淆开启：混淆后转为混淆文本发送，SpaceTokenizer hook负责还原为混淆id
    - 混淆关闭：tokenize后按token边界分段文本发送，SpaceTokenizer还原为原始id
    注意：VLLM不支持token字段，需依赖SpaceTokenizer hook在VLLM侧做分词还原
    """
    messages = original_req.get("messages", [{}])

    req_messages = []
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            if obf_flag:
                converted_text, _, _ = obfuscate_text_to_text(content)
            else:
                converted_text, _, _ = tokenize_to_segmented_text(content)
            req_messages.append({**msg, "content": converted_text})
        elif isinstance(content, list):
            new_content = []
            for item in content:
                if item.get("type") == "text":
                    if obf_flag:
                        converted_text, _, _ = obfuscate_text_to_text(item.get("text", ""))
                    else:
                        converted_text, _, _ = tokenize_to_segmented_text(item.get("text", ""))
                    new_content.append({"type": "text", "text": converted_text})
                elif item.get("type") in ("image_url", "video_url"):
                    new_content.append(process_image_video_item(item))
                else:
                    new_content.append(item)
            req_messages.append({**msg, "content": new_content})
        else:
            req_messages.append(msg)

    token_req = build_base_req(original_req, is_stream)
    token_req["model"] = original_req.get("model", "qwen3-vl")
    token_req["messages"] = req_messages

    logger.info(f"Proxy->VLLM(text mode, obf={obf_flag}): {len(req_messages)} messages")
    return token_req


def convert_to_token_req(original_req, is_stream):
    if input_mode == 'text':
        return convert_to_token_req_text_mode(original_req, is_stream)
    else:
        return convert_to_token_req_token_mode(original_req, is_stream)


# ============================================================
# 响应处理
# ============================================================

def stream_response(response, original_req):
    """流式响应：从VLLM响应中的token_ids解码后返回文本
    - 混淆开启：解混淆+decode
    - 混淆关闭：仅decode
    """
    global prev_token_id, combine_flag
    prev_token_id = []
    combine_flag = False

    response_id = f"chatcmpl-{int(time.time())}"

    def generate():
        for chunk in response.iter_content(chunk_size=None):
            if not chunk:
                continue
            event_data = chunk.decode().strip()
            if not event_data.startswith("data:"):
                continue
            if event_data.strip() == DONE_SIGNAL:
                continue

            token_response = json.loads(event_data[5:].strip())
            if token_response is None:
                yield 'data: {"error": "Invalid token response"}\n\n'
                return

            choices = token_response.get('choices', [{}])
            token_ids = choices[0].get('token_ids') if choices else None

            if token_ids is not None:
                if not isinstance(token_ids, list):
                    token_ids = [token_ids]

                delta_content = "".join(decode_token_id_stream(tid) for tid in token_ids)
                # ── Pipeline诊断：流式输出侧解码 ──
                if obf_flag:
                    deobf_ids = [data_obf_obj.token_deobf(tid) for tid in token_ids]
                    logger.debug(f"[PIPELINE-RESP-STREAM] token_ids(混淆): {token_ids} → deobf: {deobf_ids} → text: {delta_content!r}")
                else:
                    logger.debug(f"[PIPELINE-RESP-STREAM] token_ids: {token_ids} → text: {delta_content!r}")

                choice_data = {
                    "index": choices[0].get("index", 0),
                    "delta": {"role": "assistant", "content": delta_content},
                    "logprobs": choices[0].get("logprobs"),
                }
                finish_reason = choices[0].get('finish_reason')
                if finish_reason:
                    choice_data["finish_reason"] = finish_reason
                    choice_data["stop_reason"] = choices[0].get('stop_reason')

                chunk_json = json.dumps({
                    'id': response_id,
                    'object': 'chat.completion.chunk',
                    'created': int(time.time()),
                    'model': original_req.get('model'),
                    'choices': [choice_data],
                }, ensure_ascii=False)
                yield f"data: {chunk_json}\n\n"
            else:
                # 无token_ids时原样透传
                yield f"{event_data}\n\n"
        yield DONE_SIGNAL + "\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


def non_stream_response(response, original_req):
    """非流式响应：从token_ids解码后转为文本覆盖content
    - 混淆开启：解混淆+decode
    - 混淆关闭：仅decode
    """
    response_json = response.json()

    choices = response_json.get("choices", [{}])
    message = choices[0].get("message", {}) if choices else {}
    token_ids = choices[0].get("token_ids") if choices else None

    if token_ids is not None:
        generated_text = decode_token_ids(token_ids)
        # ── Pipeline诊断：输出侧解码 ──
        if obf_flag:
            deobf_ids = [data_obf_obj.token_deobf(tid) for tid in token_ids]
            logger.debug(f"[PIPELINE-RESP] VLLM返回token_ids(混淆空间): {token_ids}")
            logger.debug(f"[PIPELINE-RESP] 解混淆token_ids(原始空间): {deobf_ids}")
            logger.debug(f"[PIPELINE-RESP] BPE decode文本: {generated_text!r}")
        else:
            logger.debug(f"[PIPELINE-RESP] VLLM返回token_ids: {token_ids}")
            logger.debug(f"[PIPELINE-RESP] decode文本: {generated_text!r}")
    else:
        generated_text = message.get("content", "")

    json_result = {
        "id": response_json.get("id", f"chatcmpl-{int(time.time())}"),
        "object": "chat.completion",
        "created": response_json.get("created", int(time.time())),
        "model": response_json.get("model", original_req.get("model")),
        "choices": [{
            "index": 0,
            "message": {"role": message.get("role", "assistant"), "content": generated_text},
            "finish_reason": message.get("finish_reason"),
            "logprobs": choices[0].get("logprobs") if choices else None,
        }],
        "usage": {
            "prompt_tokens": response_json.get("usage", {}).get("prompt_tokens", 0),
            "completion_tokens": response_json.get("usage", {}).get("completion_tokens", 0),
            "total_tokens": response_json.get("usage", {}).get("prompt_tokens", 0) + response_json.get("usage", {}).get("completion_tokens", 0),
        },
    }
    return Response(json.dumps(json_result, ensure_ascii=False), mimetype='application/json')


# ============================================================
# API路由
# ============================================================

def call_token_api(token_req, original_req, is_stream=True):
    headers = {'Content-Type': 'application/json'}
    if is_stream:
        headers = {'Accept': 'text/event-stream'}
    resp = requests.post(token_infer_url, headers=headers, json=token_req, stream=True)

    if resp.status_code != 200:
        raise Exception(f"Token API error: {resp.text}")

    if is_stream:
        return stream_response(resp, original_req)
    else:
        return non_stream_response(resp, original_req)


@app.route('/v1/chat/completions', methods=['POST'])
def proxy_inference():
    try:
        original_req = request.get_json()
        logger.info(f"Client->Proxy: stream={original_req.get('stream')}, mode={input_mode}, obf={obf_flag}")

        token_req = convert_to_token_req(original_req, original_req.get("stream"))
        return call_token_api(token_req, original_req, original_req.get("stream"))
    except Exception as e:
        return Response(json.dumps({"error": str(e)}, ensure_ascii=False), status=500, mimetype='application/json')


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def forward_request(path):
    target_url = f"{server_url}/{path}"
    try:
        headers = dict(request.headers)
        headers.pop('Host', None)
        headers.pop('Content-Length', None)
        headers.pop('Content-Type', None)

        resp = requests.request(
            method=request.method, url=target_url, headers=headers,
            data=request.get_data(), cookies=request.cookies, allow_redirects=False,
        )

        response = app.make_response(resp.content)
        response.status_code = resp.status_code
        for key, value in resp.headers.items():
            if key.lower() not in ['content-length', 'content-encoding']:
                response.headers[key] = value
        return response
    except requests.exceptions.RequestException as e:
        return Response(json.dumps({"error": str(e)}, ensure_ascii=False), status=500, mimetype='application/json')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6606, debug=True, use_reloader=False)

