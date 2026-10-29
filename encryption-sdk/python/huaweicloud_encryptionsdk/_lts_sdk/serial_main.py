import argparse
import random

from loguru import logger

from huaweicloud_encryptionsdk._lts_sdk.producer.core.producer import Producer
from huaweicloud_encryptionsdk._lts_sdk.producer.model import lts_store
from huaweicloud_encryptionsdk._lts_sdk.producer.model.config import Config
from huaweicloud_encryptionsdk._lts_sdk.utils import common


def generate_random_str(str_len=16):
    """
    生成一个指定长度的随机字符串
    """
    random_str = ''
    base_str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
    length = len(base_str) - 1
    for i in range(str_len):
        random_str += base_str[random.randint(0, length)]
    return random_str


def send_log_single_producer(endpoint, ak, sk, region_id, project_id, group_id, stream_id, log_count, log_size):
    log_num = log_count
    config = Config()
    config.endpoint = endpoint
    config.access_key = ak
    config.access_secret = sk
    config.region_id = region_id
    config.project_id = project_id
    producer = Producer.init_producer(config)
    producer.start_producer()

    group_id = group_id
    stream_id = stream_id

    batch_num = 20
    count = int(log_num/batch_num)
    leave = log_num % batch_num

    logger.info("send count is {}, leave is {}", count, leave)

    log_content = generate_random_str(log_size)
    labels = {"keyA": "valueA"}
    log = []
    for i in range(batch_num):
        log.append(log_content)
    log_p = lts_store.generate_log(log, labels)

    begin_ms = common.current_time_ms()
    for i in range(count):
        producer.send_log(group_id, stream_id, log_p)
    log.clear()

    if leave > 0:
        for i in range(leave):
            log.append(log_content)
        log_p = lts_store.generate_log(log, labels)
        producer.send_log(group_id, stream_id, log_p)
    end_ms = common.current_time_ms()
    logger.info("end send log, cost [{}]ms", end_ms - begin_ms)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='lts python sdk send log help tester information')
    parser.add_argument('--endpoint', dest='endpoint', type=str, help='lts endpoint')
    parser.add_argument('--ak', dest='ak', type=str, help='huaweicloud ak')
    parser.add_argument('--sk', dest='sk', type=str, help='huaweicloud sk')
    parser.add_argument('--region', dest='region', type=str, help='huaweicloud region')
    parser.add_argument('--project_id', dest='project_id', type=str, help='huaweicloud project_id')
    parser.add_argument('--group_id', dest='group_id', type=str, help='send log group_id')
    parser.add_argument('--stream_id', dest='stream_id', type=str, help='send log stream_id')
    parser.add_argument('--log_count', dest='log_count', type=int, help='send log log_count')
    parser.add_argument('--log_size', dest='log_size', type=int, help='send log log_size(byte)')
    args = parser.parse_args()
    send_log_single_producer(args.endpoint, args.ak, args.sk, args.region, args.project_id, args.group_id, args.stream_id, args.log_count, args.log_size)
