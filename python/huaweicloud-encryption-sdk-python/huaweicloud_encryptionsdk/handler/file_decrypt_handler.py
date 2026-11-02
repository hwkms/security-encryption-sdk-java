from huaweicloud_encryptionsdk.handler.cipher_handler import CipherHandler, DECRYPT_MODE
from huaweicloud_encryptionsdk.model.cipher_header import CipherHeader
from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage
from huaweicloud_encryptionsdk.common.utils import serialize_context


class FileDecryptHandler:

    def __init__(self, algorithm, secret_key, mode):
        self._mode = mode
        self._algorithm = algorithm
        self._secret_key = secret_key
        self._un_parsed_byte = b""
        self._header = None

    def process_byte(self, input_stream, output_stream, encryption_context, block_size):
        try:
            cipher_handler = CipherHandler(self._algorithm, self._secret_key, self._mode)
            aad = serialize_context(encryption_context)
            file_header_length = CipherHeader().get_file_header_length(self._algorithm)

            while True:
                read_data = input_stream.read(block_size)
                if not read_data:
                    break

                # 拼接未解析数据和新读取数据
                if self._un_parsed_byte:
                    buf = self._un_parsed_byte + read_data
                    self._un_parsed_byte = b""
                else:
                    buf = read_data

                offset = 0
                total = len(buf)

                # 如果有残留的 header，先处理
                if self._header is not None:
                    remaining = total - offset
                    if self._header.content_length > remaining:
                        self._un_parsed_byte = buf[offset:]
                        continue
                    cipher_text = buf[offset:offset + self._header.content_length]
                    offset += self._header.content_length
                    cipher_handler.set_iv(self._header.iv)
                    cipher_handler.process_decrypt_byte(cipher_text, len(cipher_text), output_stream, aad)
                    self._header = None

                # 循环处理所有完整块
                while offset + file_header_length <= total:
                    temp_header = CipherHeader()
                    header_bytes = buf[offset:offset + file_header_length]
                    temp_header.deserialize_file_fields(header_bytes, self._algorithm)
                    content_length = temp_header.content_length
                    offset += file_header_length

                    if content_length == 0:
                        raise HuaweicloudException(ErrorMessage.FILE_CHANGED_ERROR.message)

                    if content_length > total - offset:
                        # 数据不完整，保存 header 和剩余数据
                        self._header = temp_header
                        self._un_parsed_byte = buf[offset:]
                        offset = total
                        break

                    cipher_text = buf[offset:offset + content_length]
                    offset += content_length
                    cipher_handler.set_iv(temp_header.iv)
                    cipher_handler.process_decrypt_byte(cipher_text, len(cipher_text), output_stream, aad)

                # 保存未处理的剩余数据
                if offset < total and not self._un_parsed_byte:
                    self._un_parsed_byte = buf[offset:]
                    if not self._header:
                        # 剩余数据不足一个 header
                        pass

            # 处理文件末尾剩余数据
            while self._un_parsed_byte and len(self._un_parsed_byte) > 0:
                if self._header is None:
                    if len(self._un_parsed_byte) < file_header_length:
                        break
                    temp_header = CipherHeader()
                    header_bytes = self._un_parsed_byte[:file_header_length]
                    temp_header.deserialize_file_fields(header_bytes, self._algorithm)
                    self._header = temp_header
                    self._un_parsed_byte = self._un_parsed_byte[file_header_length:]
                if self._header.content_length == 0:
                    raise HuaweicloudException(ErrorMessage.FILE_CHANGED_ERROR.message)
                if self._header.content_length > len(self._un_parsed_byte):
                    break
                cipher_text = self._un_parsed_byte[:self._header.content_length]
                cipher_handler.set_iv(self._header.iv)
                cipher_handler.process_decrypt_byte(cipher_text, len(cipher_text), output_stream, aad)
                self._un_parsed_byte = self._un_parsed_byte[self._header.content_length:]
                self._header = None
        except HuaweicloudException:
            raise
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.FILE_CHANGED_ERROR.message) from e
