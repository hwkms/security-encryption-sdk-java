import struct

from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage


class CipherBody:

    def __init__(self, iv=None, encrypted_content=None, encrypted_content_length=0, auth_tag=None):
        self._iv = iv if iv is not None else b""
        self._encrypted_content = encrypted_content if encrypted_content is not None else b""
        self._encrypted_content_length = encrypted_content_length
        self._auth_tag = auth_tag if auth_tag is not None else b""

    @property
    def iv(self):
        return self._iv

    @iv.setter
    def iv(self, value):
        self._iv = value

    @property
    def encrypted_content(self):
        return self._encrypted_content

    @encrypted_content.setter
    def encrypted_content(self, value):
        self._encrypted_content = value

    @property
    def encrypted_content_length(self):
        return self._encrypted_content_length

    @encrypted_content_length.setter
    def encrypted_content_length(self, value):
        self._encrypted_content_length = value

    @property
    def auth_tag(self):
        return self._auth_tag

    @auth_tag.setter
    def auth_tag(self, value):
        self._auth_tag = value

    def get_total_length(self):
        return len(self._iv) + len(self._encrypted_content) + 8 + len(self._auth_tag)

    def to_byte_array(self):
        total = self.get_total_length()
        buf = bytearray(total)
        offset = 0
        buf[offset:offset + len(self._iv)] = self._iv
        offset += len(self._iv)
        encrypted_content_length_bytes = struct.pack(">q", self._encrypted_content_length)
        buf[offset:offset + 8] = encrypted_content_length_bytes
        offset += 8
        buf[offset:offset + len(self._encrypted_content)] = self._encrypted_content
        offset += len(self._encrypted_content)
        buf[offset:offset + len(self._auth_tag)] = self._auth_tag
        return bytes(buf)

    def deserialize(self, data_stream, algorithm):
        self._iv = data_stream.read(algorithm.iv_len)
        if len(self._iv) != algorithm.iv_len:
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
        encrypted_content_length_bytes = data_stream.read(8)
        if len(encrypted_content_length_bytes) != 8:
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
        self._encrypted_content_length = struct.unpack(">q", encrypted_content_length_bytes)[0]
        self._encrypted_content = data_stream.read(int(self._encrypted_content_length))
        if len(self._encrypted_content) != int(self._encrypted_content_length):
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
        if algorithm != CryptoAlgorithm.SM4_128_CBC_PADDING:
            self._auth_tag = data_stream.read(algorithm.tag_len)
        else:
            self._auth_tag = b""
        if len(self._auth_tag) != (algorithm.tag_len if algorithm != CryptoAlgorithm.SM4_128_CBC_PADDING else 0):
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
        return self
