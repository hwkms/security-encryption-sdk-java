import struct
import io
from typing import Dict, List, Optional

from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey
from huaweicloud_encryptionsdk.model.key_capsule import KeyCapsule
from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, CipherTamperedException, ErrorMessage

VERSION = 1
VERSION_2 = 2


def _serialize_context(encryption_context):
    if not encryption_context:
        return b""
    sorted_entries = sorted(encryption_context.items(), key=lambda x: x[1])
    buf = bytearray()
    buf.extend(struct.pack(">h", len(encryption_context)))
    for key, value in sorted_entries:
        key_bytes = key.encode("utf-8")
        buf.extend(struct.pack(">h", len(key_bytes)))
        buf.extend(key_bytes)
        value_bytes = value.encode("utf-8")
        buf.extend(struct.pack(">h", len(value_bytes)))
        buf.extend(value_bytes)
    return bytes(buf)


def _deserialize_context(encryption_context_bytes):
    if not encryption_context_bytes:
        return {}
    stream = io.BytesIO(encryption_context_bytes)
    size = struct.unpack(">h", stream.read(2))[0]
    result = {}
    for _ in range(size):
        key_len = struct.unpack(">h", stream.read(2))[0]
        key = stream.read(key_len).decode("utf-8")
        value_len = struct.unpack(">h", stream.read(2))[0]
        value = stream.read(value_len).decode("utf-8")
        result[key] = value
    return result


def _write_string(stream, value):
    if value is None:
        stream.write(struct.pack(">i", -1))
    else:
        value_bytes = value.encode("utf-8")
        stream.write(struct.pack(">i", len(value_bytes)))
        stream.write(value_bytes)


def _read_string(stream):
    length = struct.unpack(">i", stream.read(4))[0]
    if length < 0:
        return None
    value_bytes = stream.read(length)
    if len(value_bytes) != length:
        raise HuaweicloudException("Failed to read string")
    return value_bytes.decode("utf-8")


def _serialize_key_capsule(key_capsule):
    buf = io.BytesIO()
    _write_string(buf, key_capsule.key_id)
    _write_string(buf, key_capsule.datakey_capsule)
    buf.write(struct.pack(">i", key_capsule.access_point_type))
    return buf.getvalue()


def _deserialize_key_capsule(data):
    stream = io.BytesIO(data)
    key_id = _read_string(stream)
    datakey_capsule = _read_string(stream)
    access_point_type = struct.unpack(">i", stream.read(4))[0]
    return KeyCapsule(key_id=key_id, datakey_capsule=datakey_capsule, access_point_type=access_point_type)


class CipherHeader:

    def __init__(self, algorithm=None, encryption_context=None, ciphertext_data_keys=None, secret_key=None, key_capsule=None):
        self._version = VERSION
        self._algorithm_id = 0
        self._algorithm = algorithm
        self._encryption_context_byte_length = 0
        self._encryption_context_byte = b""
        self._content_type = 1
        self._encryption_context = encryption_context if encryption_context is not None else {}
        self._ciphertext_data_keys = ciphertext_data_keys if ciphertext_data_keys is not None else []
        self._key_capsule = key_capsule
        self._key_capsule_length = 0
        self._cipher_data_key_size = 0
        self._iv_length = 0
        self._header_tag_length = 0
        self._header_tag = b""
        self._iv = b""
        self._content_length = 0

        if algorithm is not None:
            self._algorithm = algorithm
            self._algorithm_id = algorithm.value
            self._encryption_context = encryption_context if encryption_context is not None else {}
            self._encryption_context_byte = _serialize_context(self._encryption_context)
            self._encryption_context_byte_length = len(self._encryption_context_byte)
            self._content_type = 1
            self._ciphertext_data_keys = ciphertext_data_keys if ciphertext_data_keys is not None else []
            self._cipher_data_key_size = len(self._ciphertext_data_keys)
            self._iv_length = algorithm.iv_len
            self._key_capsule = key_capsule
            if self._key_capsule is not None:
                self._version = VERSION_2
            if secret_key is not None:
                self._calculate_tag(secret_key)

    def _calculate_tag(self, secret_key):
        header_fields_bytes = self.serialize_authenticated_fields()
        if self._algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING:
            from huaweicloud_encryptionsdk.common.crypto_factory import CryptoFactory
            digest = CryptoFactory.get_message_digest("SM3")
            if len(header_fields_bytes) == 0:
                digest.update(b"\x00")
            else:
                digest.update(header_fields_bytes)
            self._header_tag = digest.digest()
            self._header_tag_length = len(self._header_tag)
            return
        from huaweicloud_encryptionsdk.handler.cipher_handler import CipherHandler, ENCRYPT_MODE
        cipher_handler = CipherHandler(self._algorithm, secret_key, ENCRYPT_MODE)
        header_tag_byte = cipher_handler.cipher_header_data(b"", header_fields_bytes, 0, 0)
        iv_len = len(cipher_handler.get_iv())
        message = bytearray(iv_len + len(header_tag_byte))
        message[:iv_len] = cipher_handler.get_iv()
        message[iv_len:] = header_tag_byte
        self._header_tag = bytes(message)
        self._header_tag_length = len(self._header_tag)

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        self._version = value

    @property
    def algorithm_id(self):
        return self._algorithm_id

    @algorithm_id.setter
    def algorithm_id(self, value):
        self._algorithm_id = value

    @property
    def algorithm(self):
        return self._algorithm

    @algorithm.setter
    def algorithm(self, value):
        self._algorithm = value

    @property
    def encryption_context_byte_length(self):
        return self._encryption_context_byte_length

    @encryption_context_byte_length.setter
    def encryption_context_byte_length(self, value):
        self._encryption_context_byte_length = value

    @property
    def encryption_context_byte(self):
        return self._encryption_context_byte

    @encryption_context_byte.setter
    def encryption_context_byte(self, value):
        self._encryption_context_byte = value

    @property
    def content_type(self):
        return self._content_type

    @content_type.setter
    def content_type(self, value):
        self._content_type = value

    @property
    def encryption_context(self):
        return self._encryption_context

    @encryption_context.setter
    def encryption_context(self, value):
        self._encryption_context = value

    @property
    def ciphertext_data_keys(self):
        return self._ciphertext_data_keys

    @ciphertext_data_keys.setter
    def ciphertext_data_keys(self, value):
        self._ciphertext_data_keys = value

    @property
    def key_capsule(self):
        return self._key_capsule

    @key_capsule.setter
    def key_capsule(self, value):
        self._key_capsule = value

    @property
    def key_capsule_length(self):
        return self._key_capsule_length

    @key_capsule_length.setter
    def key_capsule_length(self, value):
        self._key_capsule_length = value

    @property
    def cipher_data_key_size(self):
        return self._cipher_data_key_size

    @cipher_data_key_size.setter
    def cipher_data_key_size(self, value):
        self._cipher_data_key_size = value

    @property
    def iv_length(self):
        return self._iv_length

    @iv_length.setter
    def iv_length(self, value):
        self._iv_length = value

    @property
    def header_tag_length(self):
        return self._header_tag_length

    @header_tag_length.setter
    def header_tag_length(self, value):
        self._header_tag_length = value

    @property
    def header_tag(self):
        return self._header_tag

    @header_tag.setter
    def header_tag(self, value):
        self._header_tag = value

    @property
    def iv(self):
        return self._iv

    @iv.setter
    def iv(self, value):
        self._iv = value

    @property
    def content_length(self):
        return self._content_length

    @content_length.setter
    def content_length(self, value):
        self._content_length = value

    def serialize_authenticated_fields(self):
        try:
            buf = io.BytesIO()
            buf.write(struct.pack(">b", self._version))
            buf.write(struct.pack(">h", self._algorithm_id))
            buf.write(struct.pack(">h", self._encryption_context_byte_length))
            buf.write(self._encryption_context_byte)
            buf.write(struct.pack(">b", self._cipher_data_key_size))
            for data_key in self._ciphertext_data_keys:
                buf.write(data_key.to_byte_array())
            buf.write(struct.pack(">b", self._content_type))
            buf.write(struct.pack(">b", self._iv_length))
            if self._version == 2 and self._key_capsule is not None:
                key_capsule_bytes = _serialize_key_capsule(self._key_capsule)
                self._key_capsule_length = len(key_capsule_bytes)
                buf.write(struct.pack(">i", self._key_capsule_length))
                buf.write(key_capsule_bytes)
            return buf.getvalue()
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.SERIALIZE_EXCEPTION.message, e)

    def deserialize_authenticated_fields(self, data_stream):
        try:
            self._version = struct.unpack(">b", data_stream.read(1))[0]
            if self._version == 1:
                self._deserialize_v1_format(data_stream)
            elif self._version == 2:
                self._deserialize_v2_format(data_stream)
            else:
                raise HuaweicloudException(
                    ErrorMessage.CIPHER_TEXT_CHANGED_ERROR.message + ", unsupported version: " + str(self._version))
            return self
        except HuaweicloudException:
            raise
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.DESERIALIZE_EXCEPTION.message, e)

    def _deserialize_v1_format(self, data_stream):
        self._algorithm_id = struct.unpack(">h", data_stream.read(2))[0]
        self._algorithm = CryptoAlgorithm.get_algorithm(self._algorithm_id)
        if self._algorithm is None:
            raise HuaweicloudException(
                ErrorMessage.CIPHER_TEXT_CHANGED_ERROR.message + ",algorithm id is: " + str(self._algorithm_id))
        self._encryption_context_byte_length = struct.unpack(">h", data_stream.read(2))[0]
        self._encryption_context_byte = data_stream.read(self._encryption_context_byte_length)
        if len(self._encryption_context_byte) != self._encryption_context_byte_length:
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
        self._encryption_context = _deserialize_context(self._encryption_context_byte)
        self._cipher_data_key_size = struct.unpack(">b", data_stream.read(1))[0]
        if self._cipher_data_key_size < 0:
            raise HuaweicloudException(ErrorMessage.NOT_FOUND_CIPHER_TEXT_DATA_KEY.message)
        self._ciphertext_data_keys = []
        for _ in range(self._cipher_data_key_size):
            cdk = CiphertextDataKey()
            cdk.from_data_stream(data_stream)
            self._ciphertext_data_keys.append(cdk)
        self._content_type = struct.unpack(">b", data_stream.read(1))[0]
        self._iv_length = struct.unpack(">b", data_stream.read(1))[0]
        self._header_tag_length = struct.unpack(">h", data_stream.read(2))[0]
        self._header_tag = data_stream.read(self._header_tag_length)
        if len(self._header_tag) != self._header_tag_length:
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)

    def _deserialize_v2_format(self, data_stream):
        self._algorithm_id = struct.unpack(">h", data_stream.read(2))[0]
        self._algorithm = CryptoAlgorithm.get_algorithm(self._algorithm_id)
        if self._algorithm is None:
            raise HuaweicloudException(
                ErrorMessage.CIPHER_TEXT_CHANGED_ERROR.message + ",algorithm id is: " + str(self._algorithm_id))
        self._encryption_context_byte_length = struct.unpack(">h", data_stream.read(2))[0]
        self._encryption_context_byte = data_stream.read(self._encryption_context_byte_length)
        if len(self._encryption_context_byte) != self._encryption_context_byte_length:
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
        self._encryption_context = _deserialize_context(self._encryption_context_byte)
        self._cipher_data_key_size = struct.unpack(">b", data_stream.read(1))[0]
        if self._cipher_data_key_size < 0:
            raise HuaweicloudException(ErrorMessage.NOT_FOUND_CIPHER_TEXT_DATA_KEY.message)
        self._ciphertext_data_keys = []
        for _ in range(self._cipher_data_key_size):
            cdk = CiphertextDataKey()
            cdk.from_data_stream(data_stream)
            self._ciphertext_data_keys.append(cdk)
        self._content_type = struct.unpack(">b", data_stream.read(1))[0]
        self._iv_length = struct.unpack(">b", data_stream.read(1))[0]
        if self._version == 2:
            self._key_capsule_length = struct.unpack(">i", data_stream.read(4))[0]
            if self._key_capsule_length > 0:
                key_capsule_bytes = data_stream.read(self._key_capsule_length)
                if len(key_capsule_bytes) != self._key_capsule_length:
                    raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
                self._key_capsule = _deserialize_key_capsule(key_capsule_bytes)
        self._header_tag_length = struct.unpack(">h", data_stream.read(2))[0]
        self._header_tag = data_stream.read(self._header_tag_length)
        if len(self._header_tag) != self._header_tag_length:
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)

    def verify_header(self, cipher_handler=None):
        try:
            self._header_tag = self._header_tag
            header_fields_bytes = self.serialize_authenticated_fields()
            if self._algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING:
                from huaweicloud_encryptionsdk.common.crypto_factory import CryptoFactory
                digest = CryptoFactory.get_message_digest("SM3")
                if len(header_fields_bytes) == 0:
                    digest.update(b"\x00")
                else:
                    digest.update(header_fields_bytes)
                computed = digest.hexdigest()
                from huaweicloud_encryptionsdk.common import utils as _utils
                encrypt_tag = _utils.bytes_to_hex(self._header_tag)
                decrypt_tag = computed
                if not encrypt_tag and not decrypt_tag:
                    return
                if not encrypt_tag or not decrypt_tag:
                    raise CipherTamperedException(ErrorMessage.TAMPERED_EXCEPTION.message)
                if encrypt_tag != decrypt_tag:
                    raise CipherTamperedException(ErrorMessage.TAMPERED_EXCEPTION.message)
                return
            if cipher_handler is not None:
                cipher_handler.cipher_header_data(
                    self._header_tag, header_fields_bytes,
                    self._algorithm.iv_len,
                    len(self._header_tag) - self._algorithm.iv_len)
        except CipherTamperedException:
            raise
        except Exception as e:
            raise CipherTamperedException(ErrorMessage.TAMPERED_EXCEPTION.message, e)

    def serialize_file_fields(self):
        try:
            return self._iv + struct.pack(">q", self._content_length)
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.SERIALIZE_EXCEPTION.message, e)

    def get_file_header_length(self, algorithm):
        return algorithm.iv_len + 8

    def deserialize_file_fields(self, header_bytes, algorithm):
        self._iv = header_bytes[:algorithm.iv_len]
        self._content_length = struct.unpack(">q", header_bytes[algorithm.iv_len:])[0]
