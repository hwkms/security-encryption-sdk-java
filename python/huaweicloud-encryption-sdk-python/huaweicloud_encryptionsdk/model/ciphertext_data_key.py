import struct
import io
from enum import Enum
from typing import Optional

from huaweicloud_encryptionsdk.model.enums.key_provider_enum import KeyProviderEnum
from huaweicloud_encryptionsdk.model.kms_config import KMSConfig
from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage


class Discovery(Enum):
    DISCOVERY = (True, 1)
    NO_DISCOVERY = (False, 2)

    def __init__(self, is_discovery, code):
        self._is_discovery = is_discovery
        self._code = code

    @property
    def is_discovery(self):
        return self._is_discovery

    @property
    def code(self):
        return self._code

    @classmethod
    def get_discovery_status(cls, code):
        for d in cls:
            if d.code == code:
                return d.is_discovery
        return False


class CiphertextDataKey:

    def __init__(self, data_key=None, kms_config=None):
        self._key_provider_length = 0
        self._key_provider = b""
        self._data_key = b""
        self._data_key_length = 0
        self._key_information_length = 0
        self._key_information = b""
        self._key_id = b""
        self._region = b""
        self._project_id = b""
        self._end_point = b""
        self._discovery = Discovery.NO_DISCOVERY
        self._total_length = 0

        if data_key is not None and kms_config is None:
            self._data_key = data_key
            self._data_key_length = len(data_key)
            self._key_provider = KeyProviderEnum.LOCAL_PROVIDER.name.encode("utf-8")
            self._key_provider_length = len(self._key_provider)
            self._discovery = Discovery.NO_DISCOVERY
            self._key_information = self._build_key_information(Discovery.NO_DISCOVERY)
            self._key_information_length = len(self._key_information)
            self._total_length = self._data_key_length + self._key_provider_length + self._key_information_length + 4
        elif data_key is not None and kms_config is not None:
            self._data_key = data_key
            self._data_key_length = len(data_key)
            self._key_id = (kms_config.key_id or "").encode("utf-8")
            self._region = (kms_config.region or "").encode("utf-8")
            self._project_id = (kms_config.project_id or "").encode("utf-8")
            self._end_point = (kms_config.end_point or "").encode("utf-8")
            self._key_provider = KeyProviderEnum.KMS_PROVIDER.name.encode("utf-8")
            self._key_provider_length = len(self._key_provider)
            self._discovery = Discovery.DISCOVERY
            self._key_information = self._build_key_information(Discovery.DISCOVERY)
            self._key_information_length = len(self._key_information)
            self._total_length = self._data_key_length + self._key_provider_length + self._key_information_length + 4

    @property
    def data_key(self):
        return self._data_key

    @property
    def key_id(self):
        return self._key_id.decode("utf-8") if self._key_id else ""

    @property
    def region(self):
        return self._region.decode("utf-8") if self._region else ""

    @property
    def project_id(self):
        return self._project_id.decode("utf-8") if self._project_id else ""

    @property
    def end_point(self):
        return self._end_point.decode("utf-8") if self._end_point else ""

    @property
    def discovery(self):
        return self._discovery

    def is_discovery(self):
        return self._discovery.is_discovery

    def _build_key_information(self, discovery):
        buf = bytearray()
        buf.append(discovery.code & 0xFF)
        if discovery.is_discovery:
            buf.append(len(self._key_id) & 0xFF)
            buf.extend(self._key_id)
            buf.append(len(self._region) & 0xFF)
            buf.extend(self._region)
            buf.append(len(self._project_id) & 0xFF)
            buf.extend(self._project_id)
            buf.append(len(self._end_point) & 0xFF)
            buf.extend(self._end_point)
        return bytes(buf)

    def to_byte_array(self):
        buf = bytearray(self._total_length)
        offset = 0
        buf[offset] = self._key_provider_length & 0xFF
        offset += 1
        buf[offset:offset + self._key_provider_length] = self._key_provider
        offset += self._key_provider_length
        buf[offset] = self._key_information_length & 0xFF
        offset += 1
        buf[offset:offset + self._key_information_length] = self._key_information
        offset += self._key_information_length
        struct.pack_into(">h", buf, offset, self._data_key_length)
        offset += 2
        buf[offset:offset + self._data_key_length] = self._data_key
        return bytes(buf)

    def from_data_stream(self, data_stream):
        self._key_provider_length = struct.unpack(">B", data_stream.read(1))[0]
        self._key_provider = data_stream.read(self._key_provider_length)
        if len(self._key_provider) != self._key_provider_length:
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
        self._key_information_length = struct.unpack(">B", data_stream.read(1))[0]
        if self._key_information_length > 0:
            self._key_information = data_stream.read(self._key_information_length)
            if len(self._key_information) != self._key_information_length:
                raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
            self._parse_key_information()
        self._data_key_length = struct.unpack(">h", data_stream.read(2))[0]
        self._data_key = data_stream.read(self._data_key_length)
        if len(self._data_key) != self._data_key_length:
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
        self._total_length = self._data_key_length + self._key_provider_length + self._key_information_length + 4

    def _parse_key_information(self):
        stream = io.BytesIO(self._key_information)
        code = struct.unpack(">B", stream.read(1))[0]
        if Discovery.get_discovery_status(code):
            self._key_id = self._read_field(stream)
            self._region = self._read_field(stream)
            self._project_id = self._read_field(stream)
            self._end_point = self._read_field(stream)
            self._discovery = Discovery.DISCOVERY
        else:
            self._discovery = Discovery.DISCOVERY

    @staticmethod
    def _read_field(stream):
        length = struct.unpack(">B", stream.read(1))[0]
        field_bytes = stream.read(length)
        if len(field_bytes) != length:
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
        return field_bytes
