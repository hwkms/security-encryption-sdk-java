import struct
from io import BytesIO

from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage
from huaweicloud_encryptionsdk.handler.serialize_handler import SerializeHandler
from huaweicloud_encryptionsdk.model.cipher_body import CipherBody
from huaweicloud_encryptionsdk.model.cipher_header import CipherHeader
from huaweicloud_encryptionsdk.model.data_materials import DataMaterials


class DefaultSerializeHandler(SerializeHandler):

    def serialize(self, data_materials):
        cipher_body = data_materials.cipher_body
        headers = data_materials.headers.serialize_authenticated_fields()
        header_tag = data_materials.headers.header_tag
        header_tag_length = data_materials.headers.header_tag_length
        body_bytes = cipher_body.to_byte_array()
        total_length = len(body_bytes) + len(headers) + 2 + len(header_tag)
        buf = bytearray(total_length)
        offset = 0
        buf[offset:offset + len(headers)] = headers
        offset += len(headers)
        struct.pack_into(">h", buf, offset, header_tag_length)
        offset += 2
        buf[offset:offset + len(header_tag)] = header_tag
        offset += len(header_tag)
        buf[offset:offset + len(body_bytes)] = body_bytes
        return bytes(buf)

    def deserialize(self, cipher_data):
        try:
            data_stream = BytesIO(cipher_data)
            cipher_header = CipherHeader()
            cipher_header.deserialize_authenticated_fields(data_stream)
            cipher_body = None
            remaining = len(cipher_data) - data_stream.tell()
            if remaining > 0:
                cipher_body = CipherBody()
                cipher_body.deserialize(data_stream, cipher_header.algorithm)
            return DataMaterials(cipher_body, cipher_header)
        except HuaweicloudException:
            raise
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.DESERIALIZE_EXCEPTION.message, e)
