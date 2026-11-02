import struct
from io import BytesIO

from huaweicloud_encryptionsdk.common.constants import Constants
from huaweicloud_encryptionsdk.common.counting_output_stream import CountingOutputStream
from huaweicloud_encryptionsdk.handler.cipher_handler import CipherHandler, ENCRYPT_MODE, DECRYPT_MODE
from huaweicloud_encryptionsdk.handler.crypto_handler import CryptoHandler
from huaweicloud_encryptionsdk.handler.default_serialize_handler import DefaultSerializeHandler
from huaweicloud_encryptionsdk.handler.file_encrypt_handler import FileEncryptHandler
from huaweicloud_encryptionsdk.handler.file_decrypt_handler import FileDecryptHandler
from huaweicloud_encryptionsdk.model.cipher_body import CipherBody
from huaweicloud_encryptionsdk.model.cipher_header import CipherHeader
from huaweicloud_encryptionsdk.model.crypto_result import CryptoResult
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.model.data_materials import DataMaterials
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest


class DefaultCryptoHandler(CryptoHandler):

    def __init__(self):
        self._serialize_handler = DefaultSerializeHandler()

    def encrypt(self, request, data_key_materials):
        cipher_handler = CipherHandler(
            data_key_materials.crypto_algorithm,
            data_key_materials.plaintext_data_key,
            ENCRYPT_MODE,
        )
        encrypted_data = cipher_handler.cipher_data(
            request.plain_text, request.encryption_context, 0, len(request.plain_text)
        )
        if data_key_materials.crypto_algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING:
            tag_len = 0
        else:
            tag_len = data_key_materials.crypto_algorithm.tag_len

        if tag_len != 0:
            cipher_text = encrypted_data[: len(encrypted_data) - tag_len]
            auth_tag = encrypted_data[len(encrypted_data) - tag_len:]
        else:
            cipher_text = encrypted_data
            auth_tag = b""

        cipher_header = CipherHeader(
            data_key_materials.crypto_algorithm,
            data_key_materials.encryption_contexts,
            data_key_materials.ciphertext_data_keys,
            data_key_materials.plaintext_data_key,
            data_key_materials.key_capsule,
        )
        cipher_body = CipherBody(
            cipher_handler.get_iv(), cipher_text, len(cipher_text), auth_tag
        )
        data_materials = DataMaterials(cipher_body, cipher_header)
        serialized_data = self._serialize_handler.serialize(data_materials)
        return CryptoResult(
            result=serialized_data,
            headers=cipher_header,
            data_length=len(cipher_text),
        )

    def decrypt(self, cipher_text, data_key_materials):
        data_materials = self._serialize_handler.deserialize(cipher_text)
        headers = data_materials.headers
        header_tag = headers.header_tag
        header_tag_iv = header_tag[: headers.algorithm.iv_len]

        cipher_handler = CipherHandler(
            data_key_materials.crypto_algorithm,
            data_key_materials.plaintext_data_key,
            DECRYPT_MODE,
        )
        cipher_handler.set_iv(header_tag_iv)
        headers.verify_header(cipher_handler)

        cipher_body = data_materials.cipher_body
        if cipher_body is None:
            raise Exception("cipher text changed error")

        iv = cipher_body.iv
        encrypted_content = cipher_body.encrypted_content
        auth_tag = cipher_body.auth_tag

        if (
            data_key_materials.crypto_algorithm != CryptoAlgorithm.SM4_128_CBC_PADDING
            and len(auth_tag) != data_key_materials.crypto_algorithm.tag_len
        ):
            raise ValueError("Invalid tag length: " + str(len(auth_tag)))

        result = bytearray(len(iv) + len(encrypted_content) + len(auth_tag))
        result[: len(iv)] = iv
        result[len(iv): len(iv) + len(encrypted_content)] = encrypted_content
        result[len(iv) + len(encrypted_content):] = auth_tag

        cipher_handler.set_iv(iv)
        decrypt_data = cipher_handler.cipher_data(
            bytes(result), data_key_materials.encryption_contexts, len(iv), len(result) - len(iv)
        )
        return CryptoResult(result=decrypt_data, headers=data_materials.headers)

    def encrypt_stream(self, input_stream, output_stream, data_key_materials, encryption_context):
        counting_stream = CountingOutputStream(output_stream)
        cipher_header = CipherHeader(
            data_key_materials.crypto_algorithm,
            data_key_materials.encryption_contexts,
            data_key_materials.ciphertext_data_keys,
            data_key_materials.plaintext_data_key,
            data_key_materials.key_capsule,
        )
        authenticated_fields = cipher_header.serialize_authenticated_fields()
        counting_stream.write(
            struct.pack(">h", len(authenticated_fields) + 2 + cipher_header.header_tag_length)
        )
        counting_stream.write(authenticated_fields)
        counting_stream.write(struct.pack(">h", cipher_header.header_tag_length))
        counting_stream.write(cipher_header.header_tag)

        file_encrypt_handler = FileEncryptHandler(
            data_key_materials.crypto_algorithm,
            data_key_materials.plaintext_data_key,
            ENCRYPT_MODE,
        )
        file_encrypt_handler.process_byte(
            input_stream, counting_stream, data_key_materials.encryption_contexts, Constants.BLOCK_SIZE
        )
        return CryptoResult(
            result=counting_stream,
            headers=cipher_header,
            data_length=counting_stream.get_bytes_written(),
        )

    def decrypt_stream(self, input_stream, output_stream, data_key_materials):
        counting_stream = CountingOutputStream(output_stream)
        file_decrypt_handler = FileDecryptHandler(
            data_key_materials.crypto_algorithm,
            data_key_materials.plaintext_data_key,
            DECRYPT_MODE,
        )
        file_decrypt_handler.process_byte(
            input_stream, counting_stream, data_key_materials.encryption_contexts, Constants.BLOCK_SIZE
        )
        return CryptoResult(
            result=counting_stream,
            headers=None,
            data_length=counting_stream.get_bytes_written(),
        )
