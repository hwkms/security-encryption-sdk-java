from abc import ABC, abstractmethod

from huaweicloud_encryptionsdk.model.crypto_result import CryptoResult
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest


class CryptoHandler(ABC):

    @abstractmethod
    def encrypt(self, request, data_key_materials):
        pass

    @abstractmethod
    def decrypt(self, cipher_text, data_key_materials):
        pass

    @abstractmethod
    def encrypt_stream(self, input_stream, output_stream, data_key_materials, encryption_context):
        pass

    @abstractmethod
    def decrypt_stream(self, input_stream, output_stream, data_key_materials):
        pass
