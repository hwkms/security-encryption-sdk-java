import pytest
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.enums.access_point_type import AccessPointType
from huaweicloud_encryptionsdk.model.enums.key_provider_enum import KeyProviderEnum
from huaweicloud_encryptionsdk.model.enums.data_key_generate_type import DataKeyGenerateType
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum
from huaweicloud_encryptionsdk.exception.errors import ErrorMessage


class TestCryptoAlgorithm:
    def test_all_values(self):
        assert CryptoAlgorithm.AES_128_GCM_NOPADDING.value == 1
        assert CryptoAlgorithm.AES_256_GCM_NOPADDING.value == 2
        assert CryptoAlgorithm.SM4_128_GCM_NOPADDING.value == 3
        assert CryptoAlgorithm.SM4_128_CBC_PADDING.value == 4

    def test_key_lengths(self):
        assert CryptoAlgorithm.AES_128_GCM_NOPADDING.key_len == 16
        assert CryptoAlgorithm.AES_256_GCM_NOPADDING.key_len == 32
        assert CryptoAlgorithm.SM4_128_GCM_NOPADDING.key_len == 16

    def test_get_algorithm(self):
        assert CryptoAlgorithm.get_algorithm(1) == CryptoAlgorithm.AES_128_GCM_NOPADDING
        assert CryptoAlgorithm.get_algorithm(2) == CryptoAlgorithm.AES_256_GCM_NOPADDING
        assert CryptoAlgorithm.get_algorithm(3) == CryptoAlgorithm.SM4_128_GCM_NOPADDING
        assert CryptoAlgorithm.get_algorithm(4) == CryptoAlgorithm.SM4_128_CBC_PADDING

    def test_get_algorithm_name(self):
        assert "AES" in CryptoAlgorithm.AES_256_GCM_NOPADDING.get_algorithm_name() or "GCM" in CryptoAlgorithm.AES_256_GCM_NOPADDING.get_algorithm_name()


class TestAccessPointType:
    def test_all_values(self):
        assert AccessPointType.ECS.code == 1
        assert AccessPointType.CUSTOM.code == 2
        assert AccessPointType.CCE.code == 3

    def test_display_names(self):
        assert AccessPointType.ECS.display_name == "ECS"
        assert AccessPointType.CUSTOM.display_name == "Custom"
        assert AccessPointType.CCE.display_name == "CCE"

    def test_get_display_name_by_code(self):
        assert AccessPointType.get_display_name_by_code(1) == "ECS"
        assert AccessPointType.get_display_name_by_code(2) == "Custom"
        assert AccessPointType.get_display_name_by_code(3) == "CCE"


class TestKeyProviderEnum:
    def test_all_values(self):
        assert KeyProviderEnum.LOCAL_PROVIDER.code == 1
        assert KeyProviderEnum.KMS_PROVIDER.code == 2


class TestDataKeyGenerateType:
    def test_all_values(self):
        assert DataKeyGenerateType.LOCAL_GENERATE.code == 1
        assert DataKeyGenerateType.KMS_GENERATE.code == 2
        assert DataKeyGenerateType.KEY_CAPSULE_GENERATE.code == 3


class TestKeyringTypeEnum:
    def test_all_values(self):
        assert KeyringTypeEnum.RAW_AES.type == "AES"
        assert KeyringTypeEnum.RAW_SM2.type == "SM2"
        assert KeyringTypeEnum.RAW_RSA.type == "RSA"
        assert KeyringTypeEnum.KMS_KEY_CAPSULE.type == "key_capsule"

    def test_get_raw_keyring_type(self):
        result = KeyringTypeEnum.get_raw_keyring_type("AES")
        assert result == KeyringTypeEnum.RAW_AES


class TestErrorMessage:
    def test_error_codes(self):
        assert ErrorMessage.DECRYPT_EXCEPTION.code == 1000
        assert ErrorMessage.CIPHER_EXCEPTION.code == 1001
        assert ErrorMessage.KEYRING_NULL_EXCEPTION.code == 1012
        assert ErrorMessage.KEY_CAPSULE_NULL.code == 1030
        assert ErrorMessage.COLLECT_PROOF_EXCEPTION.code == 1036

    def test_error_messages(self):
        assert "decrypt" in ErrorMessage.DECRYPT_EXCEPTION.message.lower()
        assert "null" in ErrorMessage.KEYRING_NULL_EXCEPTION.message.lower()
