import pytest
from unittest.mock import patch, MagicMock
from huaweicloud_encryptionsdk import HuaweiCrypto, HuaweiConfig
from huaweicloud_encryptionsdk.exception.errors import KeyringNotFoundException
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm


class TestHuaweiCryptoNoKeyring:
    def test_encrypt_without_keyring_raises(self):
        config = HuaweiConfig(ak="ak", sk="sk", crypto_algorithm=CryptoAlgorithm.AES_256_GCM_NOPADDING)
        crypto = HuaweiCrypto(config)
        with pytest.raises(KeyringNotFoundException):
            crypto.encrypt(b"test")

    def test_decrypt_without_keyring_raises(self):
        config = HuaweiConfig(ak="ak", sk="sk")
        crypto = HuaweiCrypto(config)
        with pytest.raises(KeyringNotFoundException):
            crypto.decrypt(b"test")

    def test_encrypt_stream_without_keyring_raises(self):
        config = HuaweiConfig(ak="ak", sk="sk", crypto_algorithm=CryptoAlgorithm.AES_256_GCM_NOPADDING)
        crypto = HuaweiCrypto(config)
        with pytest.raises(KeyringNotFoundException):
            crypto.encrypt_stream(MagicMock(), MagicMock())

    def test_decrypt_stream_without_keyring_raises(self):
        config = HuaweiConfig(ak="ak", sk="sk")
        crypto = HuaweiCrypto(config)
        with pytest.raises(KeyringNotFoundException):
            crypto.decrypt_stream(MagicMock(), MagicMock())

    def test_encrypt_file_without_keyring_raises(self):
        config = HuaweiConfig(ak="ak", sk="sk", crypto_algorithm=CryptoAlgorithm.AES_256_GCM_NOPADDING)
        crypto = HuaweiCrypto(config)
        with pytest.raises(KeyringNotFoundException):
            crypto.encrypt_file("src.txt", "dst.txt")

    def test_decrypt_file_without_keyring_raises(self):
        config = HuaweiConfig(ak="ak", sk="sk")
        crypto = HuaweiCrypto(config)
        with pytest.raises(KeyringNotFoundException):
            crypto.decrypt_file("src.txt", "dst.txt")


class TestHuaweiCryptoBuilder:
    def test_with_keyring(self):
        config = HuaweiConfig(ak="ak", sk="sk")
        crypto = HuaweiCrypto(config)
        mock_keyring = MagicMock()
        result = crypto.with_keyring(mock_keyring)
        assert result is crypto

    def test_with_crypto_material_manager(self):
        config = HuaweiConfig(ak="ak", sk="sk")
        crypto = HuaweiCrypto(config)
        mock_manager = MagicMock()
        result = crypto.with_crypto_material_manager(mock_manager)
        assert result is crypto


class TestHuaweiConfigLocalLogOnly:
    def test_local_log_only_does_not_init_lts(self):
        config = HuaweiConfig(ak="ak", sk="sk", local_log_only=True)
        crypto = HuaweiCrypto(config)
        from huaweicloud_encryptionsdk.log.log_reporter_manager import LogReporterManager
        assert LogReporterManager.get_instance().is_initialized
