import pytest
from huaweicloud_encryptionsdk.exception.errors import (
    HuaweicloudException,
    KeyringNotFoundException,
    KeyringNotMatchException,
    KeyParseException,
    EncryptException,
    CipherTamperedException,
    CipherDataException,
    ErrorMessage,
)


class TestExceptions:
    def test_huaweicloud_exception_message(self):
        e = HuaweicloudException("test error")
        assert str(e) == "test error"

    def test_keyring_not_found_exception(self):
        e = KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.message)
        assert "key ring" in str(e).lower() or "null" in str(e).lower()

    def test_cipher_tampered_exception(self):
        e = CipherTamperedException(ErrorMessage.TAMPERED_EXCEPTION.message)
        assert "integrity" in str(e).lower() or "tampered" in str(e).lower() or "Header" in str(e)

    def test_exception_inheritance(self):
        assert issubclass(KeyringNotFoundException, HuaweicloudException)
        assert issubclass(KeyringNotMatchException, HuaweicloudException)
        assert issubclass(KeyParseException, HuaweicloudException)
        assert issubclass(EncryptException, HuaweicloudException)
        assert issubclass(CipherTamperedException, HuaweicloudException)
        assert issubclass(CipherDataException, HuaweicloudException)

    def test_exception_with_cause(self):
        cause = ValueError("original")
        e = HuaweicloudException("wrapper", cause)
        assert "wrapper" in str(e)
