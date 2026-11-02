import pytest
from huaweicloud_encryptionsdk.model.key_capsule import KeyCapsule
from huaweicloud_encryptionsdk.model.kms_config import KMSConfig
from huaweicloud_encryptionsdk.model.access_point_config import AccessPointConfig
from huaweicloud_encryptionsdk.model.key_capsule_config import KeyCapsuleConfig
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.model.crypto_result import CryptoResult
from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest
from huaweicloud_encryptionsdk.huawei_config import HuaweiConfig
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm


class TestKeyCapsule:
    def test_defaults(self):
        kc = KeyCapsule()
        assert kc.key_id is None
        assert kc.datakey_capsule is None
        assert kc.access_point_type == 0
        assert kc.instance_id is None

    def test_with_values(self):
        kc = KeyCapsule(key_id="kid", datakey_capsule="capsule", access_point_type=1, instance_id="inst-123")
        assert kc.key_id == "kid"
        assert kc.datakey_capsule == "capsule"
        assert kc.access_point_type == 1
        assert kc.instance_id == "inst-123"


class TestKMSConfig:
    def test_defaults(self):
        c = KMSConfig()
        assert c.region == ""
        assert c.key_id == ""
        assert c.project_id == ""
        assert c.end_point is None

    def test_with_values(self):
        c = KMSConfig(region="cn-north-7", key_id="kid", project_id="pid", end_point="https://kms.example.com")
        assert c.region == "cn-north-7"
        assert c.key_id == "kid"
        assert c.project_id == "pid"
        assert c.end_point == "https://kms.example.com"


class TestAccessPointConfig:
    def test_defaults(self):
        ap = AccessPointConfig()
        assert ap.type == 0
        assert ap.encrypted_private_key is None
        assert ap.private_key_decrypt_callback is None
        assert ap.service_account is None

    def test_with_callback(self):
        cb = lambda x: x
        ap = AccessPointConfig(type=2, encrypted_private_key="enc", private_key_decrypt_callback=cb)
        assert ap.type == 2
        assert ap.private_key_decrypt_callback("test") == "test"


class TestKeyCapsuleConfig:
    def test_defaults(self):
        kcc = KeyCapsuleConfig()
        assert kcc.region == ""
        assert kcc.default_policy_id is None
        assert kcc.default_key_policy is None
        assert kcc.access_point_config is None

    def test_with_access_point(self):
        ap = AccessPointConfig(type=1)
        kcc = KeyCapsuleConfig(region="cn-north-7", access_point_config=ap)
        assert kcc.region == "cn-north-7"
        assert kcc.access_point_config.type == 1


class TestEncryptRequest:
    def test_defaults(self):
        r = EncryptRequest()
        assert r.encryption_context == {}
        assert r.plain_text == b""
        assert r.policy_id is None
        assert r.key_policy is None

    def test_with_values(self):
        r = EncryptRequest(plain_text=b"hello", policy_id="pid")
        assert r.plain_text == b"hello"
        assert r.policy_id == "pid"


class TestDataKeyMaterials:
    def test_defaults(self):
        dkm = DataKeyMaterials()
        assert dkm.plaintext_data_key == b""
        assert dkm.ciphertext_data_keys == []
        assert dkm.encryption_contexts == {}
        assert dkm.crypto_algorithm is None
        assert dkm.key_capsule is None

    def test_with_values(self):
        kc = KeyCapsule(key_id="kid", instance_id="inst-1")
        dkm = DataKeyMaterials(plaintext_data_key=b"\x01\x02", key_capsule=kc)
        assert dkm.plaintext_data_key == b"\x01\x02"
        assert dkm.key_capsule.key_id == "kid"
        assert dkm.key_capsule.instance_id == "inst-1"


class TestCryptoResult:
    def test_defaults(self):
        r = CryptoResult()
        assert r.result is None
        assert r.headers is None
        assert r.data_length == 0

    def test_with_values(self):
        r = CryptoResult(result=b"decrypted", data_length=10)
        assert r.result == b"decrypted"
        assert r.data_length == 10


class TestHuaweiConfig:
    def test_defaults(self):
        c = HuaweiConfig()
        assert c.ak == ""
        assert c.sk == ""
        assert c.is_discovery is False
        assert c.kms_config_list is None
        assert c.crypto_algorithm is None
        assert c.key_capsule_config is None
        assert c.log_config is None
        assert c.local_log_only is False

    def test_set_ak_sk(self):
        c = HuaweiConfig()
        c.set_ak("myak")
        c.set_sk("mysk")
        assert c.get_ak() == "myak"
        assert c.get_sk() == "mysk"

    def test_with_key_capsule(self):
        kcc = KeyCapsuleConfig(region="cn-north-7")
        c = HuaweiConfig(ak="ak", sk="sk", key_capsule_config=kcc, crypto_algorithm=CryptoAlgorithm.AES_256_GCM_NOPADDING)
        assert c.key_capsule_config.region == "cn-north-7"
        assert c.crypto_algorithm == CryptoAlgorithm.AES_256_GCM_NOPADDING
