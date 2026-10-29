import pytest
from huaweicloud_encryptionsdk.kms.create_key_capsule_request import CreateKeyCapsuleRequest
from huaweicloud_encryptionsdk.kms.create_key_capsule_response import CreateKeyCapsuleResponse
from huaweicloud_encryptionsdk.kms.decrypt_key_capsule_request import DecryptKeyCapsuleRequest
from huaweicloud_encryptionsdk.kms.decrypt_key_capsule_response import DecryptKeyCapsuleResponse


class TestCreateKeyCapsuleRequest:
    def test_defaults(self):
        r = CreateKeyCapsuleRequest()
        assert r.key_id is None
        assert r.datakey_length == 0
        assert r.public_key is None
        assert r.policy_id is None
        assert r.key_policy is None

    def test_to_dict(self):
        r = CreateKeyCapsuleRequest(key_id="kid", datakey_length=256, public_key="pk", policy_id="pid")
        d = r.to_dict()
        assert d["key_id"] == "kid"
        assert d["datakey_length"] == 256
        assert d["public_key"] == "pk"
        assert d["policy_id"] == "pid"

    def test_from_dict(self):
        d = {"key_id": "kid", "datakey_length": 128, "public_key": "pk", "policy_id": "pid", "key_policy": "kp"}
        r = CreateKeyCapsuleRequest.from_dict(d)
        assert r.key_id == "kid"
        assert r.datakey_length == 128
        assert r.key_policy == "kp"

    def test_roundtrip(self):
        r = CreateKeyCapsuleRequest(key_id="kid", datakey_length=256, public_key="pk")
        d = r.to_dict()
        r2 = CreateKeyCapsuleRequest.from_dict(d)
        assert r2.key_id == r.key_id
        assert r2.datakey_length == r.datakey_length


class TestCreateKeyCapsuleResponse:
    def test_defaults(self):
        r = CreateKeyCapsuleResponse()
        assert r.key_id is None
        assert r.datakey_cipher is None
        assert r.datakey is None
        assert r.datakey_capsule is None

    def test_from_dict(self):
        d = {"key_id": "kid", "datakey_cipher": "cipher", "datakey": "dk", "datakey_capsule": "capsule"}
        r = CreateKeyCapsuleResponse.from_dict(d)
        assert r.key_id == "kid"
        assert r.datakey_cipher == "cipher"
        assert r.datakey == "dk"
        assert r.datakey_capsule == "capsule"


class TestDecryptKeyCapsuleRequest:
    def test_defaults(self):
        r = DecryptKeyCapsuleRequest()
        assert r.key_id is None
        assert r.datakey_capsule is None
        assert r.attestation_document is None

    def test_to_dict(self):
        r = DecryptKeyCapsuleRequest(key_id="kid", datakey_capsule="capsule")
        d = r.to_dict()
        assert d["key_id"] == "kid"
        assert d["datakey_capsule"] == "capsule"

    def test_from_dict(self):
        d = {"key_id": "kid", "datakey_capsule": "capsule"}
        r = DecryptKeyCapsuleRequest.from_dict(d)
        assert r.key_id == "kid"
        assert r.datakey_capsule == "capsule"


class TestDecryptKeyCapsuleResponse:
    def test_defaults(self):
        r = DecryptKeyCapsuleResponse()
        assert r.key_id is None
        assert r.datakey is None
        assert r.datakey_cipher is None
        assert r.instance_id is None

    def test_from_dict(self):
        d = {"key_id": "kid", "datakey": "dk", "datakey_cipher": "cipher", "instanceId": "inst-123"}
        r = DecryptKeyCapsuleResponse.from_dict(d)
        assert r.key_id == "kid"
        assert r.datakey == "dk"
        assert r.instance_id == "inst-123"

    def test_from_dict_without_instance_id(self):
        d = {"key_id": "kid", "datakey": "dk"}
        r = DecryptKeyCapsuleResponse.from_dict(d)
        assert r.instance_id is None
