import json
import pytest
from huaweicloud_encryptionsdk.proof.attestation_document import AttestationDocument


class TestAttestationDocument:
    def test_defaults(self):
        ad = AttestationDocument()
        assert ad.ecs_signature is None
        assert ad.custom_signature is None
        assert ad.custom_public_key is None
        assert ad.expire_time is None
        assert ad.service_token is None

    def test_with_values(self):
        ad = AttestationDocument(
            ecs_signature="sig",
            custom_signature="csig",
            custom_public_key="cpk",
            expire_time="2026-12-31T23:59:59Z",
            service_token="token123",
        )
        assert ad.ecs_signature == "sig"
        assert ad.service_token == "token123"

    def test_to_dict(self):
        ad = AttestationDocument(service_token="token123", ecs_signature="sig")
        d = ad.to_dict()
        assert d["service_token"] == "token123"
        assert d["ecs_signature"] == "sig"

    def test_to_dict_omits_none(self):
        ad = AttestationDocument(service_token="token123")
        d = ad.to_dict()
        assert "service_token" in d
        assert "ecs_signature" not in d

    def test_to_json(self):
        ad = AttestationDocument(service_token="token123")
        j = ad.to_json()
        parsed = json.loads(j)
        assert parsed["service_token"] == "token123"

    def test_from_dict(self):
        d = {
            "ecs_signature": "sig",
            "custom_signature": "csig",
            "custom_public_key": "cpk",
            "expire_time": "2026-12-31T23:59:59Z",
            "service_token": "token123",
        }
        ad = AttestationDocument.from_dict(d)
        assert ad.ecs_signature == "sig"
        assert ad.service_token == "token123"
        assert ad.expire_time == "2026-12-31T23:59:59Z"

    def test_from_json(self):
        j = '{"ecs_signature": "sig", "service_token": "token123"}'
        ad = AttestationDocument.from_json(j)
        assert ad.ecs_signature == "sig"
        assert ad.service_token == "token123"

    def test_roundtrip_dict(self):
        ad = AttestationDocument(
            ecs_signature="sig",
            custom_public_key="cpk",
            service_token="token123",
        )
        d = ad.to_dict()
        ad2 = AttestationDocument.from_dict(d)
        assert ad2.ecs_signature == ad.ecs_signature
        assert ad2.custom_public_key == ad.custom_public_key
        assert ad2.service_token == ad.service_token

    def test_roundtrip_json(self):
        ad = AttestationDocument(
            ecs_signature="sig",
            service_token="token123",
        )
        j = ad.to_json()
        ad2 = AttestationDocument.from_json(j)
        assert ad2.ecs_signature == ad.ecs_signature
        assert ad2.service_token == ad.service_token
