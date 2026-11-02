import json
import pytest
from huaweicloud_encryptionsdk.log.lts_struct_log_builder import LtsStructLogBuilder


class TestBuildEncryptStructLog:
    def test_basic_fields(self):
        log = LtsStructLogBuilder.build_encrypt_struct_log(
            encrypt_file_name=None,
            encrypt_data_bytes=100,
            encrypt_output_file_name=None,
            encrypt_output_bytes=200,
            key_id="kid-123",
            access_point_type="ECS",
            instance_id="inst-456",
        )
        assert log["operation"] == "encrypt"
        assert "timestamp" in log
        assert "utcTime" in log
        assert log["encryptDataBytes"] == "100"
        assert log["encryptOutputBytes"] == "200"
        assert log["keyId"] == "kid-123"
        assert log["accessPointType"] == "ECS"
        assert log["instanceId"] == "inst-456"

    def test_optional_fields_omitted(self):
        log = LtsStructLogBuilder.build_encrypt_struct_log(
            encrypt_file_name=None,
            encrypt_data_bytes=0,
            encrypt_output_file_name=None,
            encrypt_output_bytes=0,
            key_id=None,
            access_point_type=None,
            instance_id=None,
        )
        assert "encryptDataBytes" not in log
        assert "encryptOutputBytes" not in log
        assert "keyId" not in log
        assert "accessPointType" not in log
        assert "instanceId" not in log

    def test_with_file_names(self):
        log = LtsStructLogBuilder.build_encrypt_struct_log(
            encrypt_file_name="test.txt",
            encrypt_data_bytes=100,
            encrypt_output_file_name="test.enc",
            encrypt_output_bytes=200,
            key_id="kid",
            access_point_type="Custom",
            instance_id=None,
        )
        assert log["encryptFileName"] == "test.txt"
        assert log["encryptOutputFileName"] == "test.enc"
        assert "instanceId" not in log

    def test_utc_time_format(self):
        log = LtsStructLogBuilder.build_encrypt_struct_log(
            encrypt_file_name=None, encrypt_data_bytes=None,
            encrypt_output_file_name=None, encrypt_output_bytes=None,
            key_id=None, access_point_type=None, instance_id=None,
        )
        assert log["utcTime"].endswith("Z")
        assert "T" in log["utcTime"]


class TestBuildDecryptStructLog:
    def test_basic_fields(self):
        log = LtsStructLogBuilder.build_decrypt_struct_log(
            decrypt_file_name=None,
            decrypt_data_bytes=200,
            decrypt_output_file_name=None,
            decrypt_output_bytes=100,
            key_id="kid-123",
            access_point_type="CCE",
            instance_id="inst-789",
        )
        assert log["operation"] == "decrypt"
        assert log["decryptDataBytes"] == "200"
        assert log["decryptOutputBytes"] == "100"
        assert log["keyId"] == "kid-123"
        assert log["accessPointType"] == "CCE"
        assert log["instanceId"] == "inst-789"

    def test_instance_id_from_decrypt_response(self):
        log = LtsStructLogBuilder.build_decrypt_struct_log(
            decrypt_file_name=None, decrypt_data_bytes=None,
            decrypt_output_file_name=None, decrypt_output_bytes=None,
            key_id="kid", access_point_type="Custom",
            instance_id="from-kms-response",
        )
        assert log["instanceId"] == "from-kms-response"


class TestGetLocalIp:
    def test_returns_string_or_none(self):
        ip = LtsStructLogBuilder.get_local_ip()
        assert ip is None or isinstance(ip, str)
