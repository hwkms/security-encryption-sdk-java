import re
import socket
import time
from datetime import datetime, timezone
from typing import Optional


_CONTROL_CHARS_PATTERN = re.compile(r'[\r\n\t\x00-\x1F\x7F-\x9F]')


def sanitize(input_str: Optional[str]) -> str:
    if input_str is None:
        return ""
    return _CONTROL_CHARS_PATTERN.sub("", input_str)


class LtsStructLogBuilder:

    @staticmethod
    def build_encrypt_struct_log(
        encrypt_file_name: Optional[str],
        encrypt_data_bytes: Optional[int],
        encrypt_output_file_name: Optional[str],
        encrypt_output_bytes: Optional[int],
        key_id: Optional[str],
        access_point_type: Optional[str],
        instance_id: Optional[str],
    ) -> dict:
        return LtsStructLogBuilder.build_struct_log(
            "encrypt", encrypt_file_name, encrypt_data_bytes,
            encrypt_output_file_name, encrypt_output_bytes,
            key_id, access_point_type, instance_id,
        )

    @staticmethod
    def build_decrypt_struct_log(
        decrypt_file_name: Optional[str],
        decrypt_data_bytes: Optional[int],
        decrypt_output_file_name: Optional[str],
        decrypt_output_bytes: Optional[int],
        key_id: Optional[str],
        access_point_type: Optional[str],
        instance_id: Optional[str],
    ) -> dict:
        return LtsStructLogBuilder.build_struct_log(
            "decrypt", decrypt_file_name, decrypt_data_bytes,
            decrypt_output_file_name, decrypt_output_bytes,
            key_id, access_point_type, instance_id,
        )

    @staticmethod
    def build_struct_log(
        operation: str,
        file_name: Optional[str],
        data_bytes: Optional[int],
        output_file_name: Optional[str],
        output_bytes: Optional[int],
        key_id: Optional[str],
        access_point_type: Optional[str],
        instance_id: Optional[str],
    ) -> dict:
        struct_log = {}
        ts = int(time.time() * 1000)
        struct_log["timestamp"] = str(ts)
        struct_log["utcTime"] = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        struct_log["operation"] = sanitize(operation)

        field_prefix = operation
        if file_name:
            struct_log[field_prefix + "FileName"] = sanitize(file_name)
        if data_bytes is not None and data_bytes > 0:
            struct_log[field_prefix + "DataBytes"] = str(data_bytes)
        if output_file_name:
            struct_log[field_prefix + "OutputFileName"] = sanitize(output_file_name)
        if output_bytes is not None and output_bytes > 0:
            struct_log[field_prefix + "OutputBytes"] = str(output_bytes)
        if key_id:
            struct_log["keyId"] = sanitize(key_id)
        if access_point_type:
            struct_log["accessPointType"] = sanitize(access_point_type)
        if instance_id:
            struct_log["instanceId"] = sanitize(instance_id)

        ip = LtsStructLogBuilder.get_local_ip()
        if ip:
            struct_log["ipAddress"] = ip
        return struct_log

    @staticmethod
    def get_local_ip() -> Optional[str]:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                addr = info[4][0]
                if addr and not addr.startswith("127."):
                    return addr
        except Exception:
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            pass
        return None
