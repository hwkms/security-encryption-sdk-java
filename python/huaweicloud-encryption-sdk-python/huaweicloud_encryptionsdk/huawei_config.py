from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage
from huaweicloud_encryptionsdk.model.kms_config import KMSConfig
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.key_capsule_config import KeyCapsuleConfig
from huaweicloud_encryptionsdk.log.log_config import LogConfig


@dataclass
class HuaweiConfig:
    ak: str = ""
    sk: str = ""
    security_token: Optional[str] = None
    is_discovery: bool = False
    kms_config_list: Optional[list[KMSConfig]] = None
    origin_kms_config_list: Optional[list[KMSConfig]] = None
    crypto_algorithm: Optional[CryptoAlgorithm] = None
    key_capsule_config: Optional[KeyCapsuleConfig] = None
    log_config: Optional[LogConfig] = None
    local_log_only: bool = False

    def __post_init__(self):
        if self.ak:
            self._validate_non_empty(self.ak, ErrorMessage.AK_NULL_EXCEPTION)
        if self.sk:
            self._validate_non_empty(self.sk, ErrorMessage.SK_NULL_EXCEPTION)

    @staticmethod
    def _validate_non_empty(value: str, error: ErrorMessage) -> None:
        if not value or not value.strip():
            raise HuaweicloudException(error.message)

    def set_ak(self, value: str) -> None:
        self._validate_non_empty(value, ErrorMessage.AK_NULL_EXCEPTION)
        self.ak = value

    def set_sk(self, value: str) -> None:
        self._validate_non_empty(value, ErrorMessage.SK_NULL_EXCEPTION)
        self.sk = value

    def get_ak(self) -> str:
        return self.ak

    def get_sk(self) -> str:
        return self.sk
