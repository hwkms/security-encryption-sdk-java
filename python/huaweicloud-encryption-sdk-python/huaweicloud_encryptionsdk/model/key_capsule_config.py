from dataclasses import dataclass
from typing import Optional

from huaweicloud_encryptionsdk.model.access_point_config import AccessPointConfig


@dataclass
class KeyCapsuleConfig:
    region: str = ""
    default_policy_id: Optional[str] = None
    default_key_policy: Optional[str] = None
    access_point_config: Optional[AccessPointConfig] = None
