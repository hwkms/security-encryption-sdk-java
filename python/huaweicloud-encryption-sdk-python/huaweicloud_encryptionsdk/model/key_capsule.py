from dataclasses import dataclass
from typing import Optional


@dataclass
class KeyCapsule:
    key_id: Optional[str] = None
    datakey_capsule: Optional[str] = None
    access_point_type: int = 0
    instance_id: Optional[str] = None
