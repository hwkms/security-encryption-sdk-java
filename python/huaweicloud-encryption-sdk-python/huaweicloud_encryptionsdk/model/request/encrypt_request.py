from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class EncryptRequest:
    encryption_context: Dict[str, str] = field(default_factory=dict)
    plain_text: bytes = b""
    policy_id: Optional[str] = None
    key_policy: Optional[str] = None
