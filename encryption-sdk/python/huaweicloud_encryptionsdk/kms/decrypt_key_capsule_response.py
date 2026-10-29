from dataclasses import dataclass
from typing import Optional


@dataclass
class DecryptKeyCapsuleResponse:
    key_id: Optional[str] = None
    datakey: Optional[str] = None
    datakey_cipher: Optional[str] = None
    instance_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data):
        return cls(
            key_id=data.get("key_id"),
            datakey=data.get("datakey"),
            datakey_cipher=data.get("datakey_cipher"),
            instance_id=data.get("instance_id"),
        )
