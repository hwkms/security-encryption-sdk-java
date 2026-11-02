from dataclasses import dataclass
from typing import Optional


@dataclass
class CreateKeyCapsuleResponse:
    key_id: Optional[str] = None
    datakey_cipher: Optional[str] = None
    datakey: Optional[str] = None
    datakey_capsule: Optional[str] = None

    @classmethod
    def from_dict(cls, data):
        return cls(
            key_id=data.get("key_id"),
            datakey_cipher=data.get("datakey_cipher"),
            datakey=data.get("datakey"),
            datakey_capsule=data.get("datakey_capsule"),
        )
