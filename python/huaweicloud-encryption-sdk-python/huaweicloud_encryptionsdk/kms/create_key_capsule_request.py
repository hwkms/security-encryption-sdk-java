from dataclasses import dataclass
from typing import Optional


@dataclass
class CreateKeyCapsuleRequest:
    key_id: Optional[str] = None
    datakey_length: int = 0
    public_key: Optional[str] = None
    policy_id: Optional[str] = None
    key_policy: Optional[str] = None

    def to_dict(self):
        result = {}
        if self.key_id is not None:
            result["key_id"] = self.key_id
        if self.datakey_length is not None:
            result["datakey_length"] = self.datakey_length
        if self.public_key is not None:
            result["public_key"] = self.public_key
        if self.policy_id is not None:
            result["policy_id"] = self.policy_id
        if self.key_policy is not None:
            result["key_policy"] = self.key_policy
        return result

    @classmethod
    def from_dict(cls, data):
        return cls(
            key_id=data.get("key_id"),
            datakey_length=data.get("datakey_length", 0),
            public_key=data.get("public_key"),
            policy_id=data.get("policy_id"),
            key_policy=data.get("key_policy"),
        )
