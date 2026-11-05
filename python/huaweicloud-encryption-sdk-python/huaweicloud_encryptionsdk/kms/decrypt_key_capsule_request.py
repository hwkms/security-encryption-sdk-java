from dataclasses import dataclass
from typing import Optional


@dataclass
class DecryptKeyCapsuleRequest:
    key_id: Optional[str] = None
    datakey_capsule: Optional[str] = None
    attestation_document: Optional[object] = None

    def to_dict(self):
        result = {}
        if self.key_id is not None:
            result["key_id"] = self.key_id
        if self.datakey_capsule is not None:
            result["datakey_capsule"] = self.datakey_capsule
        if self.attestation_document is not None:
            if hasattr(self.attestation_document, 'to_dict'):
                result["attestation_document"] = self.attestation_document.to_dict()
            elif hasattr(self.attestation_document, '__dict__'):
                result["attestation_document"] = self.attestation_document.__dict__
            else:
                result["attestation_document"] = self.attestation_document
        return result

    @classmethod
    def from_dict(cls, data):
        return cls(
            key_id=data.get("key_id"),
            datakey_capsule=data.get("datakey_capsule"),
            attestation_document=data.get("attestation_document"),
        )
