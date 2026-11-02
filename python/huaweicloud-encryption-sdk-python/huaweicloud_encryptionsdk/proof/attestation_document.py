import json
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class AttestationDocument:
    ecs_signature: Optional[str] = field(default=None)
    custom_signature: Optional[str] = field(default=None)
    custom_public_key: Optional[str] = field(default=None)
    expire_time: Optional[str] = field(default=None)
    service_token: Optional[str] = field(default=None)
    modelarts_job_id: Optional[str] = field(default=None)
    modelarts_pool_id: Optional[str] = field(default=None)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "AttestationDocument":
        return cls(
            ecs_signature=data.get("ecs_signature"),
            custom_signature=data.get("custom_signature"),
            custom_public_key=data.get("custom_public_key"),
            expire_time=data.get("expire_time"),
            service_token=data.get("service_token"),
            modelarts_job_id=data.get("modelarts_job_id"),
            modelarts_pool_id=data.get("modelarts_pool_id"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "AttestationDocument":
        return cls.from_dict(json.loads(json_str))
