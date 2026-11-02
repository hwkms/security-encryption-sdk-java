from dataclasses import dataclass
from typing import Optional


@dataclass
class KMSConfig:
    region: str = ""
    key_id: str = ""
    project_id: str = ""
    end_point: Optional[str] = None
