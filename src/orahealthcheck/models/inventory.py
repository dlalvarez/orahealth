from dataclasses import dataclass, field
from typing import Any


@dataclass
class Inventory:
    target_id: str
    architecture: str
    environment: str
    database: dict[str, Any] = field(default_factory=dict)
    operating_system: dict[str, Any] = field(default_factory=dict)
    features: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "architecture": self.architecture,
            "environment": self.environment,
            "database": self.database,
            "operating_system": self.operating_system,
            "features": self.features,
        }
