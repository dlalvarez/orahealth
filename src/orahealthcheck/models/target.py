from dataclasses import dataclass, field
from typing import Any


@dataclass
class Target:
    target_id: str
    name: str
    environment: str
    expected_architecture: str
    profile: str
    database: dict[str, Any] = field(default_factory=dict)
    operating_system: dict[str, Any] = field(default_factory=dict)
    features: dict[str, Any] = field(default_factory=dict)
    overrides: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "Target":
        return cls(
            target_id=data["target_id"],
            name=data.get("name", data["target_id"]),
            environment=data.get("environment", "unknown"),
            expected_architecture=data.get("expected_architecture", "standalone"),
            profile=data["profile"],
            database=data.get("database", {}),
            operating_system=data.get("operating_system", {}),
            features=data.get("features", {}),
            overrides=data.get("overrides", {}),
        )
