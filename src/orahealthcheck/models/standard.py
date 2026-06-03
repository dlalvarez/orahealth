from dataclasses import dataclass, field
from typing import Any


@dataclass
class Standard:
    standard_id: str
    policies: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, standard_id: str, data: dict[str, Any]) -> "Standard":
        return cls(standard_id=standard_id, policies=data.get("policies", data))
