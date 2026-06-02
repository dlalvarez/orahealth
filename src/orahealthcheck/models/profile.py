from dataclasses import dataclass, field
from typing import Any


@dataclass
class Profile:
    profile_id: str
    description: str = ""
    enabled_groups: list[str] = field(default_factory=list)
    standards: list[str] = field(default_factory=list)
    disabled_groups: list[str] = field(default_factory=list)
    disabled_checks: list[str] = field(default_factory=list)
    overrides: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, profile_id: str, data: dict[str, Any]) -> "Profile":
        return cls(
            profile_id=profile_id,
            description=data.get("description", ""),
            enabled_groups=data.get("enabled_groups", []),
            standards=data.get("standards", []),
            disabled_groups=data.get("disabled_groups", []),
            disabled_checks=data.get("disabled_checks", []),
            overrides=data.get("overrides", {}),
        )
