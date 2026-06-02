from dataclasses import dataclass, field
from typing import Any


@dataclass
class Check:
    check_id: str
    group_id: str
    title: str
    description: str = ""
    severity: str = "WARNING"
    collector: dict[str, Any] = field(default_factory=dict)
    evaluator: dict[str, Any] = field(default_factory=dict)
    applies_to: dict[str, Any] = field(default_factory=dict)
    remediation: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "Check":
        return cls(
            check_id=data["check_id"],
            group_id=data["group_id"],
            title=data.get("title", data["check_id"]),
            description=data.get("description", ""),
            severity=data.get("severity", "WARNING"),
            collector=data.get("collector", {}),
            evaluator=data.get("evaluator", {}),
            applies_to=data.get("applies_to", {}),
            remediation=data.get("remediation", {}),
            tags=data.get("tags", []),
            references=data.get("references", []),
        )
