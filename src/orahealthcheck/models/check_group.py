from dataclasses import dataclass, field


@dataclass
class CheckGroup:
    group_id: str
    name: str
    description: str = ""
    checks: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, group_id: str, data: dict) -> "CheckGroup":
        return cls(group_id=group_id, name=data.get("name", group_id), description=data.get("description", ""), checks=data.get("checks", []))
