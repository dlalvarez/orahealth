from dataclasses import dataclass, field
from typing import Any


@dataclass
class ConnectionProfile:
    connection_id: str
    type: str
    auth_method: str
    settings: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, connection_id: str, data: dict[str, Any]) -> "ConnectionProfile":
        copied = dict(data)
        return cls(
            connection_id=connection_id,
            type=str(copied.pop("type", "")),
            auth_method=str(copied.pop("auth_method", "")),
            settings=copied,
        )

    def masked(self) -> dict[str, Any]:
        masked = {"connection_id": self.connection_id, "type": self.type, "auth_method": self.auth_method, **self.settings}
        for key in list(masked):
            if "password" in key.lower() or "passphrase" in key.lower():
                masked[key] = "***"
        return masked
