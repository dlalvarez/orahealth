from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ResultStatus(str, Enum):
    PASS = "PASS"
    INFO = "INFO"
    WARNING = "WARNING"
    FAIL = "FAIL"
    CRITICAL = "CRITICAL"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


@dataclass
class Result:
    check_id: str
    group_id: str
    status: ResultStatus
    title: str
    severity: str = "WARNING"
    message: str = ""
    evidence: Any = None
    remediation: dict[str, Any] = field(default_factory=dict)
    skipped_reason: str | None = None
    error: str | None = None
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "group_id": self.group_id,
            "status": self.status.value,
            "title": self.title,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "skipped_reason": self.skipped_reason,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }
