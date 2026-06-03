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
    """Outcome of a check execution.

    ``status`` is the observed result for this execution. ``failure_severity`` is
    check metadata that describes the severity to assign when the check detects
    non-compliance; it is not the runtime status itself.
    """

    check_id: str
    group_id: str
    status: ResultStatus
    title: str
    failure_severity: str = "WARNING"
    message: str = ""
    evidence: Any = None
    remediation: dict[str, Any] = field(default_factory=dict)
    skipped_reason: str | None = None
    error: str | None = None
    duration_ms: int = 0

    @property
    def severity(self) -> str:
        """Backward-compatible alias for templates or callers using severity."""
        return self.failure_severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "group_id": self.group_id,
            "status": self.status.value,
            "title": self.title,
            "failure_severity": self.failure_severity,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "skipped_reason": self.skipped_reason,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }
