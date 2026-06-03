from typing import Any, Protocol

from orahealthcheck.models import ResultStatus


class Evaluator(Protocol):
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]: ...
