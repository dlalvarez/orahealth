from typing import Any

from orahealthcheck.models import ResultStatus


class NotEmptyFailEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if evidence:
            return ResultStatus(config.get("failure_status", "FAIL")), "Result contains rows"
        return ResultStatus.PASS, "Result is empty"
