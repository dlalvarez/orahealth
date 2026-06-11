from typing import Any

from orahealthcheck.models import ResultStatus


class NotEmptyFailEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if evidence:
            return ResultStatus(config.get("failure_status", "FAIL")), "El resultado contiene filas"
        return ResultStatus.PASS, "El resultado está vacío"
