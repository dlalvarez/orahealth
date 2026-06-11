from typing import Any

from orahealthcheck.models import ResultStatus


class EmptyResultPassEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not evidence:
            return ResultStatus.PASS, "El resultado está vacío según lo esperado"
        return ResultStatus(config.get("failure_status", "FAIL")), "El resultado no está vacío"
