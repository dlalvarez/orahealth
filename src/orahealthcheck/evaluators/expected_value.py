from typing import Any

from orahealthcheck.models import ResultStatus


class ExpectedValueEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        field = config.get("field")
        if isinstance(evidence, list) and evidence:
            evidence = evidence[0]
        actual = evidence.get(field) if isinstance(evidence, dict) and field else evidence
        expected = config.get("expected")
        if actual == expected:
            return ResultStatus.PASS, f"Valor actual coincide con el esperado {expected}"
        return ResultStatus(config.get("failure_status", "FAIL")), f"Valor actual {actual!r} difiere del esperado {expected!r}"
