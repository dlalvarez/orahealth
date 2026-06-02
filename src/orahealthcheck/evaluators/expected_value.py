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
            return ResultStatus.PASS, f"Actual value matches expected value {expected}"
        return ResultStatus(config.get("failure_status", "FAIL")), f"Actual value {actual!r} differs from expected {expected!r}"
