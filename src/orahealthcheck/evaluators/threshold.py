from typing import Any

from orahealthcheck.models import ResultStatus


def _extract(value: Any, field: str | None, aggregate: str | None = None) -> Any:
    if field is None:
        return value
    if isinstance(value, list):
        values = [item.get(field) for item in value if isinstance(item, dict) and item.get(field) is not None]
        if not values:
            return 0
        if aggregate == "max":
            return max(values)
        if aggregate == "min":
            return min(values)
        return values[0]
    if isinstance(value, dict):
        return value.get(field)
    return value


class ThresholdEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        field = config.get("field")
        value = float(_extract(evidence, field, config.get("aggregate")))
        warning = config.get("warning")
        critical = config.get("critical")
        fail = config.get("fail")
        operator = config.get("operator", ">=")
        def hit(limit: Any) -> bool:
            if limit is None:
                return False
            limit = float(limit)
            return value >= limit if operator == ">=" else value <= limit
        if hit(critical):
            return ResultStatus.CRITICAL, f"Value {value} reached critical threshold {critical}"
        if hit(fail):
            return ResultStatus.FAIL, f"Value {value} reached fail threshold {fail}"
        if hit(warning):
            return ResultStatus.WARNING, f"Value {value} reached warning threshold {warning}"
        return ResultStatus.PASS, f"Value {value} is within threshold"
