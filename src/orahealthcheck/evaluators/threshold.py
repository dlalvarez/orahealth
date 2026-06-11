from typing import Any

from orahealthcheck.models import ResultStatus


_MISSING = object()


def _metric_name(field: str | None) -> str:
    return field or "valor"


def _extract(value: Any, field: str | None, aggregate: str | None = None) -> Any:
    if value is None:
        return _MISSING
    if field is None:
        return value
    if isinstance(value, list):
        values = [item.get(field) for item in value if isinstance(item, dict) and item.get(field) is not None]
        if not values:
            return _MISSING
        if aggregate == "max":
            return max(values)
        if aggregate == "min":
            return min(values)
        return values[0]
    if isinstance(value, dict):
        metric = value.get(field, _MISSING)
        return _MISSING if metric is None else metric
    return value


class ThresholdEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        field = config.get("field")
        raw_value = _extract(evidence, field, config.get("aggregate"))
        if raw_value is _MISSING:
            return ResultStatus.ERROR, f"La métrica {_metric_name(field)} no se encontró en la evidencia"
        try:
            value = float(raw_value)
        except (TypeError, ValueError):
            return ResultStatus.ERROR, f"La métrica {_metric_name(field)} no es numérica en la evidencia"
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
            return ResultStatus.CRITICAL, f"El valor {value} alcanzó el umbral crítico {critical}"
        if hit(fail):
            return ResultStatus.FAIL, f"El valor {value} alcanzó el umbral de fallo {fail}"
        if hit(warning):
            return ResultStatus.WARNING, f"El valor {value} alcanzó el umbral de advertencia {warning}"
        return ResultStatus.PASS, f"El valor {value} está dentro del umbral configurado"
