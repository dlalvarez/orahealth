from typing import Any

from orahealthcheck.models import ResultStatus


_MISSING = object()


def _normalize(value: Any) -> str:
    return str(value).strip().upper()


def _get_actual(evidence: Any) -> Any:
    if isinstance(evidence, dict):
        if evidence.get("exists") is False:
            return _MISSING
        return evidence.get("actual_value", _MISSING)
    return evidence if evidence is not None else _MISSING


class OracleConfigEvaluator:
    """Evaluate Oracle configuration evidence with clear controlled missing-data handling."""

    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        actual = _get_actual(evidence)
        metric = config.get("label") or (evidence.get("parameter") if isinstance(evidence, dict) else None) or config.get("field") or "metric"
        if actual is _MISSING or actual is None:
            return ResultStatus(config.get("missing_status", "ERROR")), f"No se encontró evidencia para {metric}"

        disallowed_values = config.get("disallowed_values", [])
        if disallowed_values and _normalize(actual) in {_normalize(value) for value in disallowed_values}:
            return (
                ResultStatus(config.get("failure_status", "WARNING")),
                f"Valor actual de {metric}: {actual}. El valor está en la lista no permitida {disallowed_values}",
            )

        expected = config.get("expected")
        if expected is not None:
            matches = _normalize(actual) == _normalize(expected) if config.get("case_insensitive", True) else actual == expected
            if matches:
                return ResultStatus.PASS, f"Valor actual de {metric}: {actual}. Coincide con el esperado {expected}"
            return (
                ResultStatus(config.get("failure_status", "WARNING")),
                f"Valor actual de {metric}: {actual}. Difiere del esperado {expected}",
            )

        minimum = config.get("minimum")
        if minimum is not None:
            try:
                actual_number = float(actual)
                minimum_number = float(minimum)
            except (TypeError, ValueError):
                return ResultStatus.ERROR, f"La métrica {metric} no es numérica en la evidencia"
            if actual_number >= minimum_number:
                return ResultStatus.PASS, f"Valor actual de {metric}: {actual_number:g}. Cumple el mínimo {minimum_number:g}"
            return (
                ResultStatus(config.get("failure_status", "WARNING")),
                f"Valor actual de {metric}: {actual_number:g}. Es menor al mínimo {minimum_number:g}",
            )

        return ResultStatus(config.get("report_status", "INFO")), f"Valor actual de {metric}: {actual}"
