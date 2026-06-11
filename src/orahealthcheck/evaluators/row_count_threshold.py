from typing import Any

from orahealthcheck.models import ResultStatus


class RowCountThresholdEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        count = len(evidence) if isinstance(evidence, list) else (0 if not evidence else 1)
        warning = config.get("warning")
        fail = config.get("fail", config.get("max"))
        critical = config.get("critical")
        if critical is not None and count >= int(critical):
            return ResultStatus.CRITICAL, f"La cantidad de filas {count} alcanzó el umbral crítico {critical}"
        if fail is not None and count >= int(fail):
            return ResultStatus.FAIL, f"La cantidad de filas {count} alcanzó el umbral de fallo {fail}"
        if warning is not None and count >= int(warning):
            return ResultStatus.WARNING, f"La cantidad de filas {count} alcanzó el umbral de advertencia {warning}"
        return ResultStatus.PASS, f"La cantidad de filas {count} está dentro del umbral configurado"
