from typing import Any

from orahealthcheck.models import ResultStatus


class AlertLogEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia del alert log no tiene el formato esperado"
        if evidence.get("available") is False:
            if evidence.get("status") == "error":
                return ResultStatus.ERROR, evidence.get("message", "Error técnico al acceder al alert log")
            return ResultStatus.SKIPPED, evidence.get("message", "No fue posible acceder al alert log con las fuentes configuradas")

        count = int(evidence.get("occurrences", 0) or 0)
        mode = config.get("mode", "fail_on_match")
        if mode == "info":
            return ResultStatus.INFO, evidence.get("message", "Resumen informativo del alert log generado")
        if mode == "fail_on_match" and count > 0:
            status = ResultStatus(config.get("failure_status", "FAIL"))
            return status, evidence.get("message", f"Se detectaron {count} ocurrencias relevantes en el alert log")
        return ResultStatus.PASS, evidence.get("message", "No se detectaron eventos de esta familia en la muestra del alert log")
