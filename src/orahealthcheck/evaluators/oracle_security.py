from typing import Any

from orahealthcheck.models import ResultStatus


class OracleSecurityEvaluator:
    """Evalúa hallazgos de seguridad Oracle recolectados como listas de filas."""

    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia de seguridad Oracle no tiene el formato esperado"
        if evidence.get("collection_error"):
            status = ResultStatus(config.get("collection_error_status", "ERROR"))
            return status, f"No se pudo recolectar la evidencia de seguridad Oracle: {evidence['collection_error']}"

        count = int(evidence.get("affected_count") or 0)
        label = config.get("label") or evidence.get("label") or "hallazgos de seguridad"
        if count > 0:
            status = ResultStatus(config.get("failure_status", "WARNING"))
            noun = "hallazgo" if count == 1 else "hallazgos"
            return status, f"Se detectaron {count} {noun}: {label}"
        return ResultStatus.PASS, f"No se detectaron hallazgos: {label}"
