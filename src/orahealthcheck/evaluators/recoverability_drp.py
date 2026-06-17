from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from orahealthcheck.models import ResultStatus


class RecoverabilityDrpEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia de recuperabilidad y preparación DRP no tiene una estructura válida"
        metric = evidence.get("metric") or config.get("metric")
        if evidence.get("collection_error"):
            return ResultStatus.SKIPPED, f"No se pudo consultar la evidencia requerida para {metric}: {evidence.get('collection_error')}"
        handler = getattr(self, f"_{metric}", None)
        if handler is None:
            return ResultStatus.ERROR, f"Métrica de recuperabilidad y preparación DRP no soportada: {metric}"
        return handler(evidence, config)

    def _recoverability_backup_mode_datafiles(self, e: dict[str, Any], c: dict[str, Any]):
        rows = [r for r in e.get("rows") or [] if str(r.get("status", "")).upper() == "ACTIVE"]
        if rows:
            return ResultStatus.WARNING, "Existen datafiles en modo backup activo; validar si corresponde a una operación vigente."
        return ResultStatus.PASS, "No se detectaron datafiles en modo backup activo."

    def _recoverability_files_need_recovery(self, e: dict[str, Any], c: dict[str, Any]):
        rows = e.get("rows") or []
        if rows:
            return ResultStatus.FAIL, "Se detectaron archivos que requieren recuperación."
        return ResultStatus.PASS, "No se detectaron archivos pendientes de recuperación."

    def _recoverability_block_change_tracking(self, e: dict[str, Any], c: dict[str, Any]):
        required = bool(c.get("required", e.get("required", False)))
        status = str(e.get("status") or "DISABLED").upper()
        if status == "ENABLED":
            return ResultStatus.PASS, "Block Change Tracking está habilitado para respaldos incrementales."
        if required:
            return self._configured_status(c.get("disabled_status", "WARNING")), "Block Change Tracking no está habilitado; esto puede incrementar el trabajo de lectura en respaldos incrementales."
        return ResultStatus.INFO, "Block Change Tracking no está habilitado; esto puede incrementar el trabajo de lectura en respaldos incrementales."

    def _recoverability_backup_metadata_recent(self, e: dict[str, Any], c: dict[str, Any]):
        rows = e.get("rows") or []
        if rows:
            return ResultStatus.PASS, "Se encontraron respaldos recientes en los metadatos locales consultados."
        return self._configured_status(c.get("missing_status", "WARNING")), "No se encontraron respaldos recientes en los metadatos locales consultados. Esto no descarta respaldos externos o gestionados fuera de la base."

    def _recoverability_controlfile_record_retention(self, e: dict[str, Any], c: dict[str, Any]):
        value = self._num(e.get("value"))
        if value is None:
            return ResultStatus.SKIPPED, "No se pudo determinar CONTROL_FILE_RECORD_KEEP_TIME en los parámetros consultados."
        minimum = float(c.get("minimum_days", 14))
        if value < minimum:
            return ResultStatus.WARNING, "CONTROL_FILE_RECORD_KEEP_TIME es menor al umbral recomendado; los metadatos históricos de respaldo podrían sobrescribirse rápidamente."
        return ResultStatus.PASS, "CONTROL_FILE_RECORD_KEEP_TIME cumple el umbral recomendado."

    def _recoverability_restore_points(self, e: dict[str, Any], c: dict[str, Any]):
        rows = e.get("rows") or []
        warn_days = int(c.get("warning_guaranteed_age_days", 30))
        guaranteed_old = [r for r in rows if str(r.get("guarantee_flashback_database", "")).upper() == "YES" and self._is_older_than(r.get("time"), warn_days)]
        if guaranteed_old:
            return ResultStatus.WARNING, "Existen restore points garantizados antiguos; validar consumo de espacio y vigencia operativa."
        if rows:
            return ResultStatus.INFO, "Inventario de restore points disponibles en la base."
        return ResultStatus.INFO, "No existen restore points registrados actualmente."

    def _is_older_than(self, value: Any, days: int) -> bool:
        if value is None:
            return False
        if isinstance(value, datetime):
            return value < datetime.now(value.tzinfo) - timedelta(days=days)
        text = str(value).strip()
        candidates = (text[:19].replace("T", " "), text[:10])
        for candidate, fmt in ((candidates[0], "%Y-%m-%d %H:%M:%S"), (candidates[1], "%Y-%m-%d")):
            try:
                return datetime.strptime(candidate, fmt) < datetime.now() - timedelta(days=days)
            except ValueError:
                continue
        return False

    def _num(self, value: Any) -> float | None:
        try:
            if value is None or value == "":
                return None
            return float(value)
        except (TypeError, ValueError):
            return None

    def _configured_status(self, value: Any) -> ResultStatus:
        try:
            return ResultStatus(str(value).upper())
        except ValueError:
            return ResultStatus.WARNING
