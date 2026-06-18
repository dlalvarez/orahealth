from typing import Any

from orahealthcheck.models import ResultStatus


class StorageEvaluator:
    """Evaluate Oracle storage evidence assembled from reusable inventory data."""

    def evaluate(self, evidence: dict[str, Any], config: dict[str, Any]) -> tuple[ResultStatus, str]:
        metric = evidence.get("metric")
        if metric == "tablespace_free_pct":
            return self._low_threshold(evidence.get("worst_free_pct"), config, "El porcentaje libre mínimo de tablespace")
        if metric == "tablespace_used_pct":
            return self._high_threshold(evidence.get("max_used_pct"), config, "El porcentaje usado máximo de tablespace")
        if metric == "datafiles_autoextend_disabled":
            if evidence.get("datafiles") is None:
                return ResultStatus.ERROR, "No se encontró información de datafiles en la evidencia"
            count = int(evidence.get("affected_count") or 0)
            if count:
                return self._configured_status(config.get("status_when_found", "WARNING")), f"{count} datafile(s) tienen AUTOEXTENSIBLE deshabilitado"
            return ResultStatus.PASS, "Todos los datafiles son autoextensibles o no se detectaron datafiles fijos"
        if metric == "datafiles_near_maxsize":
            return self._high_threshold(evidence.get("max_used_of_max_pct"), config, "El uso máximo de datafile respecto a maxsize")
        if metric == "datafiles_status":
            if evidence.get("datafile_count") == 0:
                return ResultStatus.ERROR, "No se encontró información de datafiles en la evidencia"
            count = int(evidence.get("affected_count") or 0)
            if count:
                return ResultStatus.FAIL, f"{count} datafile(s) tienen estado anómalo"
            return ResultStatus.PASS, "Todos los datafiles están en estado AVAILABLE/ONLINE"
        if metric == "tempfiles_status":
            if int(evidence.get("tempfile_count") or 0) == 0:
                return self._configured_status(config.get("missing_status", "WARNING")), "No se encontraron tempfiles"
            count = int(evidence.get("affected_count") or 0)
            if count:
                return self._configured_status(config.get("anomaly_status", "FAIL")), f"{count} tempfile(s) tienen estado anómalo"
            return ResultStatus.PASS, "Los tempfiles existen y tienen estado aceptable"
        if metric == "temp_usage_pct":
            if not evidence.get("tablespaces"):
                return ResultStatus.ERROR, "No se encontró información de uso activo de tablespaces temporales en la evidencia"
            if evidence.get("active_usage_available") is False:
                status = self._configured_status(config.get("fallback_status", "SKIPPED"))
                reason = evidence.get("fallback_reason") or "la fuente activa de uso de TEMP no está disponible"
                return status, f"No se pudo medir el uso activo de tablespace temporal desde v$tempseg_usage; se recolectó evidencia fallback pero no se aplicaron umbrales para evitar falsos positivos. Motivo: {reason}"
            return self._high_threshold(evidence.get("max_used_pct"), config, "El uso activo de tablespace temporal")
        if metric == "undo_tablespace_status":
            if not evidence.get("undo_tablespace") or evidence.get("status") is None:
                return ResultStatus.WARNING, "No se pudo determinar completamente la información del tablespace UNDO"
            if str(evidence.get("status")).upper() != "ONLINE":
                return ResultStatus.WARNING, f"El estado del tablespace UNDO es {evidence.get('status')}"
            return ResultStatus.PASS, "La información del tablespace UNDO y undo_retention fue recolectada"
        if metric in {"users_system_default_tablespace", "users_missing_default_tablespace", "users_missing_temp_tablespace", "dictionary_managed_tablespaces"}:
            count = int(evidence.get("affected_count") or 0)
            if count:
                return self._configured_status(config.get("status_when_found", "WARNING")), self._found_message(metric, count)
            return ResultStatus.PASS, self._pass_message(metric)
        if metric == "users_system_temp_tablespace":
            count = int(evidence.get("affected_count") or 0)
            if count:
                return self._configured_status(config.get("status_when_found", "FAIL")), f"Se detectaron {count} usuario(s) con SYSTEM como tablespace temporal"
            return ResultStatus.PASS, "No se detectaron usuarios con SYSTEM como tablespace temporal"
        if metric == "fra_configured":
            configured = bool(evidence.get("fra_configured"))
            if configured:
                return ResultStatus.PASS, "FRA está configurada"
            status = self._configured_status(config.get("missing_status", "SKIPPED"))
            return status, evidence.get("message") or "FRA no está configurada"
        if metric in ("fra_usage", "fra_usage_pct"):
            if not evidence.get("fra_configured"):
                return ResultStatus.SKIPPED, evidence.get("message") or "FRA no está configurada"
            return self._high_threshold(evidence.get("used_pct", evidence.get("fra_used_pct")), config, "El uso de FRA")
        return ResultStatus.ERROR, f"Métrica de storage no soportada: {metric}"

    def _found_message(self, metric: Any, count: int) -> str:
        messages = {
            "users_system_default_tablespace": f"Se detectaron {count} usuario(s) abiertos de aplicación con SYSTEM como tablespace por defecto",
            "users_missing_default_tablespace": f"Se detectaron {count} usuario(s) sin tablespace por defecto válido",
            "users_missing_temp_tablespace": f"Se detectaron {count} usuario(s) sin tablespace temporal válido",
            "dictionary_managed_tablespaces": f"Se detectaron {count} tablespace(s) administrados por diccionario",
        }
        return messages.get(str(metric), f"Se detectaron {count} hallazgo(s) de storage")

    def _pass_message(self, metric: Any) -> str:
        messages = {
            "users_system_default_tablespace": "No se detectaron usuarios abiertos de aplicación con SYSTEM como tablespace por defecto",
            "users_missing_default_tablespace": "No se detectaron usuarios sin tablespace por defecto válido",
            "users_missing_temp_tablespace": "No se detectaron usuarios sin tablespace temporal válido",
            "dictionary_managed_tablespaces": "No se detectaron tablespaces administrados por diccionario",
        }
        return messages.get(str(metric), "No se detectaron hallazgos de storage")

    def _high_threshold(self, raw_value: Any, config: dict[str, Any], label: str) -> tuple[ResultStatus, str]:
        value = self._numeric(raw_value)
        if value is None:
            return ResultStatus.ERROR, f"{label} no se encontró en la evidencia"
        if config.get("critical") is not None and value >= float(config["critical"]):
            return ResultStatus.CRITICAL, f"{label} {value} alcanzó el umbral crítico {config['critical']}"
        if config.get("fail") is not None and value >= float(config["fail"]):
            return ResultStatus.FAIL, f"{label} {value} alcanzó el umbral de fallo {config['fail']}"
        if config.get("warning") is not None and value >= float(config["warning"]):
            return ResultStatus.WARNING, f"{label} {value} alcanzó el umbral de advertencia {config['warning']}"
        return ResultStatus.PASS, f"{label} {value} está dentro del umbral configurado"

    def _low_threshold(self, raw_value: Any, config: dict[str, Any], label: str) -> tuple[ResultStatus, str]:
        value = self._numeric(raw_value)
        if value is None:
            return ResultStatus.ERROR, f"{label} no se encontró en la evidencia"
        if config.get("critical") is not None and value <= float(config["critical"]):
            return ResultStatus.CRITICAL, f"{label} {value} alcanzó el umbral crítico {config['critical']}"
        if config.get("fail") is not None and value <= float(config["fail"]):
            return ResultStatus.FAIL, f"{label} {value} alcanzó el umbral de fallo {config['fail']}"
        if config.get("warning") is not None and value <= float(config["warning"]):
            return ResultStatus.WARNING, f"{label} {value} alcanzó el umbral de advertencia {config['warning']}"
        return ResultStatus.PASS, f"{label} {value} está dentro del umbral configurado"

    def _numeric(self, raw_value: Any) -> float | None:
        try:
            return float(raw_value)
        except (TypeError, ValueError):
            return None

    def _configured_status(self, value: Any) -> ResultStatus:
        try:
            return ResultStatus(str(value).upper())
        except ValueError:
            return ResultStatus.WARNING
