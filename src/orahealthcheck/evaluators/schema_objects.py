from typing import Any

from orahealthcheck.models import ResultStatus


class SchemaObjectsEvaluator:
    """Evalúa hallazgos avanzados de esquemas y objetos Oracle."""

    def evaluate(self, evidence: dict[str, Any], config: dict[str, Any]) -> tuple[ResultStatus, str]:
        metric = evidence.get("metric")
        count = int(evidence.get("affected_count") or 0)
        rows = evidence.get("rows") if isinstance(evidence.get("rows"), list) else []
        if count == 0:
            return ResultStatus.PASS, self._pass_message(metric)

        if metric == "invalid_objects_detail":
            critical_types = {str(value).upper() for value in config.get("critical_object_types", [])}
            has_critical_type = any(str(row.get("object_type", "")).upper() in critical_types for row in rows if isinstance(row, dict))
            fail = config.get("fail")
            warning = config.get("warning", 1)
            if has_critical_type:
                return ResultStatus.FAIL, f"Se detectaron {count} objeto(s) inválido(s), incluyendo tipos críticos para ejecución lógica"
            if fail is not None and count >= int(fail):
                return ResultStatus.FAIL, f"Se detectaron {count} objeto(s) inválido(s), superando el umbral de fallo {fail}"
            if warning is not None and count >= int(warning):
                return ResultStatus.WARNING, f"Se detectaron {count} objeto(s) inválido(s) en esquemas de aplicación"
            return ResultStatus.PASS, "Los objetos inválidos están dentro del umbral configurado"

        if metric in {"unusable_indexes", "unusable_index_partitions"}:
            return ResultStatus.FAIL, f"Se detectaron {count} índice(s) o partición(es) de índice en estado no utilizable"

        if metric == "disabled_constraints":
            strict_types = {str(value).upper() for value in config.get("fail_constraint_types", ["P", "U"])}
            has_strict_type = any(str(row.get("constraint_type", "")).upper() in strict_types for row in rows if isinstance(row, dict))
            if has_strict_type:
                return ResultStatus.FAIL, f"Se detectaron {count} restricción(es) deshabilitada(s), incluyendo llaves primarias o únicas"
            return self._configured_status(config.get("status_when_found", "WARNING")), f"Se detectaron {count} restricción(es) deshabilitada(s)"

        if metric == "indexes_too_many_columns":
            threshold = int(config.get("warning", config.get("max_columns", 8)) or 8)
            affected = [row for row in rows if isinstance(row, dict) and int(row.get("column_count") or 0) > threshold]
            affected_count = len(affected)
            if affected_count:
                return self._configured_status(config.get("status_when_found", "WARNING")), f"Se detectaron {affected_count} índice(s) con más de {threshold} columnas"
            return ResultStatus.PASS, f"No se detectaron índices con más de {threshold} columnas"

        if metric in {"disabled_triggers", "stale_table_statistics", "missing_table_statistics", "locked_table_statistics", "invalid_synonyms", "tables_without_primary_key", "foreign_keys_without_index", "tables_with_long_columns"}:
            return self._threshold_or_status(count, config, self._found_message(metric, count))

        if metric == "recyclebin_objects":
            total_mb = self._numeric(evidence.get("total_mb")) or 0.0
            warning_count = config.get("warning_count")
            warning_mb = config.get("warning_mb")
            if (warning_count is not None and count >= int(warning_count)) or (warning_mb is not None and total_mb >= float(warning_mb)):
                return ResultStatus.WARNING, f"La papelera de reciclaje contiene {count} objeto(s) y aproximadamente {total_mb:g} MB"
            return self._configured_status(config.get("status_when_found", "INFO")), f"La papelera de reciclaje contiene {count} objeto(s) dentro de los umbrales configurados"

        return ResultStatus.ERROR, f"Métrica de esquemas y objetos no soportada: {metric}"

    def _threshold_or_status(self, count: int, config: dict[str, Any], message: str) -> tuple[ResultStatus, str]:
        fail = config.get("fail")
        warning = config.get("warning")
        if fail is not None and count >= int(fail):
            return ResultStatus.FAIL, f"{message}; supera el umbral de fallo {fail}"
        if warning is not None and count >= int(warning):
            return ResultStatus.WARNING, f"{message}; supera el umbral de advertencia {warning}"
        return self._configured_status(config.get("status_when_found", "WARNING")), message

    def _configured_status(self, value: Any) -> ResultStatus:
        try:
            return ResultStatus(str(value).upper())
        except ValueError:
            return ResultStatus.WARNING

    def _numeric(self, value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _pass_message(self, metric: Any) -> str:
        messages = {
            "invalid_objects_detail": "No se detectaron objetos inválidos relevantes en esquemas de aplicación",
            "unusable_indexes": "No se detectaron índices no utilizables en esquemas de aplicación",
            "unusable_index_partitions": "No se detectaron particiones ni subparticiones de índices no utilizables",
            "disabled_constraints": "No se detectaron restricciones deshabilitadas relevantes",
            "disabled_triggers": "No se detectaron disparadores deshabilitados relevantes",
            "stale_table_statistics": "No se detectaron tablas con estadísticas desactualizadas",
            "missing_table_statistics": "No se detectaron tablas relevantes sin estadísticas",
            "locked_table_statistics": "No se detectaron tablas con estadísticas bloqueadas",
            "recyclebin_objects": "No se detectaron objetos en la papelera de reciclaje para esquemas de aplicación",
            "invalid_synonyms": "No se detectaron sinónimos locales apuntando a objetos inexistentes",
            "tables_without_primary_key": "No se detectaron tablas de aplicación sin llave primaria",
            "foreign_keys_without_index": "No se detectaron llaves foráneas habilitadas sin índice compatible",
            "tables_with_long_columns": "No se detectaron columnas LONG ni LONG RAW en tablas de aplicación",
            "indexes_too_many_columns": "No se detectaron índices con cantidad excesiva de columnas",
        }
        return messages.get(str(metric), "No se detectaron hallazgos")

    def _found_message(self, metric: Any, count: int) -> str:
        messages = {
            "disabled_triggers": f"Se detectaron {count} disparador(es) deshabilitado(s)",
            "stale_table_statistics": f"Se detectaron {count} tabla(s) con estadísticas desactualizadas",
            "missing_table_statistics": f"Se detectaron {count} tabla(s) sin estadísticas",
            "locked_table_statistics": f"Se detectaron {count} tabla(s) con estadísticas bloqueadas",
            "invalid_synonyms": f"Se detectaron {count} sinónimo(s) local(es) con destino inexistente",
            "tables_without_primary_key": f"Se detectaron {count} tabla(s) de aplicación sin llave primaria",
            "foreign_keys_without_index": f"Se detectaron {count} llave(s) foránea(s) habilitada(s) sin índice compatible",
            "tables_with_long_columns": f"Se detectaron {count} columna(s) LONG o LONG RAW en tablas de aplicación",
        }
        return messages.get(str(metric), f"Se detectaron {count} hallazgo(s)")
