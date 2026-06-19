from typing import Any

from orahealthcheck.models import ResultStatus


class CapacityEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia de capacidad no tiene una estructura válida"
        metric = evidence.get("metric") or config.get("metric")
        if evidence.get("collection_error"):
            return ResultStatus.INFO, f"No se pudo recolectar evidencia completa para {metric}: {evidence.get('collection_error')}"
        if metric == "capacity_database_size_snapshot":
            return ResultStatus.INFO, "Fotografía actual de tamaño de base de datos recolectada sin histórico interno"
        if metric == "capacity_segments_top_size":
            return self._segments(evidence, config)
        if metric == "capacity_fra_archive_headroom" and evidence.get("fra_configured") is False:
            return ResultStatus.SKIPPED, "FRA no configurada; no se considera incumplimiento por defecto para esta fotografía de capacidad"
        if metric == "capacity_resource_limits_headroom":
            return self._resource_limits(evidence, config)
        if metric in {"capacity_tablespace_headroom", "capacity_datafile_headroom"}:
            return self._margen(evidence, config)
        if metric in {"capacity_temp_capacity_snapshot", "capacity_undo_capacity_snapshot", "capacity_fra_archive_headroom"}:
            return self._usage(evidence, config)
        return ResultStatus.ERROR, f"Métrica de capacidad no soportada: {metric}"

    def _margen(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = e.get("rows") if isinstance(e.get("rows"), list) else []
        if not rows:
            return ResultStatus.INFO, "No hay filas suficientes para calcular margen; revisar permisos del diccionario Oracle"
        worst = min((self._num(r.get("headroom_pct")) for r in rows if self._num(r.get("headroom_pct")) is not None), default=None)
        if worst is None:
            return ResultStatus.INFO, "Margen reportado sin porcentaje comparable por límites ilimitados o indeterminados"
        status = self._status_for_low_pct(worst, c, "critical_pct", "fail_pct", "warning_pct")
        label = e.get("label") or "capacidad"
        if status == ResultStatus.PASS:
            return status, f"{label}: margen mínimo {worst}% dentro de umbrales configurados"
        return status, f"{label}: margen mínimo {worst}% bajo umbrales configurados; revisar filas con mayor riesgo"

    def _usage(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = e.get("rows") if isinstance(e.get("rows"), list) else []
        values = [self._num(r.get("used_pct")) for r in rows if self._num(r.get("used_pct")) is not None]
        if e.get("used_pct") is not None:
            values.append(self._num(e.get("used_pct")))
        if not values:
            return ResultStatus.INFO, e.get("limitation") or "Fotografía recolectada sin porcentaje de uso disponible; no se genera fallo automático"
        worst = max(v for v in values if v is not None)
        status = self._status_for_high_pct(worst, c)
        if status == ResultStatus.PASS:
            return status, f"Uso máximo actual {worst}% dentro de umbrales configurados"
        return status, f"Uso máximo actual {worst}% supera umbrales configurados de capacidad"

    def _resource_limits(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = e.get("rows") if isinstance(e.get("rows"), list) else []
        values = [self._num(r.get("used_pct")) for r in rows if self._num(r.get("used_pct")) is not None]
        if not values:
            return ResultStatus.INFO, "No hay límites numéricos comparables para sessions/processes/transactions"
        worst = max(values)
        worst_row = max(rows, key=lambda r: self._num(r.get("used_pct")) or -1)
        status = self._status_for_high_pct(worst, c)
        name = worst_row.get("resource_name", "recurso")
        if status == ResultStatus.PASS:
            return status, f"Margen de límites de recursos dentro de umbrales; peor recurso {name} con {worst}% usado"
        return status, f"El recurso {name} alcanza {worst}% del límite; revisar margen consolidado"

    def _segments(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = e.get("rows") if isinstance(e.get("rows"), list) else []
        if not rows:
            return ResultStatus.INFO, "No se detectaron segmentos de aplicación o no hubo permisos para DBA_SEGMENTS"
        max_mb = max((self._num(r.get("size_mb")) or 0 for r in rows), default=0)
        fail = self._num(c.get("segment_large_fail_mb")); warn = self._num(c.get("segment_large_warning_mb"))
        if fail is not None and max_mb >= fail:
            return ResultStatus.FAIL, f"El segmento más grande reportado alcanza {max_mb} MB"
        if warn is not None and max_mb >= warn:
            return ResultStatus.WARNING, f"El segmento más grande reportado alcanza {max_mb} MB"
        return ResultStatus.INFO, f"Se reportan {len(rows)} segmentos principales de aplicación como evidencia de capacidad"

    def _status_for_high_pct(self, value: float, c: dict[str, Any]) -> ResultStatus:
        crit = self._num(c.get("critical_pct", self._first_suffix(c, "critical_pct"))); fail = self._num(c.get("fail_pct", self._first_suffix(c, "fail_pct"))); warn = self._num(c.get("warning_pct", self._first_suffix(c, "warning_pct")))
        if crit is not None and value >= crit: return ResultStatus.CRITICAL
        if fail is not None and value >= fail: return ResultStatus.FAIL
        if warn is not None and value >= warn: return ResultStatus.WARNING
        return ResultStatus.PASS

    def _status_for_low_pct(self, value: float, c: dict[str, Any], crit_key: str, fail_key: str, warn_key: str) -> ResultStatus:
        crit = self._num(c.get(crit_key, self._first_suffix(c, crit_key))); fail = self._num(c.get(fail_key, self._first_suffix(c, fail_key))); warn = self._num(c.get(warn_key, self._first_suffix(c, warn_key)))
        if crit is not None and value <= crit: return ResultStatus.CRITICAL
        if fail is not None and value <= fail: return ResultStatus.FAIL
        if warn is not None and value <= warn: return ResultStatus.WARNING
        return ResultStatus.PASS

    def _first_suffix(self, c: dict[str, Any], suffix: str) -> Any:
        for key, value in c.items():
            if str(key).endswith(suffix):
                return value
        return None

    def _num(self, v: Any) -> float | None:
        try:
            if v is None: return None
            if isinstance(v, str):
                v = v.strip().replace(',', '')
                if not v or v.upper() in {"UNLIMITED", "UNKNOWN"}: return None
            return float(v)
        except (TypeError, ValueError):
            return None
