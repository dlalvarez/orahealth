from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from orahealthcheck.models import ResultStatus


class IoRedoArchiveEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia de I/O, redo y archive no tiene una estructura válida"
        metric = evidence.get("metric") or config.get("metric")
        if evidence.get("collection_error"):
            return self._status(config.get("collection_error_status", "INFO")), f"No se pudo recolectar evidencia para {metric}: {evidence.get('collection_error')}"
        handler = getattr(self, f"_{metric}", None)
        if handler is None:
            return ResultStatus.ERROR, f"Métrica de I/O, redo y archive no soportada: {metric}"
        return handler(evidence, config)

    def _archivelog_generation_recent(self, e, c):
        if str(e.get("archivelog_mode", "")).upper() == "NOARCHIVELOG":
            return ResultStatus.SKIPPED, "La base está en NOARCHIVELOG; la generación de archived logs no aplica"
        total = self._num(e.get("total_mb")) or 0
        if total >= float(c.get("fail_archivelog_mb_24h", c.get("fail_mb", 204800))):
            return ResultStatus.FAIL, f"La generación reciente de archived logs es {total} MB y supera el umbral de fallo"
        if total >= float(c.get("warning_archivelog_mb_24h", c.get("warning_mb", 102400))):
            return ResultStatus.WARNING, f"La generación reciente de archived logs es {total} MB y requiere revisión de capacidad"
        return ResultStatus.INFO, "Generación reciente de archived logs recolectada como señal de capacidad"

    def _archive_dest_status(self, e, c):
        if str(e.get("archivelog_mode", "")).upper() == "NOARCHIVELOG":
            return ResultStatus.INFO, "La base está en NOARCHIVELOG; los destinos de archivado se reportan solo como información"
        rows = e.get("rows") or []
        bad = [r for r in rows if self._configured(r) and (str(r.get("valid_now", "")).upper() == "NO" or self._text(r.get("error")))]
        warn = [r for r in rows if self._configured(r) and str(r.get("status", "")).upper() in {"INACTIVE", "DEFERRED", "BAD PARAM"}]
        if bad:
            return ResultStatus.FAIL, f"Se detectaron {len(bad)} destino(s) de archive activos u obligatorios con error o no válidos"
        if warn:
            return ResultStatus.WARNING, f"Se detectaron {len(warn)} destino(s) de archive configurados con estado que requiere revisión"
        return ResultStatus.PASS, "Los destinos de archive configurados no presentan errores visibles"

    def _archive_dest_errors(self, e, c):
        rows = [r for r in (e.get("rows") or []) if self._configured(r) and self._text(r.get("error"))]
        if not rows:
            return ResultStatus.PASS, "No se detectaron errores explícitos en destinos de archive"
        active = [r for r in rows if str(r.get("status", "")).upper() not in {"INACTIVE", "DEFERRED"}]
        if active:
            return ResultStatus.FAIL, f"Se detectaron {len(active)} destino(s) de archive activos con error"
        return ResultStatus.WARNING, f"Se detectaron {len(rows)} destino(s) de archive configurados con error en estado no activo"

    def _fra_usage_advanced(self, e, c):
        if not e.get("fra_configured"):
            return ResultStatus.SKIPPED, e.get("message") or "FRA no está configurada o tiene límite de espacio cero"
        return self._high(e.get("used_pct"), c, "El uso avanzado de FRA")

    def _fra_reclaimable_space(self, e, c):
        if not e.get("fra_configured"):
            return ResultStatus.SKIPPED, e.get("message") or "FRA no está configurada"
        pct = self._num(e.get("reclaimable_pct")) or 0
        if pct >= float(c.get("warning_reclaimable_pct", 50)):
            return ResultStatus.WARNING, f"El espacio recuperable de FRA es {pct}% y sugiere mantenimiento RMAN"
        return ResultStatus.INFO, "Espacio recuperable de FRA recolectado como señal de mantenimiento"

    def _flashback_status(self, e, c):
        required = bool(c.get("required", e.get("required", False)))
        on = str(e.get("flashback_on", "")).upper() in {"YES", "ON"}
        if required and on:
            return ResultStatus.PASS, "Flashback Database está habilitado según el estándar configurado"
        if required:
            return self._status(c.get("missing_status", "WARNING")), "Flashback Database es requerido por el estándar configurado y no está habilitado"
        return ResultStatus.INFO, "Estado de Flashback Database recolectado para inventario"

    def _flashback_log_usage(self, e, c):
        if str(e.get("flashback_on", "")).upper() not in {"YES", "ON"}:
            return ResultStatus.SKIPPED, "Flashback Database no está habilitado; no aplica uso de flashback logs"
        return ResultStatus.INFO, "Uso de flashback logs recolectado para análisis de recuperación"

    def _redo_log_switch_frequency(self, e, c):
        sph = self._num(e.get("switches_per_hour")) or 0
        if sph >= float(c.get("fail_switches_per_hour", 20)):
            return ResultStatus.FAIL, f"La frecuencia de log switches es {sph} por hora y supera el umbral de fallo"
        if sph >= float(c.get("warning_switches_per_hour", 6)):
            return ResultStatus.WARNING, f"La frecuencia de log switches es {sph} por hora y requiere revisión"
        return ResultStatus.INFO, "Frecuencia reciente de log switches dentro del rango informativo configurado"

    def _redo_log_size_assessment(self, e, c):
        min_mb = self._num(e.get("min_redo_mb"))
        threshold = float(c.get("warning_min_redo_mb", 256))
        if min_mb is not None and min_mb < threshold:
            return ResultStatus.WARNING, f"El tamaño mínimo de redo log es {min_mb} MB, menor al umbral {threshold} MB"
        return ResultStatus.INFO, "Tamaños de grupos redo recolectados para evaluación de capacidad"

    def _redo_log_status(self, e, c):
        count = int(e.get("affected_count") or 0)
        if count:
            return ResultStatus.WARNING, f"Se detectaron {count} grupo(s) redo en estado anómalo"
        return ResultStatus.PASS, "No se detectaron grupos redo en estados anómalos"

    def _redo_logfile_status(self, e, c):
        count = int(e.get("affected_count") or 0)
        if count:
            return ResultStatus.WARNING, f"Se detectaron {count} miembro(s) redo con estado problemático"
        return ResultStatus.PASS, "No se detectaron miembros redo inválidos, stale o eliminados"

    def _sysstat_io_basic(self, e, c):
        return ResultStatus.INFO, "Estadísticas acumuladas de I/O recolectadas desde el inicio de instancia"

    def _filestat_io_basic(self, e, c):
        return ResultStatus.INFO, "I/O acumulado por datafile recolectado desde el inicio de instancia"

    def _nologging_objects_basic(self, e, c):
        count = int(e.get("affected_count") or 0)
        if count == 0:
            return ResultStatus.PASS, "No se detectaron objetos de aplicación con NOLOGGING"
        if str(e.get("force_logging", "")).upper() == "YES":
            return ResultStatus.INFO, f"Se detectaron {count} objeto(s) NOLOGGING, mitigados por FORCE LOGGING"
        return ResultStatus.WARNING, f"Se detectaron {count} objeto(s) NOLOGGING sin FORCE LOGGING habilitado"

    def _unrecoverable_datafiles(self, e, c):
        rows = e.get("rows") or []
        if not rows:
            return ResultStatus.PASS, "No se detectaron datafiles con cambios unrecoverable registrados"
        recent = [r for r in rows if r.get("recent")]
        if recent:
            return ResultStatus.FAIL, f"Se detectaron {len(recent)} datafile(s) con cambios unrecoverable recientes"
        return ResultStatus.WARNING, f"Se detectaron {len(rows)} datafile(s) con cambios unrecoverable históricos"

    def _high(self, raw, c, label):
        value = self._num(raw)
        if value is None:
            return ResultStatus.ERROR, f"{label} no se encontró en la evidencia"
        if c.get("critical") is not None and value >= float(c["critical"]):
            return ResultStatus.CRITICAL, f"{label} {value}% alcanzó el umbral crítico {c['critical']}%"
        if c.get("fail") is not None and value >= float(c["fail"]):
            return ResultStatus.FAIL, f"{label} {value}% alcanzó el umbral de fallo {c['fail']}%"
        if c.get("warning") is not None and value >= float(c["warning"]):
            return ResultStatus.WARNING, f"{label} {value}% alcanzó el umbral de advertencia {c['warning']}%"
        return ResultStatus.PASS, f"{label} {value}% está dentro del umbral configurado"

    def _configured(self, row):
        return bool(self._text(row.get("destination")) or self._text(row.get("error")) or str(row.get("status", "")).upper() not in {"INACTIVE", ""})

    def _text(self, v):
        return str(v).strip() if v is not None and str(v).strip() else ""

    def _num(self, v):
        try:
            if v is None or v == "":
                return None
            return float(v)
        except (TypeError, ValueError):
            return None

    def _status(self, v):
        try:
            return ResultStatus(str(v).upper())
        except ValueError:
            return ResultStatus.WARNING
