import re
from typing import Any

from orahealthcheck.models import ResultStatus


class DataGuardEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia Data Guard no tiene una estructura válida"
        metric = evidence.get("metric") or config.get("metric")
        if evidence.get("collection_error"):
            return ResultStatus.INFO, f"No se pudo consultar evidencia Data Guard completa para {metric}: {evidence.get('collection_error')}"
        if metric == "dataguard_configuration_detected":
            return (ResultStatus.INFO, "Se detectaron señales locales de configuración con bases standby") if evidence.get("standby_detected") else (ResultStatus.SKIPPED, "No se detectaron señales locales de configuración con bases standby")
        if metric == "dataguard_database_role":
            role = evidence.get("database_role") or "desconocido"
            return ResultStatus.INFO, f"Rol actual de la base en configuración con standby: {role}"
        if metric == "dataguard_archive_dest_status":
            rows = self._rows(evidence)
            if not rows:
                return ResultStatus.INFO, "No se observaron destinos remotos de standby comparables desde la evidencia disponible"
            errors = [r for r in rows if str(r.get("error") or "").strip() or str(r.get("status") or "").upper() == "ERROR"]
            if errors:
                mandatory = [r for r in errors if "MANDATORY" in str(r.get("binding") or r.get("destination") or "").upper()]
                return (ResultStatus.CRITICAL if mandatory else ResultStatus.FAIL), f"Se detectaron {len(errors)} destinos Data Guard con error"
            weak = [r for r in rows if str(r.get("status") or "").upper() in {"DEFERRED", "INACTIVE", "BAD PARAM"} or str(r.get("valid_now") or "").upper() in {"NO", "UNKNOWN"}]
            if weak:
                return ResultStatus.WARNING, f"Se detectaron {len(weak)} destinos standby diferidos, inactivos o sin validez confirmada"
            return ResultStatus.PASS, f"Los {len(rows)} destinos standby observados están habilitados y sin error"
        if metric in {"dataguard_transport_lag_basic", "dataguard_apply_lag_basic"}:
            return self._lag(evidence, config, "transport" if "transport" in metric else "apply")
        if metric == "dataguard_archive_gap_basic":
            rows = self._rows(evidence)
            return (ResultStatus.FAIL, f"Se detectaron {len(rows)} gaps de archived logs") if rows else (ResultStatus.PASS, "No se observaron gaps de archived logs en V$ARCHIVE_GAP")
        if metric == "dataguard_standby_redo_logs_basic":
            srl = self._num(evidence.get("standby_redo_groups")) or 0
            if srl <= 0:
                return ResultStatus.WARNING, "No se detectaron standby redo logs en una configuración con bases standby"
            online_mb = self._num(evidence.get("online_redo_max_mb"))
            standby_mb = self._num(evidence.get("standby_redo_min_mb"))
            if online_mb and standby_mb and standby_mb < online_mb:
                return ResultStatus.WARNING, "El tamaño mínimo de standby redo logs es menor que el máximo de online redo logs"
            return ResultStatus.PASS, f"Se detectaron {int(srl)} grupos de standby redo logs"
        if metric == "dataguard_parameters_basic":
            warnings = evidence.get("warnings") if isinstance(evidence.get("warnings"), list) else []
            if warnings:
                return ResultStatus.WARNING, f"Se detectaron {len(warnings)} recomendaciones de parámetros Data Guard básicos"
            return ResultStatus.PASS, "Los parámetros básicos Data Guard observados son coherentes"
        if metric == "dataguard_broker_configuration_basic":
            start = str(evidence.get("dg_broker_start") or "").upper()
            rows = self._rows(evidence)
            if start in {"TRUE", "ON", "1"} and rows:
                return ResultStatus.INFO, "Broker Data Guard habilitado con configuración visible desde SQL"
            if start in {"TRUE", "ON", "1"} and evidence.get("broker_config_available") is False:
                return ResultStatus.WARNING, "dg_broker_start está habilitado pero no hay configuración Broker visible desde SQL"
            if rows:
                return ResultStatus.INFO, "Se observó evidencia SQL de Broker Data Guard"
            return ResultStatus.INFO, "Broker Data Guard no habilitado o sin evidencia SQL visible; no es fallo automático"
        if metric == "dataguard_broker_status_basic":
            if not evidence.get("broker_available"):
                return ResultStatus.SKIPPED, "Broker Data Guard no disponible o no habilitado desde la evidencia SQL"
            status = self._problem_status_from_rows(self._rows(evidence))
            if status:
                return status[0], f"Broker Data Guard reporta mensajes problemáticos: {status[1]}"
            return ResultStatus.PASS, "Broker Data Guard disponible sin errores visibles en la evidencia SQL"
        if metric == "dataguard_fsfo_status_basic":
            if not evidence.get("broker_available"):
                return ResultStatus.SKIPPED, "Broker Data Guard no disponible para evaluar FSFO"
            props = evidence.get("properties") if isinstance(evidence.get("properties"), dict) else {}
            enabled = str(props.get("faststartfailover") or props.get("FastStartFailover") or "").upper() in {"TRUE", "YES", "ENABLED", "ON"}
            if not enabled:
                return ResultStatus.INFO, "FSFO no está habilitado o no aplica; no es fallo automático"
            missing = [k for k in ("faststartfailovertarget", "faststartfailoverthreshold") if not props.get(k)]
            if missing:
                return ResultStatus.FAIL, "FSFO está habilitado pero faltan propiedades mínimas visibles"
            return ResultStatus.PASS, "FSFO habilitado con propiedades mínimas visibles"
        if metric == "dataguard_observer_status_basic":
            if not evidence.get("fsfo_enabled"):
                return ResultStatus.INFO, "Observer no aplica porque FSFO no está habilitado en la evidencia"
            if evidence.get("observer_visible"):
                return ResultStatus.PASS, "Observer visible para FSFO desde la evidencia SQL"
            return ResultStatus.WARNING, "FSFO está habilitado pero no se observó observer activo o visible"
        if metric == "dataguard_managed_standby_processes":
            role = str(evidence.get("database_role") or "").upper()
            rows = self._rows(evidence)
            procs = {str(r.get("process") or "").upper() for r in rows}
            if role == "PHYSICAL STANDBY":
                has_mrp = any(p.startswith("MRP") for p in procs)
                has_rfs = any(p.startswith("RFS") for p in procs)
                if has_mrp and has_rfs:
                    return ResultStatus.PASS, "Procesos MRP y RFS visibles en physical standby"
                return ResultStatus.WARNING, "Physical standby sin procesos MRP/RFS completos visibles"
            if role == "PRIMARY":
                return (ResultStatus.PASS, "Procesos de transporte Data Guard visibles en primary") if rows else (ResultStatus.INFO, "Sin procesos gestionados visibles en primary; evidencia insuficiente")
            return ResultStatus.INFO, f"Procesos Data Guard reportados de forma informativa para rol {role or 'desconocido'}"
        if metric == "dataguard_switchover_readiness_basic":
            sw = str(evidence.get("switchover_status") or "").upper()
            if sw in {"TO STANDBY", "TO PRIMARY", "SESSIONS ACTIVE"} and not evidence.get("archive_gaps"):
                return ResultStatus.PASS, f"Switchover status favorable o revisable: {sw}"
            if sw in {"NOT ALLOWED", "RECOVERY NEEDED"}:
                return ResultStatus.FAIL, f"Switchover status no favorable: {sw}"
            if sw:
                return ResultStatus.WARNING, f"Switchover status requiere revisión: {sw}"
            return ResultStatus.INFO, "Evidencia insuficiente para evaluar readiness de switchover"
        if metric == "dataguard_protection_consistency":
            mode = str(evidence.get("protection_mode") or "").upper()
            level = str(evidence.get("protection_level") or "").upper()
            if not mode or not level:
                return ResultStatus.INFO, "Evidencia insuficiente de modo o nivel de protección"
            if mode == "MAXIMUM PERFORMANCE":
                return ResultStatus.PASS, "Modo Maximum Performance observado sin penalización por sí solo"
            if mode and level and mode != level:
                return ResultStatus.WARNING, f"Nivel efectivo {level} menor o distinto al modo configurado {mode}"
            return ResultStatus.PASS, "Modo y nivel de protección Data Guard coherentes"
        if metric == "dataguard_redo_transport_services_basic":
            return self.evaluate({**evidence, "metric": "dataguard_archive_dest_status"}, {"metric": "dataguard_archive_dest_status"})
        return ResultStatus.ERROR, f"Métrica Data Guard no soportada: {metric}"

    def _lag(self, e: dict[str, Any], c: dict[str, Any], kind: str) -> tuple[ResultStatus, str]:
        seconds = e.get("lag_seconds")
        if seconds is None:
            seconds = self.parse_lag_seconds(e.get("value"))
        if seconds is None:
            return ResultStatus.INFO, f"No fue posible interpretar el {kind} lag desde la evidencia disponible"
        seconds = float(seconds)
        status = self._status_for_high(seconds, c, f"{kind}_lag_warning_seconds", f"{kind}_lag_fail_seconds", f"{kind}_lag_critical_seconds")
        return status, f"{kind.capitalize()} lag observado: {int(seconds)} segundos"

    @staticmethod
    def parse_lag_seconds(value: Any) -> int | None:
        if value is None:
            return None
        text = str(value).strip()
        m = re.match(r"^\+?(?:(\d+)\s+)?(\d{1,2}):(\d{2}):(\d{2})$", text)
        if not m:
            return None
        days = int(m.group(1) or 0)
        return days * 86400 + int(m.group(2)) * 3600 + int(m.group(3)) * 60 + int(m.group(4))

    def _status_for_high(self, value: float, c: dict[str, Any], warn_key: str, fail_key: str, crit_key: str) -> ResultStatus:
        crit = self._num(c.get(crit_key)); fail = self._num(c.get(fail_key)); warn = self._num(c.get(warn_key))
        if crit is not None and value >= crit: return ResultStatus.CRITICAL
        if fail is not None and value >= fail: return ResultStatus.FAIL
        if warn is not None and value >= warn: return ResultStatus.WARNING
        return ResultStatus.PASS

    def _rows(self, e: dict[str, Any]) -> list[dict[str, Any]]:
        return e.get("rows") if isinstance(e.get("rows"), list) else []

    def _num(self, v: Any) -> float | None:
        try:
            if v is None: return None
            return float(str(v).strip().replace(',', ''))
        except (TypeError, ValueError):
            return None

    def _problem_status_from_rows(self, rows: list[dict[str, Any]]) -> tuple[ResultStatus, int] | None:
        texts = " ".join(str(v).upper() for r in rows for v in r.values())
        if any(t in texts for t in ("FATAL", "CRITICAL", "ORA-16795", "ORA-16810")):
            return ResultStatus.CRITICAL, len(rows)
        if "ERROR" in texts or "ORA-" in texts:
            return ResultStatus.FAIL, len(rows)
        if "WARNING" in texts or "WARN" in texts:
            return ResultStatus.WARNING, len(rows)
        return None
