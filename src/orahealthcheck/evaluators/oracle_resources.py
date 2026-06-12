import re
from typing import Any

from orahealthcheck.models import ResultStatus


class OracleResourcesEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia de recursos Oracle no tiene una estructura válida"
        metric = evidence.get("metric") or config.get("metric")
        if evidence.get("collection_error"):
            status = self._configured_status(config.get("collection_error_status", "INFO"))
            return status, f"No se pudo recolectar evidencia para {metric}: {evidence.get('collection_error')}"
        if metric in {"processes_usage_pct", "sessions_usage_pct", "transactions_usage_pct"}:
            return self._resource_limit(evidence, config)
        if metric == "sga_target_configured":
            return self._sga_target(evidence, config)
        if metric == "pga_aggregate_target_configured":
            return self._positive_parameter(evidence, "pga_aggregate_target", config)
        if metric == "pga_aggregate_limit_configured":
            return self._positive_parameter(evidence, "pga_aggregate_limit", config, auto_info=True)
        if metric == "pga_memory_usage_info":
            return self._pga_memory(evidence, config)
        if metric == "sga_memory_info":
            return self._sga_memory(evidence, config)
        if metric == "blocked_sessions_basic":
            return self._blocked_sessions(evidence, config)
        if metric == "blocking_sessions_basic":
            return self._blocking_sessions(evidence, config)
        if metric == "inactive_sessions_high":
            return self._inactive_sessions(evidence, config)
        if metric in {"scheduler_failed_jobs_recent", "scheduler_disabled_jobs", "scheduler_broken_jobs", "legacy_dba_jobs_broken"}:
            return self._row_findings(evidence, config)
        return ResultStatus.ERROR, f"Métrica de recursos Oracle no soportada: {metric}"

    def _resource_limit(self, evidence: dict[str, Any], config: dict[str, Any]) -> tuple[ResultStatus, str]:
        metric = evidence.get("metric")
        name = evidence.get("resource_name") or metric
        if not evidence.get("exists", True):
            return self._configured_status(config.get("missing_status", "INFO")), f"El recurso {name} no está disponible en v$resource_limit para esta instancia"
        if not evidence.get("limit_numeric", False):
            return ResultStatus.INFO, f"El límite de {name} no es numérico ({evidence.get('limit_value')}); se reporta como información sin aplicar umbrales"
        used_pct = self._numeric(evidence.get("used_pct"))
        if used_pct is None:
            return ResultStatus.INFO, f"No se pudo calcular el porcentaje de uso del recurso {name}"
        return self._high_threshold(used_pct, config, f"El uso actual de {name}")

    def _sga_target(self, evidence: dict[str, Any], config: dict[str, Any]) -> tuple[ResultStatus, str]:
        mode = str(evidence.get("management_mode") or "MANUAL")
        sga_target = self._memory_value_bytes(evidence.get("sga_target_bytes", evidence.get("sga_target"))) or 0
        memory_target = self._memory_value_bytes(evidence.get("memory_target_bytes", evidence.get("memory_target"))) or 0
        if memory_target > 0:
            return ResultStatus.PASS, "La memoria Oracle se administra mediante AMM con memory_target configurado"
        if sga_target > 0:
            return ResultStatus.PASS, "SGA está configurada mediante ASMM con sga_target mayor a cero"
        status = self._configured_status(config.get("manual_status", "INFO"))
        return status, f"La instancia opera en modo {mode}; sga_target y memory_target no tienen valor mayor a cero"

    def _positive_parameter(self, evidence: dict[str, Any], parameter: str, config: dict[str, Any], auto_info: bool = False) -> tuple[ResultStatus, str]:
        if not evidence.get("exists", False):
            return self._configured_status(config.get("missing_status", "WARNING")), f"No se encontró el parámetro {parameter} en v$parameter"
        value = self._memory_value_bytes(evidence.get(f"{parameter}_bytes", evidence.get(parameter)))
        if value is not None and value > 0:
            return ResultStatus.PASS, f"El parámetro {parameter} está configurado con valor mayor a cero"
        display = str(evidence.get(f"{parameter}_display", evidence.get(parameter, ""))).lower()
        if auto_info and ("auto" in display or "default" in display):
            return ResultStatus.INFO, f"El parámetro {parameter} parece estar derivado automáticamente"
        return self._configured_status(config.get("zero_status", "WARNING")), f"El parámetro {parameter} está en cero o no se pudo determinar"

    def _pga_memory(self, evidence: dict[str, Any], config: dict[str, Any]) -> tuple[ResultStatus, str]:
        over = self._numeric(evidence.get("over_allocation_count")) or 0
        cache_hit = self._numeric(evidence.get("cache_hit_percentage"))
        min_cache = self._numeric(config.get("warning_cache_hit_percentage_min"))
        if over > 0:
            return ResultStatus.WARNING, f"La PGA registra {int(over)} sobreasignación(es), posible presión de memoria"
        if min_cache is not None and cache_hit is not None and cache_hit < min_cache:
            return ResultStatus.WARNING, f"El cache hit percentage de PGA {cache_hit} está bajo el umbral {min_cache}"
        return ResultStatus.INFO, "Información de uso de PGA recolectada para análisis de capacidad"

    def _sga_memory(self, evidence: dict[str, Any], config: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = evidence.get("rows") if isinstance(evidence.get("rows"), list) else []
        if not rows:
            return self._configured_status(config.get("missing_status", "INFO")), "No se encontraron filas de v$sgainfo para reportar SGA"
        free_pct = self._numeric(evidence.get("free_sga_memory_pct"))
        warning = self._numeric(config.get("warning_free_pct_min")) if config.get("enable_free_pct_warning") is True else None
        if warning is not None and free_pct is not None and free_pct < warning:
            return ResultStatus.WARNING, f"La memoria libre de SGA {free_pct}% está bajo el umbral opcional {warning}%"
        return ResultStatus.INFO, "Información de SGA recolectada para análisis de capacidad"

    def _blocked_sessions(self, evidence: dict[str, Any], config: dict[str, Any]) -> tuple[ResultStatus, str]:
        count = int(self._numeric(evidence.get("affected_count")) or 0)
        max_wait = self._numeric(evidence.get("max_seconds_in_wait")) or 0
        if count == 0:
            return ResultStatus.PASS, "No se detectaron sesiones bloqueadas al momento de la recolección"
        if count >= int(config.get("fail_blocked_count", 10)) or max_wait >= float(config.get("fail_seconds_in_wait", 600)):
            return ResultStatus.FAIL, f"Se detectaron {count} sesión(es) bloqueada(s), con espera máxima de {max_wait} segundos"
        return ResultStatus.WARNING, f"Se detectaron {count} sesión(es) bloqueada(s)"

    def _blocking_sessions(self, evidence: dict[str, Any], config: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = evidence.get("rows") if isinstance(evidence.get("rows"), list) else []
        count = int(evidence.get("affected_count") or len(rows))
        max_blocked = max([int(row.get("blocked_count") or 0) for row in rows], default=0)
        max_wait = max([float(row.get("max_seconds_in_wait") or 0) for row in rows], default=0)
        if count == 0:
            return ResultStatus.PASS, "No se detectaron sesiones bloqueadoras al momento de la recolección"
        if max_blocked >= int(config.get("fail_blocked_count", 10)) or max_wait >= float(config.get("fail_seconds_in_wait", 600)):
            return ResultStatus.FAIL, f"Se detectaron {count} sesión(es) bloqueadora(s) con impacto elevado"
        return ResultStatus.WARNING, f"Se detectaron {count} sesión(es) bloqueadora(s)"

    def _inactive_sessions(self, evidence: dict[str, Any], config: dict[str, Any]) -> tuple[ResultStatus, str]:
        total = int(self._numeric(evidence.get("total_inactive_sessions")) or 0)
        fail = int(config.get("fail_inactive_sessions", 300))
        warning = int(config.get("warning_inactive_sessions", 100))
        if total >= fail:
            return ResultStatus.FAIL, f"Se detectaron {total} sesiones inactivas, sobre el umbral de fallo {fail}"
        if total >= warning:
            return ResultStatus.WARNING, f"Se detectaron {total} sesiones inactivas, sobre el umbral de advertencia {warning}"
        return self._configured_status(config.get("ok_status", "INFO")), f"Se detectaron {total} sesiones inactivas, dentro del umbral configurado"

    def _row_findings(self, evidence: dict[str, Any], config: dict[str, Any]) -> tuple[ResultStatus, str]:
        count = int(self._numeric(evidence.get("affected_count")) or 0)
        if count == 0:
            return ResultStatus.PASS, "No se detectaron hallazgos para este control"
        fail = config.get("fail")
        if fail is not None and count >= int(fail):
            return ResultStatus.FAIL, f"Se detectaron {count} hallazgo(s), alcanzando el umbral de fallo {fail}"
        return self._configured_status(config.get("status_when_found", "WARNING")), f"Se detectaron {count} hallazgo(s) para revisión"

    def _high_threshold(self, value: float, config: dict[str, Any], label: str) -> tuple[ResultStatus, str]:
        if config.get("critical") is not None and value >= float(config["critical"]):
            return ResultStatus.CRITICAL, f"{label} {value}% alcanzó el umbral crítico {config['critical']}%"
        if config.get("fail") is not None and value >= float(config["fail"]):
            return ResultStatus.FAIL, f"{label} {value}% alcanzó el umbral de fallo {config['fail']}%"
        if config.get("warning") is not None and value >= float(config["warning"]):
            return ResultStatus.WARNING, f"{label} {value}% alcanzó el umbral de advertencia {config['warning']}%"
        return ResultStatus.PASS, f"{label} {value}% está dentro del umbral configurado"


    def _memory_value_bytes(self, raw_value: Any) -> float | None:
        if raw_value is None:
            return None
        if isinstance(raw_value, (int, float)):
            return float(raw_value)
        text = str(raw_value).strip()
        if not text:
            return None
        normalized = text.replace(",", "").replace(" ", "")
        match = re.fullmatch(r"(?i)([+-]?\d+(?:\.\d+)?)([kmgtp]?b?)?", normalized)
        if not match:
            return None
        value = float(match.group(1))
        unit = (match.group(2) or "").upper()
        factors = {
            "": 1,
            "B": 1,
            "K": 1024,
            "KB": 1024,
            "M": 1024 ** 2,
            "MB": 1024 ** 2,
            "G": 1024 ** 3,
            "GB": 1024 ** 3,
            "T": 1024 ** 4,
            "TB": 1024 ** 4,
            "P": 1024 ** 5,
            "PB": 1024 ** 5,
        }
        return value * factors.get(unit, 1)

    def _numeric(self, raw_value: Any) -> float | None:
        try:
            if raw_value is None:
                return None
            if isinstance(raw_value, str):
                cleaned = raw_value.strip().replace(",", "")
                if not cleaned:
                    return None
                return float(cleaned)
            return float(raw_value)
        except (TypeError, ValueError):
            return None

    def _configured_status(self, value: Any) -> ResultStatus:
        try:
            return ResultStatus(str(value).upper())
        except ValueError:
            return ResultStatus.WARNING
