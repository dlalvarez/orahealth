from typing import Any

from orahealthcheck.models import ResultStatus


class PerformanceEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia de performance no tiene una estructura válida"
        metric = evidence.get("metric") or config.get("metric")
        if evidence.get("collection_error"):
            return ResultStatus.INFO, f"No se pudo recolectar evidencia para {metric}: {evidence.get('collection_error')}"
        if metric == "performance_instance_uptime":
            return self._instance_uptime(evidence, config)
        if metric == "performance_active_user_sessions":
            return self._active_user_sessions(evidence, config)
        if metric == "performance_wait_class_snapshot":
            return self._wait_class_snapshot(evidence, config)
        if metric == "performance_current_event_summary":
            return self._event_summary(evidence)
        if metric == "performance_non_idle_wait_sessions":
            return self._detail_rows(evidence, "sesiones de usuario en esperas no idle actuales")
        if metric == "performance_long_operations_active":
            return self._longops(evidence, config)
        if metric == "performance_parse_ratio_basic":
            return self._parse_ratio(evidence, config)
        if metric == "performance_library_cache_hit_ratio":
            return self._library_cache(evidence, config)
        if metric == "performance_sql_current_activity":
            return self._sql_activity(evidence)
        return ResultStatus.ERROR, f"Métrica de performance no soportada: {metric}"

    def _instance_uptime(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        hours = self._num(e.get("uptime_hours"))
        minimum = self._num(c.get("warning_min_uptime_hours"))
        if hours is not None and minimum is not None and hours < minimum:
            return ResultStatus.WARNING, f"La instancia tiene uptime reciente ({hours} horas), menor al umbral {minimum}; interpretar métricas acumuladas con cautela"
        return ResultStatus.INFO, "Uptime de instancia recolectado para contextualizar métricas acumuladas"

    def _active_user_sessions(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        count = int(self._num(e.get("active_user_sessions")) or 0)
        fail = self._num(c.get("fail")); warning = self._num(c.get("warning"))
        if fail is not None and count >= fail:
            return ResultStatus.FAIL, f"Hay {count} sesiones de usuario activas, alcanzando el umbral de fallo {int(fail)}"
        if warning is not None and count >= warning:
            return ResultStatus.WARNING, f"Hay {count} sesiones de usuario activas, sobre el umbral de advertencia {int(warning)}"
        return ResultStatus.PASS, f"Hay {count} sesiones de usuario activas, dentro del umbral configurado"

    def _wait_class_snapshot(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = e.get("rows") if isinstance(e.get("rows"), list) else []
        if not rows:
            return ResultStatus.PASS, "No se detectaron esperas no idle de sesiones de usuario en la fotografía actual"
        worst = ResultStatus.INFO; messages = []
        for row in rows:
            wc = str(row.get("wait_class") or "Other")
            thresholds = self._thresholds_for_wait_class(wc, c)
            status = self._evaluate_wait_thresholds(row, thresholds)
            if self._rank(status) > self._rank(worst):
                worst = status
            if status in {ResultStatus.WARNING, ResultStatus.FAIL}:
                messages.append(self._wait_message(row, wc))
        if messages:
            return worst, messages[0]
        return ResultStatus.INFO, f"Se observaron esperas no idle actuales en {len(rows)} wait class(es), sin superar thresholds configurados"

    def _event_summary(self, e: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = e.get("rows") if isinstance(e.get("rows"), list) else []
        if not rows:
            return ResultStatus.PASS, "No se detectaron eventos de espera no idle de sesiones de usuario en la fotografía actual"
        return ResultStatus.INFO, f"Resumen actual por WAIT_CLASS/EVENT recolectado con {len(rows)} grupo(s); thresholds por evento quedan para refinamiento futuro"

    def _detail_rows(self, e: dict[str, Any], label: str) -> tuple[ResultStatus, str]:
        count = int(self._num(e.get("affected_count")) or 0)
        if count == 0:
            return ResultStatus.PASS, f"No se detectaron {label}"
        return ResultStatus.INFO, f"Se reportan {count} {label} como evidencia técnica actual"

    def _longops(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        count = int(self._num(e.get("affected_count")) or 0); max_remaining = self._num(e.get("max_time_remaining")) or 0
        if count == 0: return ResultStatus.PASS, "No se detectaron operaciones largas activas con tiempo restante"
        if count >= int(c.get("warning_count", 10)) or max_remaining >= float(c.get("warning_time_remaining_seconds", 3600)):
            return ResultStatus.WARNING, f"Se detectaron {count} operaciones largas activas; máximo time_remaining={max_remaining} segundos"
        return ResultStatus.INFO, f"Se detectaron {count} operaciones largas activas dentro del umbral configurado"

    def _parse_ratio(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        total = self._num(e.get("parse_total")) or 0; pct = self._num(e.get("hard_parse_pct"))
        if total <= 0 or pct is None: return ResultStatus.INFO, "No hay volumen suficiente para calcular hard_parse_pct"
        min_volume = float(c.get("min_parse_total", 1000))
        if total < min_volume: return ResultStatus.INFO, f"Volumen de parse acumulado ({int(total)}) menor al mínimo configurable {int(min_volume)}"
        warning = self._num(c.get("warning_hard_parse_pct"))
        if warning is not None and pct >= warning: return ResultStatus.WARNING, f"Hard parse acumulado desde startup {pct}% supera el umbral {warning}%"
        return ResultStatus.INFO, f"Hard parse acumulado desde startup {pct}% dentro del umbral configurado"

    def _library_cache(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        gets = self._num(e.get("gets")) or 0; pins = self._num(e.get("pins")) or 0
        min_volume = float(c.get("min_volume", 1000))
        if gets < min_volume and pins < min_volume: return ResultStatus.INFO, "Volumen de library cache insuficiente para evaluar ratios con umbral"
        get_pct = self._num(e.get("get_hit_pct")); pin_pct = self._num(e.get("pin_hit_pct"))
        min_get = self._num(c.get("warning_min_get_hit_pct")); min_pin = self._num(c.get("warning_min_pin_hit_pct"))
        if (min_get is not None and get_pct is not None and get_pct < min_get) or (min_pin is not None and pin_pct is not None and pin_pct < min_pin):
            return ResultStatus.WARNING, f"Ratios básicos de library cache bajos (get_hit_pct={get_pct}, pin_hit_pct={pin_pct}) con volumen suficiente"
        return ResultStatus.INFO, "Ratios básicos de library cache recolectados sin advertencias configuradas"

    def _sql_activity(self, e: dict[str, Any]) -> tuple[ResultStatus, str]:
        count = int(self._num(e.get("affected_count")) or 0)
        return (ResultStatus.INFO, f"Se reportan {count} SQL_ID actualmente activos; no equivale a top SQL histórico") if count else (ResultStatus.PASS, "No se detectó SQL de usuario activo con SQL_ID al momento de la recolección")

    def _thresholds_for_wait_class(self, wait_class: str, c: dict[str, Any]) -> dict[str, Any]:
        classes = c.get("classes") if isinstance(c.get("classes"), dict) else {}
        return classes.get(wait_class) if isinstance(classes.get(wait_class), dict) else c.get("default", {})

    def _evaluate_wait_thresholds(self, row: dict[str, Any], t: dict[str, Any]) -> ResultStatus:
        values = {"sessions": self._num(row.get("session_count")) or 0, "total_seconds": self._num(row.get("total_observed_wait_seconds")) or 0, "max_seconds": self._num(row.get("max_wait_seconds")) or 0}
        for level, status in (("fail", ResultStatus.FAIL), ("warning", ResultStatus.WARNING)):
            cfg = t.get(level) if isinstance(t.get(level), dict) else {}
            if any(cfg.get(k) is not None and values[k] >= float(cfg[k]) for k in values):
                return status
        return ResultStatus.INFO

    def _wait_message(self, row: dict[str, Any], wc: str) -> str:
        events = row.get("top_events") if isinstance(row.get("top_events"), list) else []
        top = events[0].get("event") if events and isinstance(events[0], dict) else "sin evento principal"
        return (f"Se detectó concentración actual en wait class {wc}: {row.get('session_count')} sesiones de usuario, "
                f"{row.get('total_observed_wait_seconds')} segundos observados acumulados y máximo de {row.get('max_wait_seconds')} segundos en una sesión. "
                f"Evento principal: {top}. Posible presión actual observada; revisar eventos principales y SQL_ID asociados.")

    def _rank(self, s: ResultStatus) -> int:
        return {ResultStatus.PASS: 0, ResultStatus.INFO: 1, ResultStatus.WARNING: 2, ResultStatus.FAIL: 3, ResultStatus.CRITICAL: 4}.get(s, 0)

    def _num(self, v: Any) -> float | None:
        try:
            if v is None: return None
            if isinstance(v, str):
                v = v.strip().replace(',', '')
                if not v: return None
            return float(v)
        except (TypeError, ValueError):
            return None
