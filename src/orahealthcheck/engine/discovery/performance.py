"""Descubrimiento y construcción de evidencia del grupo performance.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin


class PerformanceMixin(CommonMixin):
    def _default_performance_inventory(self) -> dict[str, Any]:
        return {
            "instance_uptime": {"startup_time": None, "current_time": None, "uptime_days": None, "uptime_hours": None},
            "active_user_sessions": [],
            "wait_sessions": [],
            "long_operations": [],
            "sysstat": {"parse_total": 0, "parse_hard": 0},
            "library_cache": [],
            "sql_current_activity": [],
        }

    def _discover_performance_inventory(self, connector: Any) -> dict[str, Any]:
        perf = self._default_performance_inventory()
        perf["instance_uptime"] = self._query_one(connector, "uptime actual de instancia", """
            select startup_time,
                   sysdate as current_time,
                   round(sysdate - startup_time, 4) as uptime_days,
                   round((sysdate - startup_time) * 24, 2) as uptime_hours
            from v$instance
        """)
        perf["active_user_sessions"] = self._query_rows(connector, "sesiones de usuario activas actuales", """
            select sid, serial#, username, status, wait_class, event, sql_id, module, machine, program
            from v$session
            where type = 'USER'
              and status = 'ACTIVE'
            order by sid
        """)
        perf["wait_sessions"] = self._query_rows(connector, "esperas no idle actuales por sesión", """
            select sid, serial#, username, status, wait_class, event, seconds_in_wait, state,
                   sql_id, module, machine, program
            from v$session
            where type = 'USER'
              and wait_class is not null
              and wait_class <> 'Idle'
            order by seconds_in_wait desc, sid
        """)
        perf["long_operations"] = self._query_rows(connector, "operaciones largas activas", """
            select sid, serial#, opname, target, sofar, totalwork, units,
                   elapsed_seconds, time_remaining, sql_id
            from v$session_longops
            where time_remaining > 0
            order by time_remaining desc, elapsed_seconds desc
        """)
        stats = self._query_rows(connector, "parse count total/hard", """
            select name, value
            from v$sysstat
            where name in ('parse count (total)', 'parse count (hard)')
        """)
        perf["sysstat"] = {
            "parse_total": next((r.get("value") for r in stats if str(r.get("name", "")).lower() == "parse count (total)"), 0),
            "parse_hard": next((r.get("value") for r in stats if str(r.get("name", "")).lower() == "parse count (hard)"), 0),
        }
        perf["library_cache"] = self._query_rows(connector, "library cache básico", """
            select namespace, gets, gethits, pins, pinhits, reloads, invalidations
            from v$librarycache
            order by namespace
        """)
        perf["sql_current_activity"] = self._query_rows(connector, "SQL actualmente activo", """
            select s.sid, s.serial#, s.username, s.sql_id, s.sql_child_number, s.status,
                   s.wait_class, s.event, s.module, s.machine, s.program,
                   substr(q.sql_text, 1, 200) as sql_text_sample
            from v$session s
            left join v$sql q on q.sql_id = s.sql_id and q.child_number = s.sql_child_number
            where s.type = 'USER'
              and s.status = 'ACTIVE'
              and s.sql_id is not null
            order by s.sid
        """)
        return {"performance": perf}

    def _build_performance_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        perf = database.get("performance") if isinstance(database.get("performance"), dict) else self._default_performance_inventory()
        check_id = check.check_id
        thresholds = {k: v for k, v in check.evaluator.items() if k not in {"type", "metric"} and not k.endswith("_policy")}
        evidence: dict[str, Any] = {
            "metric": check_id,
            "label": check.collector.get("label", check.title),
            "source": check.collector.get("source_view", "inventario performance"),
            "scope_note": "Fotografía actual sin repositorios históricos licenciados; los segundos observados no son DB Time histórico.",
        }
        evidence.update(thresholds)
        max_rows = int(check.evaluator.get("max_rows", check.collector.get("max_rows", 20)) or 20)
        if check_id == "performance_instance_uptime":
            evidence.update(perf.get("instance_uptime") if isinstance(perf.get("instance_uptime"), dict) else {})
            return evidence
        if check_id == "performance_active_user_sessions":
            rows = perf.get("active_user_sessions") if isinstance(perf.get("active_user_sessions"), list) else []
            evidence.update({"active_user_sessions": len(rows), "sample_sessions": rows[:max_rows]})
            return evidence
        if check_id == "performance_wait_class_snapshot":
            rows = self._performance_wait_rows(perf, exclude=check.evaluator.get("exclude_wait_classes", ["Idle"]), max_rows=max_rows)
            evidence.update({"rows": rows, "affected_count": sum(int(r.get("session_count") or 0) for r in rows)})
            return evidence
        if check_id == "performance_current_event_summary":
            rows = self._performance_event_rows(perf, exclude=check.evaluator.get("exclude_wait_classes", ["Idle"]), max_rows=max_rows)
            evidence.update({"rows": rows, "affected_count": sum(int(r.get("session_count") or 0) for r in rows), "future_note": "Thresholds específicos por EVENT pueden agregarse en una fase futura."})
            return evidence
        if check_id == "performance_non_idle_wait_sessions":
            rows = self._filtered_wait_sessions(perf, check.evaluator.get("exclude_wait_classes", ["Idle"]))
            evidence.update({"rows": rows[:max_rows], "affected_count": len(rows), "filters": ["TYPE = 'USER'", "WAIT_CLASS IS NOT NULL", "WAIT_CLASS <> 'Idle'"]})
            return evidence
        if check_id == "performance_long_operations_active":
            rows = perf.get("long_operations") if isinstance(perf.get("long_operations"), list) else []
            max_remaining = max([self._safe_float(r.get("time_remaining")) or 0 for r in rows], default=0)
            evidence.update({"rows": rows[:max_rows], "affected_count": len(rows), "max_time_remaining": max_remaining})
            return evidence
        if check_id == "performance_parse_ratio_basic":
            stats = perf.get("sysstat") if isinstance(perf.get("sysstat"), dict) else {}
            total = self._safe_float(stats.get("parse_total")) or 0
            hard = self._safe_float(stats.get("parse_hard")) or 0
            evidence.update({"parse_total": total, "parse_hard": hard, "hard_parse_pct": round((hard / total) * 100, 2) if total > 0 else None, "interpretation_note": "Métrica acumulada desde startup; interpretar junto con performance_instance_uptime."})
            return evidence
        if check_id == "performance_library_cache_hit_ratio":
            rows = perf.get("library_cache") if isinstance(perf.get("library_cache"), list) else []
            gets = sum(self._safe_float(r.get("gets")) or 0 for r in rows)
            gethits = sum(self._safe_float(r.get("gethits")) or 0 for r in rows)
            pins = sum(self._safe_float(r.get("pins")) or 0 for r in rows)
            pinhits = sum(self._safe_float(r.get("pinhits")) or 0 for r in rows)
            evidence.update({"rows": rows[:max_rows], "gets": gets, "gethits": gethits, "pins": pins, "pinhits": pinhits, "reloads": sum(self._safe_float(r.get("reloads")) or 0 for r in rows), "invalidations": sum(self._safe_float(r.get("invalidations")) or 0 for r in rows), "get_hit_pct": round((gethits / gets) * 100, 2) if gets > 0 else None, "pin_hit_pct": round((pinhits / pins) * 100, 2) if pins > 0 else None})
            return evidence
        if check_id == "performance_sql_current_activity":
            rows = perf.get("sql_current_activity") if isinstance(perf.get("sql_current_activity"), list) else []
            evidence.update({"rows": rows[:max_rows], "affected_count": len(rows), "privacy_note": "SQL_TEXT se trunca a 200 caracteres y no representa top SQL histórico."})
            return evidence
        return evidence

    def _filtered_wait_sessions(self, perf: dict[str, Any], exclude: Any) -> list[dict[str, Any]]:
        rows = perf.get("wait_sessions") if isinstance(perf.get("wait_sessions"), list) else []
        excluded = {str(x) for x in (exclude if isinstance(exclude, list) else ["Idle"])}
        return [r for r in rows if r.get("wait_class") and str(r.get("wait_class")) not in excluded]

    def _performance_wait_rows(self, perf: dict[str, Any], exclude: Any, max_rows: int) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in self._filtered_wait_sessions(perf, exclude):
            grouped.setdefault(str(row.get("wait_class") or "Other"), []).append(row)
        result = []
        for wait_class, rows in grouped.items():
            events: dict[str, int] = {}
            for row in rows:
                events[str(row.get("event") or "UNKNOWN")] = events.get(str(row.get("event") or "UNKNOWN"), 0) + 1
            result.append({"wait_class": wait_class, "session_count": len(rows), "total_observed_wait_seconds": sum(self._safe_float(r.get("seconds_in_wait")) or 0 for r in rows), "max_wait_seconds": max([self._safe_float(r.get("seconds_in_wait")) or 0 for r in rows], default=0), "top_events": [{"event": k, "session_count": v} for k, v in sorted(events.items(), key=lambda i: i[1], reverse=True)[:5]], "sample_sessions": rows[:max_rows]})
        return sorted(result, key=lambda r: (r["session_count"], r["total_observed_wait_seconds"]), reverse=True)

    def _performance_event_rows(self, perf: dict[str, Any], exclude: Any, max_rows: int) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in self._filtered_wait_sessions(perf, exclude):
            grouped.setdefault((str(row.get("wait_class") or "Other"), str(row.get("event") or "UNKNOWN")), []).append(row)
        result = []
        for (wait_class, event), rows in grouped.items():
            result.append({"wait_class": wait_class, "event": event, "session_count": len(rows), "total_observed_wait_seconds": sum(self._safe_float(r.get("seconds_in_wait")) or 0 for r in rows), "max_wait_seconds": max([self._safe_float(r.get("seconds_in_wait")) or 0 for r in rows], default=0), "sample_sql_ids": sorted({str(r.get("sql_id")) for r in rows if r.get("sql_id")})[:max_rows], "sample_modules": sorted({str(r.get("module")) for r in rows if r.get("module")})[:max_rows]})
        return sorted(result, key=lambda r: (r["session_count"], r["total_observed_wait_seconds"]), reverse=True)
