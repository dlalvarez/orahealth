"""Descubrimiento y construcción de evidencia del grupo oracle_resources.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin


class OracleResourcesMixin(CommonMixin):
    def _default_oracle_resources_inventory(self, parameters: dict[str, Any] | None = None, healthy_defaults: bool = False) -> dict[str, Any]:
        parameters = parameters if isinstance(parameters, dict) else {}

        def parameter_data(name: str) -> dict[str, Any]:
            data = parameters.get(name.lower(), {}) if isinstance(parameters, dict) else {}
            return data if isinstance(data, dict) else {}

        def parameter_value(name: str) -> Any:
            data = parameter_data(name)
            value = data.get("value")
            if value is None:
                value = data.get("display_value")
            if value is None and healthy_defaults:
                defaults = {
                    "sga_target": 2147483648,
                    "sga_max_size": 2147483648,
                    "memory_target": 0,
                    "memory_max_target": 0,
                    "pga_aggregate_target": 536870912,
                    "pga_aggregate_limit": 2147483648,
                }
                return defaults.get(name)
            return value

        def parameter_display(name: str) -> Any:
            data = parameter_data(name)
            display = data.get("display_value")
            if display is None:
                display = data.get("value")
            if display is None:
                display = parameter_value(name)
            return display

        def memory_parameter(name: str) -> dict[str, Any]:
            value = parameter_value(name)
            display = parameter_display(name)
            normalized_bytes = self._parse_memory_value_bytes(value)
            if normalized_bytes is None:
                normalized_bytes = self._parse_memory_value_bytes(display)
            return {
                name: display,
                f"{name}_value": value,
                f"{name}_bytes": normalized_bytes,
                f"{name}_mb": round(normalized_bytes / 1024 / 1024, 2) if normalized_bytes is not None else None,
            }

        memory_parameters: dict[str, Any] = {}
        for memory_name in (
            "sga_target",
            "sga_max_size",
            "memory_target",
            "memory_max_target",
            "pga_aggregate_target",
            "pga_aggregate_limit",
        ):
            memory_parameters.update(memory_parameter(memory_name))

        return {
            "resource_limits": [
                {"resource_name": "processes", "current_utilization": 50, "max_utilization": 80, "limit_value": 500},
                {"resource_name": "sessions", "current_utilization": 70, "max_utilization": 100, "limit_value": 776},
                {"resource_name": "transactions", "current_utilization": 10, "max_utilization": 20, "limit_value": 854},
            ] if healthy_defaults else [],
            "memory": {
                "parameters": memory_parameters,
                "pga_stats": [
                    {"name": "aggregate PGA target parameter", "value": 536870912, "unit": "bytes"},
                    {"name": "aggregate PGA auto target", "value": 402653184, "unit": "bytes"},
                    {"name": "total PGA allocated", "value": 268435456, "unit": "bytes"},
                    {"name": "total PGA inuse", "value": 134217728, "unit": "bytes"},
                    {"name": "maximum PGA allocated", "value": 402653184, "unit": "bytes"},
                    {"name": "over allocation count", "value": 0, "unit": "count"},
                    {"name": "cache hit percentage", "value": 95, "unit": "percent"},
                ] if healthy_defaults else [],
                "sga_info": [
                    {"name": "Buffer Cache Size", "bytes": 1073741824, "mb": 1024, "resizeable": "Yes"},
                    {"name": "Shared Pool Size", "bytes": 536870912, "mb": 512, "resizeable": "Yes"},
                    {"name": "Large Pool Size", "bytes": 134217728, "mb": 128, "resizeable": "Yes"},
                    {"name": "Java Pool Size", "bytes": 67108864, "mb": 64, "resizeable": "Yes"},
                    {"name": "Streams Pool Size", "bytes": 67108864, "mb": 64, "resizeable": "Yes"},
                    {"name": "Granule Size", "bytes": 16777216, "mb": 16, "resizeable": "No"},
                    {"name": "Maximum SGA Size", "bytes": 2147483648, "mb": 2048, "resizeable": "No"},
                    {"name": "Free SGA Memory Available", "bytes": 268435456, "mb": 256, "resizeable": "No"},
                ] if healthy_defaults else [],
            },
            "sessions": {"blocked_sessions": [], "blocking_sessions": [], "inactive_sessions": []},
            "scheduler_jobs": {"failed_recent": [], "disabled": [], "broken": []},
            "legacy_jobs": {"broken": []},
        }

    def _discover_oracle_resources_inventory(self, connector: Any, parameters: dict[str, Any]) -> dict[str, Any]:
        resources = self._default_oracle_resources_inventory(parameters)
        resources["resource_limits"] = self._query_rows(connector, "límites de recursos Oracle", """
            select resource_name, current_utilization, max_utilization, limit_value
            from v$resource_limit
            where resource_name in ('processes', 'sessions', 'transactions')
            order by resource_name
        """)
        pga_stats = self._query_rows(connector, "estadísticas básicas de PGA", """
            select name, value, unit
            from v$pgastat
            where name in (
              'aggregate PGA target parameter',
              'aggregate PGA auto target',
              'total PGA allocated',
              'total PGA inuse',
              'maximum PGA allocated',
              'over allocation count',
              'cache hit percentage'
            )
        """)
        resources["memory"]["pga_stats"] = pga_stats
        resources["memory"]["sga_info"] = self._query_rows(connector, "información básica de SGA", """
            select name, bytes, round(bytes / 1024 / 1024, 2) as mb, resizeable
            from v$sgainfo
            where name in (
              'Buffer Cache Size',
              'Shared Pool Size',
              'Large Pool Size',
              'Java Pool Size',
              'Streams Pool Size',
              'Granule Size',
              'Maximum SGA Size',
              'Free SGA Memory Available'
            )
            order by name
        """)
        resources["sessions"]["blocked_sessions"] = self._query_rows(connector, "sesiones bloqueadas actuales", """
            select sid, serial#, username, status, event, wait_class, seconds_in_wait,
                   blocking_session, blocking_instance, machine, program, module
            from v$session
            where blocking_session is not null
              and type <> 'BACKGROUND'
            order by seconds_in_wait desc, sid
        """)
        resources["sessions"]["blocking_sessions"] = self._query_rows(connector, "sesiones bloqueadoras actuales", """
            select b.sid as blocker_sid, b.serial# as blocker_serial, b.username as blocker_username,
                   b.status as blocker_status, b.machine, b.program, b.module,
                   count(w.sid) as blocked_count, max(w.seconds_in_wait) as max_seconds_in_wait
            from v$session w
            left join v$session b on b.sid = w.blocking_session
            where w.blocking_session is not null
              and w.type <> 'BACKGROUND'
            group by b.sid, b.serial#, b.username, b.status, b.machine, b.program, b.module
            order by blocked_count desc, max_seconds_in_wait desc
        """)
        resources["sessions"]["inactive_sessions"] = self._query_schema_rows(connector, "sesiones inactivas de aplicación", """
            select s.username, s.machine, s.program, count(*) as inactive_sessions, u.oracle_maintained
            from v$session s
            left join dba_users u on u.username = s.username
            where s.status = 'INACTIVE'
              and s.type <> 'BACKGROUND'
              and s.username is not null
              and nvl(u.oracle_maintained, 'N') = 'N'
            group by s.username, s.machine, s.program, u.oracle_maintained
            order by inactive_sessions desc, s.username, s.machine, s.program
        """, """
            select s.username, s.machine, s.program, count(*) as inactive_sessions, null as oracle_maintained
            from v$session s
            where s.status = 'INACTIVE'
              and s.type <> 'BACKGROUND'
              and s.username is not null
              and s.username not in ({internal_schemas})
            group by s.username, s.machine, s.program
            order by inactive_sessions desc, s.username, s.machine, s.program
        """)
        resources["scheduler_jobs"]["failed_recent"] = self._query_schema_rows(connector, "jobs scheduler fallidos recientes", """
            select r.owner, r.job_name, r.status, r.actual_start_date, r.run_duration, r.error#,
                   substr(r.additional_info, 1, 500) as additional_info, u.oracle_maintained
            from dba_scheduler_job_run_details r
            left join dba_users u on u.username = r.owner
            where r.actual_start_date >= systimestamp - interval '7' day
              and r.status in ('FAILED', 'STOPPED', 'BROKEN')
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by r.actual_start_date desc
        """, """
            select r.owner, r.job_name, r.status, r.actual_start_date, r.run_duration, r.error#,
                   substr(r.additional_info, 1, 500) as additional_info, null as oracle_maintained
            from dba_scheduler_job_run_details r
            where r.actual_start_date >= systimestamp - interval '7' day
              and r.status in ('FAILED', 'STOPPED', 'BROKEN')
              and r.owner not in ({internal_schemas})
            order by r.actual_start_date desc
        """)
        resources["scheduler_jobs"]["disabled"] = self._query_schema_rows(connector, "jobs scheduler deshabilitados", """
            select j.owner, j.job_name, j.job_type, j.enabled, j.state, j.schedule_type,
                   j.repeat_interval, j.last_start_date, j.next_run_date, u.oracle_maintained
            from dba_scheduler_jobs j
            left join dba_users u on u.username = j.owner
            where j.enabled = 'FALSE'
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by j.owner, j.job_name
        """, """
            select j.owner, j.job_name, j.job_type, j.enabled, j.state, j.schedule_type,
                   j.repeat_interval, j.last_start_date, j.next_run_date, null as oracle_maintained
            from dba_scheduler_jobs j
            where j.enabled = 'FALSE'
              and j.owner not in ({internal_schemas})
            order by j.owner, j.job_name
        """)
        resources["scheduler_jobs"]["broken"] = self._query_schema_rows(connector, "jobs scheduler en estado problemático", """
            select j.owner, j.job_name, j.state, j.failure_count, j.retry_count,
                   j.last_start_date, j.next_run_date, u.oracle_maintained
            from dba_scheduler_jobs j
            left join dba_users u on u.username = j.owner
            where j.state in ('BROKEN', 'FAILED', 'RETRY SCHEDULED', 'CHAIN_STALLED')
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by j.owner, j.job_name
        """, """
            select j.owner, j.job_name, j.state, j.failure_count, j.retry_count,
                   j.last_start_date, j.next_run_date, null as oracle_maintained
            from dba_scheduler_jobs j
            where j.state in ('BROKEN', 'FAILED', 'RETRY SCHEDULED', 'CHAIN_STALLED')
              and j.owner not in ({internal_schemas})
            order by j.owner, j.job_name
        """)
        resources["legacy_jobs"]["broken"] = self._query_schema_rows(connector, "jobs legacy DBMS_JOB rotos", """
            select j.schema_user, j.job, j.broken, j.failures, j.last_date, j.next_date,
                   substr(j.what, 1, 500) as what, u.oracle_maintained
            from dba_jobs j
            left join dba_users u on u.username = j.schema_user
            where j.broken = 'Y'
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by j.schema_user, j.job
        """, """
            select j.schema_user, j.job, j.broken, j.failures, j.last_date, j.next_date,
                   substr(j.what, 1, 500) as what, null as oracle_maintained
            from dba_jobs j
            where j.broken = 'Y'
              and j.schema_user not in ({internal_schemas})
            order by j.schema_user, j.job
        """)
        return {"oracle_resources": resources}

    def _build_oracle_resources_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        resources = database.get("oracle_resources") if isinstance(database.get("oracle_resources"), dict) else self._default_oracle_resources_inventory(database.get("parameters", {}))
        check_id = check.check_id
        thresholds = {k: v for k, v in check.evaluator.items() if k not in {"type"}}
        evidence: dict[str, Any] = {"metric": check_id, "label": check.collector.get("label", check.title), "source": check.collector.get("source_view", "inventario de recursos Oracle")}
        evidence.update(thresholds)
        if check_id in {"processes_usage_pct", "sessions_usage_pct", "transactions_usage_pct"}:
            resource_name = check.collector.get("resource_name", check_id.replace("_usage_pct", ""))
            rows = resources.get("resource_limits") or []
            row = next((item for item in rows if str(item.get("resource_name", "")).lower() == resource_name), None)
            evidence.update({"resource_name": resource_name, "exists": bool(row)})
            if row:
                limit_value = row.get("limit_value")
                limit_numeric = self._safe_float(limit_value)
                current = self._safe_float(row.get("current_utilization"))
                used_pct = round((current / limit_numeric) * 100, 2) if current is not None and limit_numeric and limit_numeric > 0 else None
                evidence.update({
                    "current_utilization": row.get("current_utilization"),
                    "max_utilization": row.get("max_utilization"),
                    "limit_value": limit_value,
                    "limit_numeric": limit_numeric is not None and limit_numeric > 0,
                    "used_pct": used_pct,
                })
            return evidence
        memory = resources.get("memory") if isinstance(resources.get("memory"), dict) else {}
        params = memory.get("parameters") if isinstance(memory.get("parameters"), dict) else {}
        if check_id == "sga_target_configured":
            sga_target_bytes = self._parse_memory_value_bytes(params.get("sga_target_bytes", params.get("sga_target_value", params.get("sga_target")))) or 0
            memory_target_bytes = self._parse_memory_value_bytes(params.get("memory_target_bytes", params.get("memory_target_value", params.get("memory_target")))) or 0
            mode = "AMM" if memory_target_bytes > 0 else "ASMM" if sga_target_bytes > 0 else "MANUAL"
            evidence.update({
                "source": "v$parameter",
                "sga_target": params.get("sga_target"),
                "sga_target_value": params.get("sga_target_value"),
                "sga_target_bytes": sga_target_bytes,
                "sga_target_mb": round(sga_target_bytes / 1024 / 1024, 2) if sga_target_bytes is not None else None,
                "sga_max_size": params.get("sga_max_size"),
                "sga_max_size_value": params.get("sga_max_size_value"),
                "sga_max_size_bytes": params.get("sga_max_size_bytes"),
                "sga_max_size_mb": params.get("sga_max_size_mb"),
                "memory_target": params.get("memory_target"),
                "memory_target_value": params.get("memory_target_value"),
                "memory_target_bytes": memory_target_bytes,
                "memory_target_mb": round(memory_target_bytes / 1024 / 1024, 2) if memory_target_bytes is not None else None,
                "memory_max_target": params.get("memory_max_target"),
                "memory_max_target_value": params.get("memory_max_target_value"),
                "memory_max_target_bytes": params.get("memory_max_target_bytes"),
                "memory_max_target_mb": params.get("memory_max_target_mb"),
                "management_mode": mode,
            })
            return evidence
        if check_id in {"pga_aggregate_target_configured", "pga_aggregate_limit_configured"}:
            parameter = check_id.replace("_configured", "")
            raw_value = params.get(f"{parameter}_value", params.get(parameter))
            normalized_bytes = self._parse_memory_value_bytes(params.get(f"{parameter}_bytes", raw_value))
            if normalized_bytes is None:
                normalized_bytes = self._parse_memory_value_bytes(params.get(parameter))
            evidence.update({
                "source": "v$parameter",
                "exists": parameter in params and params.get(parameter) is not None,
                parameter: params.get(parameter),
                f"{parameter}_display": params.get(parameter),
                f"{parameter}_value": raw_value,
                f"{parameter}_bytes": normalized_bytes,
                f"{parameter}_mb": round(normalized_bytes / 1024 / 1024, 2) if normalized_bytes is not None else None,
            })
            return evidence
        if check_id == "pga_memory_usage_info":
            stats = memory.get("pga_stats") or []
            by_name = {str(row.get("name", "")).lower(): row.get("value") for row in stats if isinstance(row, dict)}
            bytes_to_mb = {
                "aggregate PGA target parameter": "aggregate_pga_target_parameter_mb",
                "aggregate PGA auto target": "aggregate_pga_auto_target_mb",
                "total PGA allocated": "total_pga_allocated_mb",
                "total PGA inuse": "total_pga_inuse_mb",
                "maximum PGA allocated": "maximum_pga_allocated_mb",
            }
            for name, field in bytes_to_mb.items():
                value = self._safe_float(by_name.get(name.lower()))
                evidence[field] = round(value / 1024 / 1024, 2) if value is not None else None
            evidence["over_allocation_count"] = by_name.get("over allocation count")
            evidence["cache_hit_percentage"] = by_name.get("cache hit percentage")
            evidence["rows"] = stats
            return evidence
        if check_id == "sga_memory_info":
            rows = memory.get("sga_info") or []
            normalized = []
            max_sga = None
            free_sga = None
            for row in rows:
                item = dict(row)
                value = self._safe_float(item.get("mb"))
                if value is None:
                    bytes_value = self._safe_float(item.get("bytes"))
                    value = round(bytes_value / 1024 / 1024, 2) if bytes_value is not None else None
                    item["mb"] = value
                if item.get("name") == "Maximum SGA Size":
                    max_sga = value
                if item.get("name") == "Free SGA Memory Available":
                    free_sga = value
                normalized.append(item)
            evidence["rows"] = normalized
            evidence["free_sga_memory_mb"] = free_sga
            evidence["maximum_sga_size_mb"] = max_sga
            evidence["free_sga_memory_pct"] = round((free_sga / max_sga) * 100, 2) if free_sga is not None and max_sga else None
            return evidence
        sessions = resources.get("sessions") if isinstance(resources.get("sessions"), dict) else {}
        if check_id == "blocked_sessions_basic":
            rows = sessions.get("blocked_sessions") or []
            evidence.update({"affected_count": len(rows), "rows": rows, "thresholds": thresholds, "max_seconds_in_wait": max([float(row.get("seconds_in_wait") or 0) for row in rows], default=0)})
            return evidence
        if check_id == "blocking_sessions_basic":
            rows = sessions.get("blocking_sessions") or []
            evidence.update({"affected_count": len(rows), "rows": rows, "thresholds": thresholds})
            return evidence
        if check_id == "inactive_sessions_high":
            rows = sessions.get("inactive_sessions") or []
            total = sum(int(row.get("inactive_sessions") or 0) for row in rows if isinstance(row, dict))
            evidence.update({"total_inactive_sessions": total, "affected_count": total, "rows": rows, "thresholds": thresholds})
            return evidence
        scheduler = resources.get("scheduler_jobs") if isinstance(resources.get("scheduler_jobs"), dict) else {}
        legacy = resources.get("legacy_jobs") if isinstance(resources.get("legacy_jobs"), dict) else {}
        field_map = {
            "scheduler_failed_jobs_recent": (scheduler.get("failed_recent") or [], {"lookback_days": check.evaluator.get("lookback_days", 7)}),
            "scheduler_disabled_jobs": (scheduler.get("disabled") or [], {}),
            "scheduler_broken_jobs": (scheduler.get("broken") or [], {}),
            "legacy_dba_jobs_broken": (legacy.get("broken") or [], {}),
        }
        rows, extra = field_map.get(check_id, ([], {}))
        evidence.update({"affected_count": len(rows), "rows": rows})
        evidence.update(extra)
        return evidence
