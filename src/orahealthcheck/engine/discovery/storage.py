"""Descubrimiento y construcción de evidencia del grupo storage.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin
from orahealthcheck.engine.discovery.constants import ORACLE_INTERNAL_SCHEMAS


class StorageMixin(CommonMixin):
    def _discover_storage_inventory(self, connector: Any, parameters: dict[str, Any]) -> dict[str, Any]:
        storage: dict[str, Any] = {"tablespaces": [], "datafiles": [], "tempfiles": [], "temp_usage": [], "fra": {}, "undo": {}, "users": []}
        tablespaces = self._query_rows(connector, "tablespace usage", """
            select
              df.tablespace_name,
              round(df.bytes / 1024 / 1024, 2) as total_mb,
              round((df.bytes - nvl(f.free_bytes, 0)) / 1024 / 1024, 2) as used_mb,
              round(nvl(f.free_bytes, 0) / 1024 / 1024, 2) as free_mb,
              round((nvl(f.free_bytes, 0) / df.bytes) * 100, 2) as free_pct,
              round(((df.bytes - nvl(f.free_bytes, 0)) / df.bytes) * 100, 2) as used_pct,
              df.autoextensible
            from (
              select tablespace_name, sum(bytes) as bytes,
                     case when max(case when autoextensible = 'YES' then 1 else 0 end) = 1 then 'YES' else 'NO' end as autoextensible
              from dba_data_files
              group by tablespace_name
            ) df
            left join (
              select tablespace_name, sum(bytes) as free_bytes
              from dba_free_space
              group by tablespace_name
            ) f on f.tablespace_name = df.tablespace_name
            order by df.tablespace_name
        """)
        storage["tablespaces"] = tablespaces
        if tablespaces:
            free_values = [row.get("free_pct") for row in tablespaces if row.get("free_pct") is not None]
            legacy_free_values = [row.get("tablespace_min_free_pct") for row in tablespaces if row.get("tablespace_min_free_pct") is not None]
            used_values = [row.get("used_pct") for row in tablespaces if row.get("used_pct") is not None]
            if free_values:
                storage["tablespace_min_free_pct"] = min(free_values)
            elif legacy_free_values:
                storage["tablespace_min_free_pct"] = min(legacy_free_values)
            if used_values:
                storage["tablespace_max_used_pct"] = max(used_values)

        storage["datafiles"] = self._query_rows(connector, "datafiles", """
            select file_name, tablespace_name,
                   round(bytes / 1024 / 1024, 2) as bytes_mb,
                   round(bytes / 1024 / 1024, 2) as current_mb,
                   autoextensible,
                   round(maxbytes / 1024 / 1024, 2) as maxbytes_mb,
                   round(maxbytes / 1024 / 1024, 2) as max_mb,
                   case when autoextensible = 'YES' and nvl(maxbytes, 0) > 0 then round((bytes / maxbytes) * 100, 2) else null end as used_of_max_pct,
                   status,
                   online_status
            from dba_data_files
            order by tablespace_name, file_name
        """)
        storage["tempfiles"] = self._query_rows(connector, "tempfiles", """
            select tablespace_name, file_name,
                   round(bytes / 1024 / 1024, 2) as bytes_mb,
                   status,
                   autoextensible,
                   round(maxbytes / 1024 / 1024, 2) as maxbytes_mb
            from dba_temp_files
            order by tablespace_name, file_name
        """)

        internal_schemas = self._sql_in_list(ORACLE_INTERNAL_SCHEMAS)
        storage["users"] = self._query_rows(connector, "tablespaces asignados a usuarios de aplicación", f"""
            select u.username, u.account_status, u.default_tablespace, u.temporary_tablespace,
                   u.oracle_maintained, dt.tablespace_name as default_tablespace_exists,
                   tt.tablespace_name as temporary_tablespace_exists
            from dba_users u
            left join dba_tablespaces dt on dt.tablespace_name = u.default_tablespace
            left join dba_tablespaces tt on tt.tablespace_name = u.temporary_tablespace
            where nvl(u.oracle_maintained, 'N') = 'N'
              and u.username not in ({internal_schemas})
            order by u.username
        """)
        storage["dictionary_managed_tablespaces"] = self._query_rows(connector, "tablespaces administrados por diccionario", """
            select tablespace_name, extent_management, allocation_type, contents, status
            from dba_tablespaces
            where extent_management = 'DICTIONARY'
            order by tablespace_name
        """)
        temp_usage, temp_usage_error = self._query_rows_with_error(connector, "active temporary tablespace usage", """
            select tf.tablespace_name,
                   round(tf.total_bytes / 1024 / 1024, 2) as total_mb,
                   round(nvl(tu.used_bytes, 0) / 1024 / 1024, 2) as used_mb,
                   round((tf.total_bytes - nvl(tu.used_bytes, 0)) / 1024 / 1024, 2) as free_mb,
                   case when tf.total_bytes > 0 then round((nvl(tu.used_bytes, 0) / tf.total_bytes) * 100, 2) else 0 end as used_pct,
                   nvl(tu.active_temp_segments_count, 0) as active_temp_segments_count,
                   nvl(tu.active_temp_sessions_count, 0) as active_temp_sessions_count,
                   'dba_temp_files+v$tempseg_usage' as source,
                   'active_temp_segments' as calculation_method,
                   'Uso activo calculado desde segmentos temporales actualmente asignados a sesiones.' as note
            from (
              select tablespace_name, sum(bytes) as total_bytes
              from dba_temp_files
              group by tablespace_name
            ) tf
            left join (
              select u.tablespace as tablespace_name,
                     sum(u.blocks * ts.block_size) as used_bytes,
                     count(*) as active_temp_segments_count,
                     count(distinct rawtohex(u.session_addr) || ':' || to_char(u.session_num)) as active_temp_sessions_count
              from v$tempseg_usage u
              join dba_tablespaces ts on ts.tablespace_name = u.tablespace
              group by u.tablespace
            ) tu on tu.tablespace_name = tf.tablespace_name
            order by tf.tablespace_name
        """)
        if temp_usage_error:
            temp_usage = self._query_rows(connector, "fallback temporary tablespace usage", """
                select tf.tablespace_name,
                       round(tf.total_bytes / 1024 / 1024, 2) as total_mb,
                       round(nvl(th.used_bytes, 0) / 1024 / 1024, 2) as used_mb,
                       round((tf.total_bytes - nvl(th.used_bytes, 0)) / 1024 / 1024, 2) as free_mb,
                       case when tf.total_bytes > 0 then round((nvl(th.used_bytes, 0) / tf.total_bytes) * 100, 2) else 0 end as used_pct,
                       null as active_temp_segments_count,
                       null as active_temp_sessions_count,
                       'dba_temp_files+v$temp_space_header' as source,
                       'fallback_temp_space_header' as calculation_method,
                       'Fuente activa v$tempseg_usage no disponible; este valor puede reflejar extents temporales retenidos y no se usa para generar FAIL automático.' as note
                from (
                  select tablespace_name, sum(bytes) as total_bytes
                  from dba_temp_files
                  group by tablespace_name
                ) tf
                left join (
                  select tablespace_name, sum(bytes_used) as used_bytes
                  from v$temp_space_header
                  group by tablespace_name
                ) th on th.tablespace_name = tf.tablespace_name
                order by tf.tablespace_name
            """)
            for row in temp_usage:
                row["active_usage_available"] = False
                row["fallback_reason"] = temp_usage_error
        else:
            for row in temp_usage:
                row["active_usage_available"] = True
        storage["temp_usage"] = temp_usage
        storage["temp_usage_active_source_available"] = temp_usage_error is None
        if temp_usage_error:
            storage["temp_usage_error"] = temp_usage_error
        undo_tablespace = self._parameter_value(parameters, "undo_tablespace")
        undo_retention = self._parameter_value(parameters, "undo_retention")
        undo: dict[str, Any] = {"undo_tablespace": undo_tablespace, "undo_retention": undo_retention}
        if undo_tablespace:
            rows = self._query_rows(connector, "undo tablespace", f"""
                select t.tablespace_name, t.status,
                       round(nvl(df.total_bytes, 0) / 1024 / 1024, 2) as total_mb,
                       round(nvl(df.total_bytes, 0) / 1024 / 1024 - nvl(fs.free_bytes, 0) / 1024 / 1024, 2) as used_mb,
                       round(nvl(fs.free_bytes, 0) / 1024 / 1024, 2) as free_mb
                from dba_tablespaces t
                left join (select tablespace_name, sum(bytes) total_bytes from dba_data_files group by tablespace_name) df on df.tablespace_name = t.tablespace_name
                left join (select tablespace_name, sum(bytes) free_bytes from dba_free_space group by tablespace_name) fs on fs.tablespace_name = t.tablespace_name
                where t.tablespace_name = '{str(undo_tablespace).replace("'", "''")}'
            """)
            if rows:
                undo.update(rows[0])
        storage["undo"] = undo
        fra = self._query_one(connector, "FRA usage", """
            select
              name as recovery_file_dest,
              space_limit,
              round(space_limit / 1024 / 1024, 2) as space_limit_mb,
              space_used,
              round(space_used / 1024 / 1024, 2) as space_used_mb,
              space_reclaimable,
              round(space_reclaimable / 1024 / 1024, 2) as space_reclaimable_mb,
              case when nvl(space_limit, 0) > 0 then round((space_used / space_limit) * 100, 2) else null end as used_pct,
              case when nvl(space_limit, 0) > 0 then round((space_reclaimable / space_limit) * 100, 2) else null end as reclaimable_pct
            from v$recovery_file_dest
        """)
        if fra.get("used_pct") is None and fra.get("fra_used_pct") is not None:
            fra["used_pct"] = fra.get("fra_used_pct")
        configured = bool(fra and fra.get("space_limit") not in (None, 0))
        fra["fra_configured"] = configured
        if not configured:
            fra.setdefault("recovery_file_dest", self._parameter_value(parameters, "db_recovery_file_dest"))
            fra.setdefault("recovery_file_dest_size", self._parameter_value(parameters, "db_recovery_file_dest_size"))
            fra["message"] = "FRA no está configurada o space_limit es 0"
        storage["fra"] = fra
        flattened: dict[str, Any] = {"storage": storage, "fra_configured": configured}
        if "tablespace_min_free_pct" in storage:
            flattened["tablespace_min_free_pct"] = storage["tablespace_min_free_pct"]
        if "tablespace_max_used_pct" in storage:
            flattened["tablespace_max_used_pct"] = storage["tablespace_max_used_pct"]
        if configured:
            flattened.update({"fra_used_pct": fra.get("used_pct"), "space_limit": fra.get("space_limit"), "space_used": fra.get("space_used")})
        else:
            flattened["fra_message"] = fra.get("message")
        return flattened

    def _build_storage_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        storage = database.get("storage") if isinstance(database.get("storage"), dict) else {}
        check_id = check.check_id
        thresholds = {k: v for k, v in check.evaluator.items() if k in {"warning", "fail", "critical", "missing_fra_status", "status_when_found"}}
        evidence: dict[str, Any] = {"metric": check_id, "source": check.collector.get("source_view", "oracle storage inventory"), **thresholds}
        tablespaces = storage.get("tablespaces") or []
        datafiles = storage.get("datafiles") or []
        tempfiles = storage.get("tempfiles") or []
        temp_usage = storage.get("temp_usage") or []
        users = self._filter_oracle_maintained_schema_rows(storage.get("users") or [])
        fra = storage.get("fra") or {"fra_configured": database.get("fra_configured"), "used_pct": database.get("fra_used_pct"), "message": database.get("fra_message")}
        undo = storage.get("undo") or {}
        if check_id == "tablespace_free_pct":
            normalized_tablespaces = []
            for row in tablespaces:
                item = dict(row)
                if item.get("free_pct") is None and item.get("tablespace_min_free_pct") is not None:
                    item["free_pct"] = item.get("tablespace_min_free_pct")
                normalized_tablespaces.append(item)
            worst = min(normalized_tablespaces, key=lambda row: row.get("free_pct", 101)) if normalized_tablespaces else {}
            evidence.update({"worst_tablespace": worst.get("tablespace_name"), "worst_free_pct": worst.get("free_pct"), "tablespaces": normalized_tablespaces})
            if not normalized_tablespaces and database.get("tablespace_min_free_pct") is not None:
                evidence.update({"worst_free_pct": database.get("tablespace_min_free_pct"), "tablespaces": [{"free_pct": database.get("tablespace_min_free_pct")} ]})
        elif check_id == "tablespace_used_pct":
            worst = max(tablespaces, key=lambda row: row.get("used_pct", -1)) if tablespaces else {}
            evidence.update({"worst_tablespace": worst.get("tablespace_name"), "max_used_pct": worst.get("used_pct"), "tablespaces": tablespaces})
        elif check_id == "datafiles_autoextend_disabled":
            affected = [row for row in datafiles if str(row.get("autoextensible", "")).upper() == "NO"]
            evidence.update({"datafile_count": len(datafiles), "affected_count": len(affected), "datafiles": affected})
        elif check_id == "datafiles_near_maxsize":
            affected = [row for row in datafiles if row.get("used_of_max_pct") is not None]
            evidence.update({"max_used_of_max_pct": max([row.get("used_of_max_pct") for row in affected], default=None), "datafiles": affected})
        elif check_id == "datafiles_status":
            good_status = {"AVAILABLE"}
            good_online = {"ONLINE", "SYSTEM"}
            affected = [row for row in datafiles if str(row.get("status", "")).upper() not in good_status or (row.get("online_status") and str(row.get("online_status")).upper() not in good_online)]
            evidence.update({"datafile_count": len(datafiles), "affected_count": len(affected), "datafiles": affected})
        elif check_id == "tempfiles_status":
            affected = [row for row in tempfiles if str(row.get("status", "")).upper() not in {"AVAILABLE", "ONLINE"}]
            evidence.update({"tempfile_count": len(tempfiles), "affected_count": len(affected), "tempfiles": tempfiles, "affected_tempfiles": affected})
        elif check_id == "users_system_default_tablespace":
            affected = [row for row in users if str(row.get("default_tablespace", "")).upper() == "SYSTEM" and str(row.get("account_status", "")).upper() == "OPEN"]
            evidence.update({"affected_count": len(affected), "rows": affected})
        elif check_id == "users_system_temp_tablespace":
            affected = [row for row in users if str(row.get("temporary_tablespace", "")).upper() == "SYSTEM"]
            evidence.update({"affected_count": len(affected), "rows": affected})
        elif check_id == "users_missing_default_tablespace":
            affected = [row for row in users if not row.get("default_tablespace") or row.get("default_tablespace_exists") is None]
            evidence.update({"affected_count": len(affected), "rows": affected})
        elif check_id == "users_missing_temp_tablespace":
            affected = [row for row in users if not row.get("temporary_tablespace") or row.get("temporary_tablespace_exists") is None]
            evidence.update({"affected_count": len(affected), "rows": affected})
        elif check_id == "dictionary_managed_tablespaces":
            rows = storage.get("dictionary_managed_tablespaces") or []
            evidence.update({"affected_count": len(rows), "rows": rows})
        elif check_id == "temp_usage_pct":
            worst = max(temp_usage, key=lambda row: row.get("used_pct", -1)) if temp_usage else {}
            evidence.update({
                "max_used_pct": worst.get("used_pct"),
                "worst_tablespace": worst.get("tablespace_name"),
                "source": worst.get("source", evidence.get("source")),
                "calculation_method": worst.get("calculation_method"),
                "active_temp_segments_count": worst.get("active_temp_segments_count"),
                "active_temp_sessions_count": worst.get("active_temp_sessions_count"),
                "active_usage_available": storage.get("temp_usage_active_source_available", True),
                "fallback_reason": storage.get("temp_usage_error"),
                "tablespaces": temp_usage,
            })
        elif check_id == "undo_tablespace_status":
            evidence.update(undo)
        elif check_id == "fra_configured":
            evidence.update(fra)
        elif check_id in ("fra_usage", "fra_usage_pct"):
            evidence.update(fra)
            if "used_pct" in fra:
                evidence["fra_used_pct"] = fra.get("used_pct")
        return evidence
