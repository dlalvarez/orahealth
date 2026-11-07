"""Descubrimiento y construcción de evidencia del grupo io_redo_archive.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin


class IoRedoArchiveMixin(CommonMixin):
    def _discover_io_redo_archive_inventory(self, connector: Any, parameters: dict[str, Any], base_inventory: dict[str, Any]) -> dict[str, Any]:
        io: dict[str, Any] = self._default_io_redo_archive_inventory(base_inventory, parameters)
        io["archive_destinations"]["rows"] = self._query_rows(connector, "destinos de archive", """
            select d.dest_id,
                   d.dest_name,
                   d.status as archive_dest_status,
                   s.status as archive_dest_status_detail,
                   d.type as archive_dest_type,
                   s.type as archive_dest_status_type,
                   d.destination as archive_destination,
                   d.target,
                   d.binding,
                   d.archiver,
                   d.schedule,
                   d.valid_now,
                   d.valid_type,
                   d.valid_role,
                   d.error as archive_dest_error,
                   s.error as archive_dest_status_error,
                   d.db_unique_name,
                   s.database_mode,
                   s.recovery_mode,
                   s.protection_mode,
                   s.synchronization_status,
                   s.synchronized,
                   s.gap_status
            from v$archive_dest d
            left join v$archive_dest_status s on s.dest_id = d.dest_id
            where d.dest_id is not null
              and (
                   d.destination is not null
                   or d.status not in ('INACTIVE')
                   or d.error is not null
                   or s.error is not null
              )
            order by d.dest_id
        """)
        io["archivelog"]["recent"] = (self._query_one(connector, "generación reciente de archived logs", """
            select count(*) as archivelog_count,
                   round(nvl(sum(blocks * block_size),0)/1024/1024,2) as total_mb,
                   round(nvl(avg(blocks * block_size),0)/1024/1024,2) as avg_mb,
                   min(first_time) as first_time,
                   max(first_time) as last_time,
                   listagg(distinct thread#, ',') within group (order by thread#) as threads
            from v$archived_log
            where first_time >= sysdate - 1
              and name is not null
        """) or {})
        io["fra"]["recovery_file_dest"] = self._query_one(connector, "uso de FRA", """
            select name as recovery_file_dest,
                   round(space_limit/1024/1024,2) as space_limit_mb,
                   round(space_used/1024/1024,2) as space_used_mb,
                   round(space_reclaimable/1024/1024,2) as space_reclaimable_mb,
                   case when space_limit > 0 then round(space_used/space_limit*100,2) end as used_pct,
                   case when space_limit > 0 then round(space_reclaimable/space_limit*100,2) end as reclaimable_pct
            from v$recovery_file_dest
        """)
        io["fra"]["usage_by_file_type"] = self._query_rows(connector, "desglose de uso de FRA", """
            select file_type, percent_space_used, percent_space_reclaimable, number_of_files
            from v$flash_recovery_area_usage
            order by file_type
        """)
        io["flashback"]["log_usage"] = self._query_one(connector, "uso de flashback logs", """
            select oldest_flashback_scn, oldest_flashback_time, retention_target,
                   round(flashback_size/1024/1024,2) as flashback_size_mb,
                   round(estimated_flashback_size/1024/1024,2) as estimated_flashback_size_mb
            from v$flashback_database_log
        """)
        io["redo"]["log_switches"] = self._query_rows(connector, "frecuencia de log switches", """
            select thread#, to_char(first_time, 'YYYY-MM-DD HH24') as switch_hour, count(*) as switch_count
            from v$log_history
            where first_time >= sysdate - 1
            group by thread#, to_char(first_time, 'YYYY-MM-DD HH24')
            order by switch_hour, thread#
        """)
        io["redo"]["groups"] = self._query_rows(connector, "grupos redo", """
            select group#, thread#, round(bytes/1024/1024,2) as bytes_mb, status, archived
            from v$log
            order by thread#, group#
        """)
        io["redo"]["logfiles"] = self._query_rows(connector, "miembros redo", """
            select group#, member, type, status
            from v$logfile
            order by group#, member
        """)
        io["io"]["sysstat"] = self._query_rows(connector, "estadísticas acumuladas de I/O", """
            select name, value
            from v$sysstat
            where name in ('physical reads','physical writes','physical read total bytes','physical write total bytes','redo size','redo writes','redo wastage','DBWR checkpoints','DBWR transaction table writes','redo synch writes','redo write time')
            order by name
        """)
        io["io"]["filestat"] = self._query_rows(connector, "I/O acumulado por datafile", """
            select * from (
              select f.file# as file_number, d.tablespace_name, d.file_name,
                     f.phyrds, f.phywrts, f.phyblkrd, f.phyblkwrt, f.readtim, f.writetim
              from v$filestat f
              join dba_data_files d on d.file_id = f.file#
              order by (nvl(f.phyrds,0) + nvl(f.phywrts,0)) desc
            ) where rownum <= 20
        """)
        io["recoverability"]["nologging_objects"] = self._query_schema_rows(connector, "objetos NOLOGGING de aplicación", """
            select * from (
              select owner, table_name as object_name, 'TABLE' as object_type, logging, tablespace_name, u.oracle_maintained from dba_tables t left join dba_users u on u.username=t.owner where nvl(t.logging,'YES')='NO' and nvl(u.oracle_maintained,'N')='N'
              union all select owner, index_name, 'INDEX', logging, tablespace_name, u.oracle_maintained from dba_indexes i left join dba_users u on u.username=i.owner where nvl(i.logging,'YES')='NO' and nvl(u.oracle_maintained,'N')='N'
              union all select owner, segment_name, 'LOB', logging, tablespace_name, u.oracle_maintained from dba_lobs l left join dba_users u on u.username=l.owner where nvl(l.logging,'YES')='NO' and nvl(u.oracle_maintained,'N')='N'
            ) where rownum <= 100
        """, """
            select * from (
              select owner, table_name as object_name, 'TABLE' as object_type, logging, tablespace_name, null as oracle_maintained from dba_tables where nvl(logging,'YES')='NO' and owner not in ({internal_schemas})
              union all select owner, index_name, 'INDEX', logging, tablespace_name, null as oracle_maintained from dba_indexes where nvl(logging,'YES')='NO' and owner not in ({internal_schemas})
              union all select owner, segment_name, 'LOB', logging, tablespace_name, null as oracle_maintained from dba_lobs where nvl(logging,'YES')='NO' and owner not in ({internal_schemas})
            ) where rownum <= 100
        """)
        io["recoverability"]["unrecoverable_datafiles"] = self._query_rows(connector, "datafiles con cambios unrecoverable", """
            select v.file# as file_number, v.name as file_name, v.unrecoverable_change# as unrecoverable_change, v.unrecoverable_time
            from v$datafile v
            where v.unrecoverable_change# > 0 and v.unrecoverable_time is not null
            order by v.unrecoverable_time desc
        """)
        return {"io_redo_archive": io}

    def _default_io_redo_archive_inventory(self, database: dict[str, Any] | None = None, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        database = database or {}
        parameters = parameters or database.get("parameters", {}) or {}
        return {
            "archivelog_mode": database.get("archivelog_mode"),
            "force_logging": database.get("force_logging"),
            "flashback_on": database.get("flashback_on"),
            "db_flashback_retention_target": self._parameter_value(parameters, "db_flashback_retention_target"),
            "archivelog": {"recent": {}},
            "archive_destinations": {"rows": []},
            "fra": {"recovery_file_dest": {}, "usage_by_file_type": []},
            "flashback": {"log_usage": {}},
            "redo": {"log_switches": [], "groups": [], "logfiles": []},
            "io": {"sysstat": [], "filestat": []},
            "recoverability": {"nologging_objects": [], "unrecoverable_datafiles": []},
        }

    def _build_io_redo_archive_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        io = database.get("io_redo_archive") if isinstance(database.get("io_redo_archive"), dict) else self._default_io_redo_archive_inventory(database, database.get("parameters", {}))
        cid = check.check_id
        ev = {"metric": cid, "label": check.collector.get("label", check.title), "source": check.collector.get("source_view", "inventario de I/O, redo y archive")}
        ev.update({k:v for k,v in check.evaluator.items() if k != "type"})
        ev["archivelog_mode"] = io.get("archivelog_mode", database.get("archivelog_mode"))
        ev["force_logging"] = io.get("force_logging", database.get("force_logging"))
        if cid == "archivelog_generation_recent":
            ev.update({"lookback_hours": check.evaluator.get("lookback_hours",24), **(io.get("archivelog",{}).get("recent") or {})})
            ev["warning_mb"] = check.evaluator.get("warning_archivelog_mb_24h")
            ev["fail_mb"] = check.evaluator.get("fail_archivelog_mb_24h")
        elif cid in {"archive_dest_status", "archive_dest_errors"}:
            rows = [r for r in (io.get("archive_destinations",{}).get("rows") or []) if self._archive_dest_configured(r)]
            ev.update({"rows": rows, "affected_count": len(rows)})
        elif cid in {"fra_usage_advanced", "fra_reclaimable_space"}:
            fra = io.get("fra",{}).get("recovery_file_dest") or {}
            configured = bool(fra.get("space_limit_mb") and float(fra.get("space_limit_mb") or 0) > 0)
            ev.update(fra); ev.update({"fra_configured": configured, "usage_by_file_type": io.get("fra",{}).get("usage_by_file_type") or []})
            if not configured: ev["message"] = "FRA no está configurada o tiene límite de espacio cero"
        elif cid == "flashback_status":
            ev.update({"flashback_on": io.get("flashback_on", database.get("flashback_on")), "db_flashback_retention_target": io.get("db_flashback_retention_target"), "required": check.evaluator.get("required", False)})
        elif cid == "flashback_log_usage":
            ev.update({"flashback_on": io.get("flashback_on", database.get("flashback_on")), **(io.get("flashback",{}).get("log_usage") or {})})
        elif cid == "redo_log_switch_frequency":
            rows = io.get("redo",{}).get("log_switches") or []
            total = sum(int(r.get("switch_count") or 0) for r in rows)
            by_thread = {}
            for r in rows: by_thread[str(r.get("thread#", r.get("thread_number", "?")))] = by_thread.get(str(r.get("thread#", r.get("thread_number", "?"))),0)+int(r.get("switch_count") or 0)
            ev.update({"lookback_hours": check.evaluator.get("lookback_hours",24), "switch_count": total, "switches_per_hour": round(total/float(check.evaluator.get("lookback_hours",24)),2), "max_switches_in_hour": max([int(r.get("switch_count") or 0) for r in rows], default=0), "by_thread": by_thread})
        elif cid == "redo_log_size_assessment":
            groups = io.get("redo",{}).get("groups") or []
            sizes=[float(g.get("bytes_mb") or 0) for g in groups]
            ev.update({"groups": groups, "group_count": len(groups), "min_redo_mb": min(sizes) if sizes else None, "max_redo_mb": max(sizes) if sizes else None, "avg_redo_mb": round(sum(sizes)/len(sizes),2) if sizes else None, "threshold": check.evaluator.get("warning_min_redo_mb")})
        elif cid == "redo_log_status":
            groups = io.get("redo",{}).get("groups") or []
            bad=[g for g in groups if str(g.get("status","")).upper() not in {"CURRENT","ACTIVE","INACTIVE","UNUSED"}]
            ev.update({"groups": bad, "affected_count": len(bad)})
        elif cid == "redo_logfile_status":
            rows = io.get("redo",{}).get("logfiles") or []
            bad=[r for r in rows if str(r.get("status") or "").upper() in {"INVALID","STALE","DELETED"}]
            ev.update({"rows": bad, "affected_count": len(bad)})
        elif cid == "sysstat_io_basic":
            vals={str(r.get("name","")).lower(): r.get("value") for r in io.get("io",{}).get("sysstat",[])}
            ev.update({"startup_time": database.get("startup_time"), "values": vals, "physical_read_total_mb": self._bytes_to_mb(vals.get("physical read total bytes")), "physical_write_total_mb": self._bytes_to_mb(vals.get("physical write total bytes")), "redo_size_mb": self._bytes_to_mb(vals.get("redo size"))})
        elif cid == "filestat_io_basic":
            rows=(io.get("io",{}).get("filestat") or [])[:int(check.evaluator.get("top_n",20))]
            ev.update({"top_n": check.evaluator.get("top_n",20), "rows": rows})
        elif cid == "nologging_objects_basic":
            rows=(io.get("recoverability",{}).get("nologging_objects") or [])[:int(check.evaluator.get("top_n",100))]
            ev.update({"rows": rows, "affected_count": len(rows)})
        elif cid == "unrecoverable_datafiles":
            rows=[]
            recent_days = int(check.evaluator.get("recent_unrecoverable_days",7))
            for r in io.get("recoverability",{}).get("unrecoverable_datafiles",[]):
                item=dict(r)
                item["recent"] = self._is_recent_datetime(item.get("unrecoverable_time"), recent_days)
                rows.append(item)
            ev.update({"rows": rows, "affected_count": len(rows), "recent_unrecoverable_days": recent_days})
        return ev

    def _archive_dest_configured(self, row: dict[str, Any]) -> bool:
        destination = row.get("archive_destination", row.get("destination"))
        status = str(row.get("archive_dest_status", row.get("status", "")) or "").upper()
        return bool(
            destination
            or row.get("archive_dest_error", row.get("error"))
            or row.get("archive_dest_status_error")
            or status not in {"INACTIVE", ""}
        )
