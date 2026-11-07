"""Descubrimiento y construcción de evidencia del grupo capacity.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin


class CapacityMixin(CommonMixin):
    def _default_capacity_inventory(self, database: dict[str, Any] | None = None, healthy_defaults: bool = False) -> dict[str, Any]:
        database = database if isinstance(database, dict) else {}
        storage = database.get("storage") if isinstance(database.get("storage"), dict) else {}
        resources = database.get("oracle_resources") if isinstance(database.get("oracle_resources"), dict) else {}
        if healthy_defaults and not storage:
            storage = {
                "tablespaces": [{"tablespace_name": "USERS", "total_mb": 10240, "used_mb": 2048, "free_mb": 8192, "used_pct": 20, "free_pct": 80, "autoextensible": "YES", "max_mb": 32768}],
                "datafiles": [{"file_id": 7, "tablespace_name": "USERS", "file_name": "/u01/oradata/users01.dbf", "bytes_mb": 10240, "maxbytes_mb": 32768, "autoextensible": "YES", "increment_by": 128, "used_of_max_pct": 31.25}],
                "tempfiles": [{"tablespace_name": "TEMP", "file_name": "/u01/oradata/temp01.dbf", "bytes_mb": 4096, "maxbytes_mb": 16384, "autoextensible": "YES"}],
                "temp_usage": [{"tablespace_name": "TEMP", "total_mb": 4096, "used_mb": 128, "free_mb": 3968, "used_pct": 3.13, "active_usage_available": True}],
                "undo": {"undo_tablespace": "UNDOTBS1", "undo_retention": 900, "total_mb": 4096, "used_mb": 512, "free_mb": 3584},
                "fra": {"fra_configured": False, "message": "FRA no está configurada o space_limit es 0"},
            }
        return {"storage": storage, "resource_limits": resources.get("resource_limits", []), "segments_top": [], "archive_destinations": []}

    def _discover_capacity_inventory(self, connector: Any, database: dict[str, Any]) -> dict[str, Any]:
        capacity = self._default_capacity_inventory(database)
        top_segments = self._query_schema_rows(connector, "segmentos principales de aplicación para capacidad", """
            select * from (
              select s.owner, s.segment_name, s.segment_type, s.tablespace_name,
                     round(sum(s.bytes) / 1024 / 1024, 2) as size_mb,
                     count(*) as segment_parts,
                     u.oracle_maintained
              from dba_segments s
              left join dba_users u on u.username = s.owner
              where nvl(u.oracle_maintained, 'N') = 'N'
              group by s.owner, s.segment_name, s.segment_type, s.tablespace_name, u.oracle_maintained
              order by sum(s.bytes) desc
            ) where rownum <= 50
        """, """
            select * from (
              select s.owner, s.segment_name, s.segment_type, s.tablespace_name,
                     round(sum(s.bytes) / 1024 / 1024, 2) as size_mb,
                     count(*) as segment_parts,
                     null as oracle_maintained
              from dba_segments s
              where s.owner not in ({internal_schemas})
              group by s.owner, s.segment_name, s.segment_type, s.tablespace_name
              order by sum(s.bytes) desc
            ) where rownum <= 50
        """)
        capacity["segments_top"] = self._filter_oracle_maintained_schema_rows(top_segments)
        capacity["archive_destinations"] = self._query_rows(connector, "destinos archive para capacity", """
            select d.dest_id, d.destination, d.status, d.target, d.binding,
                   s.status as runtime_status, s.error
            from v$archive_dest d
            left join v$archive_dest_status s on s.dest_id = d.dest_id
            where d.destination is not null
            order by d.dest_id
        """)
        return {"capacity": capacity}

    def _build_capacity_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        cap = database.get("capacity") if isinstance(database.get("capacity"), dict) else self._default_capacity_inventory(database)
        storage = cap.get("storage") if isinstance(cap.get("storage"), dict) else {}
        check_id = check.check_id
        evidence: dict[str, Any] = {"metric": check_id, "label": check.collector.get("label", check.title), "source": check.collector.get("source_view"), "scope_note": "Fotografía actual de capacidad; no usa AWR, ASH, vistas históricas DBA-HIST, SQLite ni repositorio histórico interno."}
        evidence.update({k: v for k, v in check.evaluator.items() if k not in {"type", "metric"} and not k.endswith("_policy")})
        if check_id == "capacity_database_size_snapshot":
            rows = storage.get("tablespaces") or []
            total = sum(self._safe_float(r.get("total_mb")) or 0 for r in rows)
            used = sum(self._safe_float(r.get("used_mb")) or 0 for r in rows)
            free = sum(self._safe_float(r.get("free_mb")) or 0 for r in rows)
            evidence.update({"total_mb": round(total, 2), "used_mb": round(used, 2), "free_mb": round(free, 2), "used_pct": round((used / total) * 100, 2) if total else None, "free_pct": round((free / total) * 100, 2) if total else None, "tablespace_count": len(rows), "datafile_count": len(storage.get("datafiles") or []), "rows": rows})
            return evidence
        if check_id == "capacity_tablespace_headroom":
            rows=[]
            for r in storage.get("tablespaces") or []:
                item=dict(r); total=self._safe_float(item.get("total_mb")) or 0; free=self._safe_float(item.get("free_mb")) or 0; maxmb=self._safe_float(item.get("max_mb")) or self._safe_float(item.get("total_mb")) or 0
                item["autoextend_enabled"] = str(item.get("autoextensible", item.get("autoextend_enabled", "NO"))).upper() == "YES"
                item["max_mb"] = maxmb; item["headroom_mb"] = round(maxmb - total + free, 2) if maxmb else free; item["headroom_pct"] = round((item["headroom_mb"] / maxmb) * 100, 2) if maxmb else None
                rows.append(item)
            evidence["rows"] = sorted(rows, key=lambda x: x.get("headroom_pct") if x.get("headroom_pct") is not None else 999)
            return evidence
        if check_id == "capacity_datafile_headroom":
            rows=[]
            for r in storage.get("datafiles") or []:
                item=dict(r); bytesmb=self._safe_float(item.get("bytes_mb", item.get("current_mb"))) or 0; maxmb=self._safe_float(item.get("maxbytes_mb", item.get("max_mb"))) or bytesmb
                item["maxbytes_mb"] = maxmb; item["remaining_mb_to_max"] = round(maxmb - bytesmb, 2); item["used_pct_of_max"] = round((bytesmb / maxmb) * 100, 2) if maxmb else None; item["headroom_pct"] = round((item["remaining_mb_to_max"] / maxmb) * 100, 2) if maxmb else None
                rows.append(item)
            evidence["rows"] = sorted(rows, key=lambda x: x.get("headroom_pct") if x.get("headroom_pct") is not None else 999)
            return evidence
        if check_id == "capacity_segments_top_size":
            limit = int(evidence.get("top_segments_limit", check.collector.get("max_rows", 20)) or 20)
            evidence["rows"] = (cap.get("segments_top") or [])[:limit]
            evidence["internal_schema_filter"] = "Se excluyen esquemas ORACLE_MAINTAINED cuando la columna existe; si no, se usa lista conservadora."
            return evidence
        if check_id == "capacity_temp_capacity_snapshot":
            usage = {r.get("tablespace_name"): r for r in (storage.get("temp_usage") or []) if isinstance(r, dict)}
            rows=[]
            by_ts={}
            for tf in storage.get("tempfiles") or []:
                by_ts.setdefault(tf.get("tablespace_name"), []).append(tf)
            for ts, files in by_ts.items():
                total=sum(self._safe_float(f.get("bytes_mb")) or 0 for f in files); maxmb=sum(self._safe_float(f.get("maxbytes_mb")) or self._safe_float(f.get("bytes_mb")) or 0 for f in files); u=usage.get(ts, {})
                used=self._safe_float(u.get("used_mb")); free=self._safe_float(u.get("free_mb"))
                if used is None: used=0 if u else None
                rows.append({"tablespace_name": ts, "total_temp_mb": total, "used_temp_mb": used, "free_temp_mb": free if free is not None else (round(total-used,2) if used is not None else None), "used_pct": self._safe_float(u.get("used_pct")), "free_pct": round(100-(self._safe_float(u.get("used_pct")) or 0),2) if u.get("used_pct") is not None else None, "tempfile_count": len(files), "max_mb": maxmb, "headroom_mb": round(maxmb - total + (free or 0),2) if maxmb else None, "active_usage_available": u.get("active_usage_available"), "note": u.get("note")})
            evidence["rows"] = rows; evidence["limitation"] = storage.get("temp_usage_error") or ("Uso actual TEMP no disponible; se reporta capacidad de tempfiles." if not usage else None)
            return evidence
        if check_id == "capacity_undo_capacity_snapshot":
            undo=dict(storage.get("undo") or {}); total=self._safe_float(undo.get("total_mb")); used=self._safe_float(undo.get("used_mb")); free=self._safe_float(undo.get("free_mb"))
            undo.update({"total_undo_mb": total, "used_undo_mb": used, "free_undo_mb": free, "used_pct": round((used/total)*100,2) if total and used is not None else None, "free_pct": round((free/total)*100,2) if total and free is not None else None})
            evidence.update(undo); evidence["rows"] = [undo] if undo else []; evidence.setdefault("limitation", "Uso UNDO aproximado desde diccionario actual; no es proyección histórica.")
            return evidence
        if check_id == "capacity_resource_limits_headroom":
            rows=[]
            for r in cap.get("resource_limits") or []:
                limit=self._safe_float(r.get("limit_value")); current=self._safe_float(r.get("current_utilization")); item=dict(r)
                item["used_pct"] = round((current/limit)*100,2) if current is not None and limit and limit > 0 else None; item["headroom"] = round(limit-current,2) if current is not None and limit else None
                rows.append(item)
            evidence["rows"] = rows
            return evidence
        if check_id == "capacity_fra_archive_headroom":
            fra=dict(storage.get("fra") or {}); limit=self._safe_float(fra.get("space_limit_mb")); used=self._safe_float(fra.get("space_used_mb")); reclaim=self._safe_float(fra.get("space_reclaimable_mb")) or 0
            evidence.update(fra); evidence["fra_configured"] = bool(fra.get("fra_configured")); evidence["headroom_mb"] = round(limit - used + reclaim, 2) if limit is not None and used is not None else None; evidence["archive_destinations"] = cap.get("archive_destinations") or []; evidence["rows"] = [fra] if evidence["fra_configured"] else []
            if not evidence["fra_configured"]: evidence["message"] = fra.get("message", "FRA no configurada o sin límite efectivo reportado")
            return evidence
        return evidence
