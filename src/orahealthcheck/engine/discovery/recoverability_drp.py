"""Descubrimiento y construcción de evidencia del grupo recoverability_drp.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin


class RecoverabilityDrpMixin(CommonMixin):
    def _default_recoverability_drp_inventory(self, parameters: dict[str, Any] | None = None, healthy_defaults: bool = False) -> dict[str, Any]:
        parameters = parameters if isinstance(parameters, dict) else {}
        control_keep = self._parameter_value(parameters, "control_file_record_keep_time")
        if control_keep is None and healthy_defaults:
            control_keep = 30
        return {
            "backup_mode_datafiles": [],
            "recover_files": [],
            "block_change_tracking": {"status": "ENABLED"} if healthy_defaults else {},
            "backup_metadata": {"rows": [{"status": "COMPLETED", "end_time": datetime.now().isoformat()}]} if healthy_defaults else {"rows": []},
            "controlfile_record_keep_time": {"value": control_keep, "parameter": "control_file_record_keep_time"},
            "restore_points": [],
        }

    def _discover_recoverability_drp_inventory(self, connector: Any, parameters: dict[str, Any]) -> dict[str, Any]:
        data = self._default_recoverability_drp_inventory(parameters)
        rows, error = self._query_rows_with_error(connector, "datafiles en modo backup activo", """
            select file# as file_number, status, change# as change_number, time
            from v$backup
            order by file#
        """, log_warning=False)
        data["backup_mode_datafiles"] = rows
        if error:
            data["backup_mode_datafiles_error"] = error
        rows, error = self._query_rows_with_error(connector, "archivos que requieren recuperación", """
            select file# as file_number, online_status, error, change# as change_number, time
            from v$recover_file
            order by file#
        """, log_warning=False)
        data["recover_files"] = rows
        if error:
            data["recover_files_error"] = error
        rows, error = self._query_rows_with_error(connector, "Block Change Tracking", """
            select status, filename, bytes
            from v$block_change_tracking
        """, log_warning=False)
        data["block_change_tracking"] = rows[0] if rows else {}
        if error:
            data["block_change_tracking_error"] = error
        rows, error = self._query_rows_with_error(connector, "metadatos locales de respaldos recientes", """
            select * from (
              select session_key, input_type, status, start_time, end_time, elapsed_seconds, output_bytes_display
              from v$rman_backup_job_details
              where status like 'COMPLETED%'
              order by end_time desc
            ) where rownum <= 20
        """, log_warning=False)
        data["backup_metadata"] = {"rows": rows, "source": "v$rman_backup_job_details"}
        if error:
            data["backup_metadata"]["collection_error"] = error
        data["restore_points"] = self._query_rows(connector, "restore points", """
            select name, scn, time, guarantee_flashback_database, storage_size, preserved
            from v$restore_point
            order by time desc
        """)
        return {"recoverability_drp": data}

    def _build_recoverability_drp_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        data = database.get("recoverability_drp") if isinstance(database.get("recoverability_drp"), dict) else self._default_recoverability_drp_inventory(database.get("parameters", {}))
        cid = check.check_id
        evidence = {"metric": cid, "label": check.collector.get("label", check.title), "source": check.collector.get("source_view", "inventario de recuperabilidad y preparación DRP")}
        evidence.update({k: v for k, v in check.evaluator.items() if k != "type"})
        if cid == "recoverability_backup_mode_datafiles":
            evidence.update({"rows": data.get("backup_mode_datafiles") or [], "collection_error": data.get("backup_mode_datafiles_error")})
        elif cid == "recoverability_files_need_recovery":
            evidence.update({"rows": data.get("recover_files") or [], "collection_error": data.get("recover_files_error")})
        elif cid == "recoverability_block_change_tracking":
            evidence.update(data.get("block_change_tracking") or {})
            evidence["collection_error"] = data.get("block_change_tracking_error")
        elif cid == "recoverability_backup_metadata_recent":
            metadata = data.get("backup_metadata") or {}
            rows = metadata.get("rows") or []
            days = int(check.evaluator.get("recent_backup_days", 7))
            recent = [r for r in rows if self._is_recent_datetime(r.get("end_time"), days)]
            evidence.update({"rows": recent, "visible_rows": rows, "recent_backup_days": days, "source": metadata.get("source", evidence["source"]), "collection_error": metadata.get("collection_error")})
        elif cid == "recoverability_controlfile_record_retention":
            evidence.update(data.get("controlfile_record_keep_time") or {})
        elif cid == "recoverability_restore_points":
            evidence.update({"rows": data.get("restore_points") or []})
        return evidence
