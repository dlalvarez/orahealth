"""Descubrimiento y construcción de evidencia del grupo asm.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin


class AsmMixin(CommonMixin):
    def _default_asm_inventory(self, database: dict[str, Any]) -> dict[str, Any]:
        existing = database.get("asm")
        if isinstance(existing, dict) and ("files" in existing or "diskgroups_detectados" in existing):
            return existing
        files: list[dict[str, Any]] = []
        storage = database.get("storage") if isinstance(database.get("storage"), dict) else {}
        for source_key, file_type in (("datafiles", "DATAFILE"), ("tempfiles", "TEMPFILE")):
            for row in storage.get(source_key) or []:
                name = row.get("file_name") or row.get("name")
                dg = self._asm_diskgroup_from_path(name)
                if dg:
                    item = dict(row); item.update({"file_type": file_type, "file_name": name, "diskgroup": dg})
                    files.append(item)
        for row in database.get("logfiles", database.get("redo_log_files", [])) or []:
            name = row.get("member") or row.get("file_name")
            dg = self._asm_diskgroup_from_path(name)
            if dg:
                item = dict(row); item.update({"file_type": "REDO", "file_name": name, "diskgroup": dg})
                files.append(item)
        control_files = database.get("control_files")
        if isinstance(control_files, str):
            control_files = [x.strip() for x in control_files.split(",")]
        for name in control_files or []:
            if isinstance(name, dict):
                name = name.get("name") or name.get("file_name")
            dg = self._asm_diskgroup_from_path(name)
            if dg:
                files.append({"file_type": "CONTROLFILE", "file_name": name, "diskgroup": dg})
        fra = storage.get("fra") if isinstance(storage.get("fra"), dict) else {}
        fra_dest = fra.get("name") or fra.get("recovery_file_dest") or database.get("recovery_file_dest") or self._parameter_value(database.get("parameters", {}), "db_recovery_file_dest")
        fra_dg = self._asm_diskgroup_from_path(fra_dest)
        if fra_dg:
            files.append({"file_type": "FRA", "file_name": fra_dest, "diskgroup": fra_dg})
        dgs = sorted({f["diskgroup"] for f in files if f.get("diskgroup")})
        return {
            "usa_asm": bool(dgs),
            "diskgroups_detectados": dgs,
            "files": files,
            "diskgroups": [],
            "disks": [],
            "operations": [],
            "counts": {
                "datafiles": sum(1 for f in files if f.get("file_type") == "DATAFILE"),
                "tempfiles": sum(1 for f in files if f.get("file_type") == "TEMPFILE"),
                "redo_members": sum(1 for f in files if f.get("file_type") == "REDO"),
                "control_files": sum(1 for f in files if f.get("file_type") == "CONTROLFILE"),
            },
            "fra_en_asm": bool(fra_dg),
        }

    def _discover_asm_inventory(self, connector: Any, database: dict[str, Any]) -> dict[str, Any]:
        asm = self._default_asm_inventory(database)
        datafile_rows = [
            dict(row, file_type="DATAFILE")
            for row in (database.get("storage", {}) if isinstance(database.get("storage"), dict) else {}).get("datafiles", [])
            if isinstance(row, dict)
        ]
        if not datafile_rows:
            datafile_rows, datafile_error = self._query_rows_with_error(connector, "datafiles ASM con tablespace", """
                select 'DATAFILE' as file_type, file_id, file_name, tablespace_name
                from dba_data_files
                order by tablespace_name, file_id
            """, log_warning=False)
            if datafile_error:
                datafile_rows = self._query_rows(connector, "datafiles ASM fallback", """
                    select 'DATAFILE' as file_type, file# as file_id, name as file_name, null as tablespace_name
                    from v$datafile
                    order by file#
                """)

        tempfile_rows = [
            dict(row, file_type="TEMPFILE")
            for row in (database.get("storage", {}) if isinstance(database.get("storage"), dict) else {}).get("tempfiles", [])
            if isinstance(row, dict)
        ]
        if not tempfile_rows:
            tempfile_rows, tempfile_error = self._query_rows_with_error(connector, "tempfiles ASM con tablespace", """
                select 'TEMPFILE' as file_type, file_id, file_name, tablespace_name
                from dba_temp_files
                order by tablespace_name, file_id
            """, log_warning=False)
            if tempfile_error:
                tempfile_rows = self._query_rows(connector, "tempfiles ASM fallback", """
                    select 'TEMPFILE' as file_type, file# as file_id, name as file_name, null as tablespace_name
                    from v$tempfile
                    order by file#
                """)

        rows = datafile_rows + tempfile_rows + self._query_rows(connector, "redo y controlfiles ASM usados por la base", """
            select 'REDO' as file_type, group# as file_id, member as file_name, null as tablespace_name from v$logfile
            union all
            select 'CONTROLFILE' as file_type, null as file_id, name as file_name, null as tablespace_name from v$controlfile
        """)
        files = []
        for row in rows:
            dg = self._asm_diskgroup_from_path(row.get("file_name"))
            if dg:
                item = dict(row); item["diskgroup"] = dg; files.append(item)
        fra = self._query_one(connector, "FRA ASM", """
            select name as recovery_file_dest, space_limit, space_used, space_reclaimable
            from v$recovery_file_dest
        """)
        fra_dg = self._asm_diskgroup_from_path(fra.get("recovery_file_dest"))
        if fra_dg:
            files.append({"file_type": "FRA", "file_name": fra.get("recovery_file_dest"), "diskgroup": fra_dg})
        asm["files"] = files
        asm["diskgroups_detectados"] = sorted({f["diskgroup"] for f in files if f.get("diskgroup")})
        asm["usa_asm"] = bool(asm["diskgroups_detectados"])
        asm["fra_en_asm"] = bool(fra_dg)
        asm["counts"] = {
            "datafiles": sum(1 for f in files if f.get("file_type") == "DATAFILE"),
            "tempfiles": sum(1 for f in files if f.get("file_type") == "TEMPFILE"),
            "redo_members": sum(1 for f in files if f.get("file_type") == "REDO"),
            "control_files": sum(1 for f in files if f.get("file_type") == "CONTROLFILE"),
        }
        dg_rows, dg_error = self._query_rows_with_error(connector, "diskgroups ASM desde base", """
            select group_number, name, state, type, total_mb, free_mb, usable_file_mb,
                   required_mirror_free_mb, offline_disks, voting_files
            from v$asm_diskgroup_stat
            order by name
        """, log_warning=False)
        asm["diskgroups"] = dg_rows
        if dg_error:
            asm["diskgroup_collection_error"] = dg_error
        disk_rows, disk_error = self._query_rows_with_error(connector, "discos ASM desde base", """
            select group_number, name as disk_name, path, header_status, mode_status,
                   state, mount_status, failgroup, total_mb, free_mb
            from v$asm_disk_stat
            order by group_number, name
        """, log_warning=False)
        asm["disks"] = disk_rows
        if disk_error:
            asm["disk_collection_error"] = disk_error
        op_rows, op_error = self._query_rows_with_error(connector, "operaciones ASM desde base", """
            select group_number, operation, state, power, actual, sofar, est_work, est_rate, est_minutes
            from v$asm_operation
            order by group_number, operation
        """, log_warning=False)
        asm["operations"] = op_rows
        if op_error:
            asm["operation_collection_error"] = op_error
        return {"asm": asm}

    def _build_asm_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        asm = self._default_asm_inventory(database)
        check_id = check.check_id
        evidence = {"metric": check_id, "label": check.collector.get("label", check.title), "source": check.collector.get("source_view"), "scope_note": "ASM se evalúa desde la conexión de la base de datos; no usa conexión dedicada ASM/Grid ni comandos de infraestructura."}
        evidence.update({k: v for k, v in check.evaluator.items() if k not in {"type", "metric"} and not k.endswith("_policy")})
        evidence["used_diskgroups"] = asm.get("diskgroups_detectados") or []
        if check_id == "asm_database_uses_asm":
            evidence.update({"usa_asm": bool(asm.get("usa_asm")), "diskgroups_detectados": asm.get("diskgroups_detectados") or [], "fra_en_asm": bool(asm.get("fra_en_asm"))})
            evidence.update(asm.get("counts") or {})
            return evidence
        if check_id == "asm_database_files_on_asm":
            evidence["rows"] = asm.get("files") or []
            return evidence
        if check_id in {"asm_diskgroup_inventory_db_view", "asm_diskgroup_state_db_view"}:
            evidence["rows"] = self._asm_relevant_diskgroups(asm)
            if asm.get("diskgroup_collection_error"):
                evidence["collection_error"] = asm.get("diskgroup_collection_error")
            return evidence
        if check_id in {"asm_diskgroup_usage_db_view", "asm_diskgroup_free_headroom_db_view"}:
            rows = []
            for row in self._asm_relevant_diskgroups(asm):
                item = dict(row)
                total = self._safe_float(item.get("total_mb")) or 0
                free = self._safe_float(item.get("free_mb"))
                usable = self._safe_float(item.get("usable_file_mb"))
                item["used_mb"] = round(total - (free or 0), 2) if total and free is not None else None
                item["free_pct"] = round((free / total) * 100, 2) if total and free is not None else None
                item["used_pct"] = round(100 - item["free_pct"], 2) if item.get("free_pct") is not None else None
                item["usable_pct"] = round((usable / total) * 100, 2) if total and usable is not None else None
                item["headroom_status"] = "USABLE_FILE_MB" if usable is not None else "FREE_MB_FALLBACK"
                rows.append(item)
            evidence["rows"] = rows
            if asm.get("diskgroup_collection_error"):
                evidence["collection_error"] = asm.get("diskgroup_collection_error")
            return evidence
        if check_id == "asm_disk_status_db_view":
            evidence["rows"] = asm.get("disks") or []
            if asm.get("disk_collection_error"):
                evidence["collection_error"] = asm.get("disk_collection_error")
            return evidence
        if check_id == "asm_rebalance_operations_db_view":
            evidence["rows"] = asm.get("operations") or []
            if asm.get("operation_collection_error"):
                evidence["collection_error"] = asm.get("operation_collection_error")
            return evidence
        return evidence

    def _asm_relevant_diskgroups(self, asm: dict[str, Any]) -> list[dict[str, Any]]:
        used = {str(x).upper().lstrip("+") for x in asm.get("diskgroups_detectados") or []}
        rows = asm.get("diskgroups") if isinstance(asm.get("diskgroups"), list) else []
        if not used:
            return rows
        filtered = [r for r in rows if str(r.get("name") or r.get("diskgroup") or "").upper().lstrip("+") in used]
        return filtered or rows

    def _asm_diskgroup_from_path(self, path: Any) -> str | None:
        text = str(path or "").strip()
        if not text.startswith("+"):
            return None
        return text.split("/", 1)[0].lstrip("+").upper()
