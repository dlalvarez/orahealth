"""Descubrimiento y construcción de evidencia del grupo patching.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin


class PatchingMixin(CommonMixin):
    def _default_patching_inventory(self, database: dict[str, Any] | None = None, healthy_defaults: bool = False) -> dict[str, Any]:
        database = database if isinstance(database, dict) else {}
        sqlpatch = database.get("sqlpatch_rows") if isinstance(database.get("sqlpatch_rows"), list) else []
        if healthy_defaults and not sqlpatch:
            sqlpatch = [{"patch_id": 0, "patch_uid": 0, "action": "APPLY", "status": "SUCCESS", "action_time": "2026-01-01", "description": "Inventario mock saludable", "source_version": database.get("version", "19.0.0.0.0"), "target_version": database.get("version", "19.0.0.0.0")}]
        components = database.get("registry_components") if isinstance(database.get("registry_components"), list) else []
        if healthy_defaults and not components:
            components = [{"comp_id": "CATALOG", "comp_name": "Oracle Database Catalog Views", "version": database.get("version", "19.0.0.0.0"), "status": "VALID", "modified": None}]
        return {
            "product_components": database.get("product_components", []),
            "sqlpatch_rows": sqlpatch,
            "registry_components": components,
            "invalid_objects": database.get("patching_invalid_objects", []),
            "pdb_sqlpatch_rows": database.get("pdb_sqlpatch_rows", []),
            "collection_errors": database.get("patching_collection_errors", {}),
        }

    def _discover_patching_inventory(self, connector: Any, inventory: dict[str, Any]) -> dict[str, Any]:
        patching = self._default_patching_inventory(inventory)
        patching["product_components"], pc_error = self._query_rows_with_error(connector, "componentes de producto para patching", """
            select product, version, status
            from product_component_version
            order by product
        """, log_warning=False)
        patching["sqlpatch_rows"], sqlpatch_error = self._query_rows_with_error(connector, "inventario SQL patch", """
            select patch_id, patch_uid, action, status, action_time, description,
                   source_version, target_version
            from dba_registry_sqlpatch
            order by action_time desc, patch_id
        """, log_warning=False)
        patching["registry_components"], reg_error = self._query_rows_with_error(connector, "componentes DBA_REGISTRY", """
            select comp_id, comp_name, version, status, modified
            from dba_registry
            order by comp_id
        """, log_warning=False)
        patching["invalid_objects"], inv_error = self._query_rows_with_error(connector, "objetos inválidos para prepatch", """
            select o.owner, o.object_name, o.object_type, o.status, o.last_ddl_time, u.oracle_maintained
            from dba_objects o
            left join dba_users u on u.username = o.owner
            where o.status <> 'VALID'
            order by o.owner, o.object_type, o.object_name
            fetch first 200 rows only
        """, log_warning=False)
        errors = {k: v for k, v in {"product_components": pc_error, "sqlpatch_rows": sqlpatch_error, "registry_components": reg_error, "invalid_objects": inv_error}.items() if v}
        if str(inventory.get("cdb") or "NO").upper() == "YES":
            patching["pdb_sqlpatch_rows"], pdb_error = self._query_rows_with_error(connector, "SQL patch por PDB", """
                select con_id, patch_id, patch_uid, action, status, action_time, description, source_version, target_version
                from cdb_registry_sqlpatch
                order by con_id, action_time desc, patch_id
            """, log_warning=False)
            if pdb_error:
                errors["pdb_sqlpatch_rows"] = pdb_error
        patching["collection_errors"] = errors
        return {"patching": patching}

    def _build_patching_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        patching = database.get("patching") if isinstance(database.get("patching"), dict) else self._default_patching_inventory(database)
        metric = check.check_id
        errors = patching.get("collection_errors") if isinstance(patching.get("collection_errors"), dict) else {}
        evidence = {"metric": metric, "label": check.collector.get("label", check.title), "source": check.collector.get("source_view", "inventario patching")}
        if metric == "patching_database_version":
            evidence.update({"instance_version": database.get("version"), "database_version": database.get("database_version", database.get("version")), "product_components": patching.get("product_components") or [], "source": "V$INSTANCE / PRODUCT_COMPONENT_VERSION"})
            if errors.get("product_components") and not database.get("version"):
                evidence["collection_error"] = errors["product_components"]
            return evidence
        if metric in {"patching_registry_sqlpatch_status", "patching_registry_sqlpatch_errors", "patching_datapatch_inventory_consistency"}:
            evidence.update({"rows": patching.get("sqlpatch_rows") or [], "collection_error": errors.get("sqlpatch_rows")})
            return evidence
        if metric == "patching_registry_components_status":
            rows = patching.get("registry_components") or []
            statuses = [str(r.get("status") or "").upper() for r in rows]
            warning_statuses = {"LOADED", "LOADING", "UPGRADING", "DOWNGRADING"}
            informational_statuses = {"OPTION OFF", "REMOVED"}
            evidence.update({
                "components": rows,
                "component_count": len(rows),
                "invalid_count": statuses.count("INVALID"),
                "warning_count": len([s for s in statuses if s in warning_statuses or s not in {"VALID", "INVALID", *informational_statuses}]),
                "informational_count": len([s for s in statuses if s in informational_statuses]),
                "option_off_count": statuses.count("OPTION OFF"),
                "removed_count": statuses.count("REMOVED"),
                "collection_error": errors.get("registry_components"),
            })
            return evidence
        if metric == "patching_invalid_objects_prepatch":
            rows = patching.get("invalid_objects") or []
            app = [r for r in rows if str(r.get("oracle_maintained") or "N").upper() != "Y"]
            ora = [r for r in rows if str(r.get("oracle_maintained") or "N").upper() == "Y"]
            crit = [r for r in app if str(r.get("object_type") or "").upper() in {"PACKAGE BODY", "PACKAGE", "PROCEDURE", "FUNCTION", "TRIGGER"}]
            evidence.update({"invalid_count": len(rows), "application_invalid_count": len(app), "oracle_maintained_invalid_count": len(ora), "critical_invalid_count": len(crit), "sample_objects": rows[:20], "collection_error": errors.get("invalid_objects")})
            return evidence
        if metric == "patching_database_open_mode_readiness":
            role = database.get("database_role") or database.get("role")
            open_mode = database.get("open_mode")
            db_status = database.get("status")
            note = "Modo observado para evaluar readiness SQL de patching."
            evidence.update({"database_role": role, "open_mode": open_mode, "status": db_status, "readiness_note": note})
            return evidence
        if metric == "patching_pdb_sqlpatch_status":
            is_cdb = str(database.get("cdb") or "NO").upper() == "YES"
            pdbs = (database.get("multitenant") or {}).get("pdbs", []) if isinstance(database.get("multitenant"), dict) else []
            rows = patching.get("pdb_sqlpatch_rows") or []
            problems = [r for r in rows if str(r.get("status") or "").upper() in {"WITH ERRORS", "FAILED", "ERROR", "FAILURE"}]
            evidence.update({"is_cdb": is_cdb, "pdb_count": len(pdbs), "pdbs": pdbs, "pdb_patch_rows": rows, "problem_pdbs": problems, "collection_error": errors.get("pdb_sqlpatch_rows")})
            return evidence
        return evidence
