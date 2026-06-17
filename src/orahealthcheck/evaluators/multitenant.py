from __future__ import annotations

from typing import Any

from orahealthcheck.models import ResultStatus


class MultitenantEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia Multitenant no tiene una estructura válida"
        if evidence.get("collection_error"):
            return ResultStatus.SKIPPED, f"No se pudo recolectar evidencia Multitenant: {evidence.get('collection_error')}"
        metric = evidence.get("metric") or config.get("metric")
        handler = getattr(self, f"_{metric}", None)
        if handler is None:
            return ResultStatus.ERROR, f"Métrica Multitenant no soportada: {metric}"
        return handler(evidence, config)

    def _application_pdbs(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [r for r in rows if str(r.get("name", "")).upper() not in {"PDB$SEED", "CDB$ROOT"}]

    def _multitenant_pdb_inventory(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        count = int(e.get("pdb_count") or len(e.get("rows") or []))
        return ResultStatus.INFO, f"Inventario Multitenant recolectado con {count} PDB(s) visible(s)."

    def _multitenant_pdb_open_state(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = self._application_pdbs(e.get("rows") or [])
        unexpected_modes = {"MOUNTED", "MIGRATE", "READ ONLY RESTRICTED", "READ WRITE RESTRICTED"}
        inconsistent_statuses = {"UNUSABLE", "UNPLUGGED", "RELOCATING", "RELOCATED"}
        findings = [
            r for r in rows
            if str(r.get("open_mode", "")).upper() in unexpected_modes
            or str(r.get("status", "")).upper() in inconsistent_statuses
            or not str(r.get("open_mode", "")).strip()
        ]
        if not rows:
            return ResultStatus.INFO, "No se detectaron PDBs de aplicación visibles para validar estado de apertura."
        if findings:
            return ResultStatus.WARNING, f"Se detectaron {len(findings)} PDB(s) de aplicación con estado o modo de apertura que requiere revisión prudente."
        return ResultStatus.PASS, "Las PDBs de aplicación visibles tienen un modo de apertura razonable para operación normal."

    def _multitenant_pdb_restricted_mode(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = self._application_pdbs(e.get("rows") or [])
        restricted = [r for r in rows if str(r.get("restricted", "")).upper() in {"YES", "Y", "TRUE"}]
        if restricted:
            return ResultStatus.WARNING, f"Se detectaron {len(restricted)} PDB(s) de aplicación en modo restringido; puede ser intencional durante mantenimiento, pero debe revisarse si no corresponde a una ventana operativa."
        return ResultStatus.PASS, "No se detectaron PDBs de aplicación en modo restringido."
