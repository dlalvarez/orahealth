"""Descubrimiento y construcción de evidencia del grupo multitenant.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin


class MultitenantMixin(CommonMixin):
    def _default_multitenant_inventory(self) -> dict[str, Any]:
        return {
            "pdbs": [],
        }

    def _discover_multitenant_inventory(self, connector: Any, cdb: Any) -> dict[str, Any]:
        multitenant = self._default_multitenant_inventory()
        if str(cdb or "NO").upper() != "YES":
            return {"multitenant": multitenant}
        rows, error = self._query_rows_with_error(connector, "PDBs Multitenant", """
            select c.con_id,
                   c.name,
                   c.open_mode,
                   c.restricted,
                   p.status
            from v$containers c
            left join v$pdbs p on p.con_id = c.con_id
            where c.con_id > 1
            order by c.con_id
        """, log_warning=False)
        multitenant["pdbs"] = rows
        if error:
            multitenant["pdbs_error"] = error
        return {"multitenant": multitenant}

    def _build_multitenant_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        multitenant = database.get("multitenant") if isinstance(database.get("multitenant"), dict) else self._default_multitenant_inventory()
        rows = multitenant.get("pdbs") or []
        return {
            "metric": check.check_id,
            "label": check.collector.get("label", check.title),
            "source": check.collector.get("source_view", "inventario Multitenant"),
            "required_feature": "multitenant",
            "rows": rows,
            "pdb_count": len(rows),
            "collection_error": multitenant.get("pdbs_error"),
        }
