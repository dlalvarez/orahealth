"""Descubrimiento y construcción de evidencia del grupo rac.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin


class RacMixin(CommonMixin):
    def _default_rac_inventory(self, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        parameters = parameters if isinstance(parameters, dict) else {}
        return {
            "cluster_database": self._parameter_value(parameters, "cluster_database"),
            "instances": [],
            "threads": [],
            "services": [],
            "undo_by_instance": [],
            "interconnects": [],
        }

    def _discover_rac_inventory(self, connector: Any, parameters: dict[str, Any]) -> dict[str, Any]:
        rac = self._default_rac_inventory(parameters)
        if str(rac.get("cluster_database") or "FALSE").upper() != "TRUE":
            return {"rac": rac}
        rac["instances"] = self._query_rows(connector, "instancias RAC visibles", """
            select inst_id, instance_number, instance_name, host_name, status, database_status,
                   active_state, startup_time, version, thread# as thread_number
            from gv$instance
            order by inst_id
        """)
        rac["threads"] = self._query_rows(connector, "threads redo RAC", """
            select inst_id, thread# as thread_number, status, enabled, instance
            from gv$thread
            order by thread#
        """)
        rac["undo_by_instance"] = self._query_rows(connector, "UNDO por instancia RAC", """
            select inst_id, name, value
            from gv$parameter
            where name = 'undo_tablespace'
            order by inst_id
        """)
        rows, error = self._query_rows_with_error(connector, "servicios RAC", """
            select inst_id, name, network_name, creation_date, pdb
            from gv$services
            order by inst_id, name
        """, log_warning=False)
        rac["services"] = rows
        if error:
            rac["services_error"] = error
        rows, error = self._query_rows_with_error(connector, "interconnect RAC", """
            select inst_id, name, ip_address, is_public, source
            from gv$cluster_interconnects
            order by inst_id, name
        """, log_warning=False)
        rac["interconnects"] = rows
        if error:
            rac["interconnects_error"] = error
        return {"rac": rac}

    def _build_rac_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        rac = database.get("rac") if isinstance(database.get("rac"), dict) else self._default_rac_inventory(database.get("parameters", {}))
        cid = check.check_id
        ev = {"metric": cid, "label": check.collector.get("label", check.title), "source": check.collector.get("source_view", "inventario RAC")}
        ev.update({k: v for k, v in check.evaluator.items() if k != "type"})
        ev["required_feature"] = "oracle_rac"
        ev["cluster_database"] = rac.get("cluster_database")
        if cid == "rac_cluster_database_parameter":
            return ev
        if cid in {"rac_instances_status", "rac_instance_count"}:
            rows = rac.get("instances") or []
            ev.update({"rows": rows, "instance_count": len(rows)})
        elif cid == "rac_threads_status":
            rows = rac.get("threads") or []
            ev.update({"rows": rows, "thread_count": len(rows)})
        elif cid == "rac_undo_configuration_basic":
            rows = rac.get("undo_by_instance") or []
            ev.update({"rows": rows, "instance_count": len(rows)})
        elif cid == "rac_services_basic":
            rows = rac.get("services") or []
            ev.update({"rows": rows, "service_count": len(rows), "collection_error": rac.get("services_error")})
        elif cid == "rac_interconnect_info":
            rows = rac.get("interconnects") or []
            ev.update({"rows": rows, "interconnect_count": len(rows), "collection_error": rac.get("interconnects_error")})
        return ev
