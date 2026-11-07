"""Descubrimiento y construcción de evidencia del grupo dataguard.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

import re
from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.discovery.common import CommonMixin


class DataguardMixin(CommonMixin):
    def _default_dataguard_inventory(self, database: dict[str, Any]) -> dict[str, Any]:
        existing = database.get("dataguard")
        existing_dg = existing if isinstance(existing, dict) else {}
        params = database.get("parameters", {}) if isinstance(database.get("parameters"), dict) else {}
        role = str(existing_dg.get("database_role") or database.get("role", database.get("database_role", "PRIMARY"))).upper()
        signals: list[str] = []
        if role in {"PHYSICAL STANDBY", "LOGICAL STANDBY", "SNAPSHOT STANDBY", "FAR SYNC"}:
            signals.append(f"database_role={role}")
        if self._has_explicit_dg_config(params, database.get("db_unique_name")):
            signals.append("parametro_log_archive_config_dg_config")
        if self._has_remote_standby_archive_parameter(params):
            signals.append("parametro_log_archive_dest_service")
        remote_destinations = existing_dg.get("remote_archive_destinations") or database.get("remote_archive_destinations") or []
        archive_destinations = existing_dg.get("archive_destinations") or database.get("archive_destinations") or []
        standby_dests = list(remote_destinations) + [r for r in archive_destinations if self._is_standby_archive_dest(r)]
        if standby_dests:
            signals.append("destinos_archive_standby")
        archive_gaps = existing_dg.get("archive_gaps") or database.get("archive_gaps") or []
        if archive_gaps:
            signals.append("v$archive_gap")
        dataguard_stats = existing_dg.get("dataguard_stats") or database.get("dataguard_stats") or []
        if signals and self._has_meaningful_dataguard_stats(dataguard_stats):
            signals.append("v$dataguard_stats")
        return {
            **existing_dg,
            "database_role": role,
            "open_mode": existing_dg.get("open_mode") or database.get("open_mode"),
            "protection_mode": existing_dg.get("protection_mode") or database.get("protection_mode"),
            "protection_level": existing_dg.get("protection_level") or database.get("protection_level"),
            "switchover_status": existing_dg.get("switchover_status") or database.get("switchover_status"),
            "standby_detected": bool(signals),
            "signals": sorted(set(signals)),
            "archive_destinations": standby_dests,
            "dataguard_stats": dataguard_stats,
            "archive_gaps": archive_gaps,
            "standby_logs": existing_dg.get("standby_logs") or database.get("standby_logs") or [],
            "online_logs": existing_dg.get("online_logs") or database.get("online_logs") or [],
            "threads": existing_dg.get("threads") or database.get("threads") or [],
            "parameters": existing_dg.get("parameters") or params,
            "broker_config": existing_dg.get("broker_config") or database.get("broker_config") or [],
            "broker_properties": existing_dg.get("broker_properties") or database.get("broker_properties") or [],
            "dataguard_status": existing_dg.get("dataguard_status") or database.get("dataguard_status") or [],
            "managed_standby": existing_dg.get("managed_standby") or database.get("managed_standby") or [],
            "broker_config_collection_error": existing_dg.get("broker_config_collection_error"),
            "broker_property_collection_error": existing_dg.get("broker_property_collection_error"),
            "dataguard_status_collection_error": existing_dg.get("dataguard_status_collection_error"),
            "managed_standby_collection_error": existing_dg.get("managed_standby_collection_error"),
        }

    def _discover_dataguard_inventory(self, connector: Any, database: dict[str, Any]) -> dict[str, Any]:
        dg = self._default_dataguard_inventory(database)
        role_info = self._query_one(connector, "rol Data Guard desde V$DATABASE", """
            select database_role, open_mode, protection_mode, protection_level, switchover_status
            from v$database
        """)
        if role_info:
            dg.update({
                "database_role": role_info.get("database_role") or role_info.get("role") or dg.get("database_role"),
                "open_mode": role_info.get("open_mode"),
                "protection_mode": role_info.get("protection_mode"),
                "protection_level": role_info.get("protection_level"),
                "switchover_status": role_info.get("switchover_status"),
            })
        dest_rows, dest_error = self._query_rows_with_error(connector, "destinos Data Guard standby", """
            select dest_id, status, target, destination, error
            from v$archive_dest
            where status <> 'INACTIVE'
        """, log_warning=False)
        dg["archive_destinations"] = [r for r in dest_rows if self._is_standby_archive_dest(r)]
        if dest_error:
            dg["archive_dest_collection_error"] = dest_error
        stats_rows, stats_error = self._query_rows_with_error(connector, "estadísticas Data Guard", """
            select name, value, unit, time_computed, datum_time
            from v$dataguard_stats
        """, log_warning=False)
        dg["dataguard_stats"] = stats_rows
        if stats_error:
            dg["stats_collection_error"] = stats_error
        gap_rows, gap_error = self._query_rows_with_error(connector, "gaps Data Guard", """
            select thread#, low_sequence#, high_sequence#
            from v$archive_gap
        """, log_warning=False)
        dg["archive_gaps"] = gap_rows
        if gap_error:
            dg["gap_collection_error"] = gap_error
        dg["standby_logs"], srl_error = self._query_rows_with_error(connector, "standby redo logs", "select group#, thread#, sequence#, bytes, status from v$standby_log", log_warning=False)
        if srl_error:
            dg["standby_log_collection_error"] = srl_error
        dg["online_logs"], _ = self._query_rows_with_error(connector, "online redo logs Data Guard", "select group#, thread#, bytes, status from v$log", log_warning=False)
        dg["threads"], _ = self._query_rows_with_error(connector, "threads Data Guard", "select thread#, status, enabled from v$thread", log_warning=False)
        dg["broker_config"], broker_error = self._query_rows_with_error(connector, "configuración Broker Data Guard", "select * from v$dg_broker_config", log_warning=False)
        if broker_error:
            dg["broker_config_collection_error"] = broker_error
        dg["broker_properties"], property_error = self._query_rows_with_error(connector, "propiedades Broker Data Guard", "select * from v$dg_broker_property", log_warning=False)
        if property_error:
            dg["broker_property_collection_error"] = property_error
        dg["dataguard_status"], status_error = self._query_rows_with_error(connector, "estado Data Guard", "select * from v$dataguard_status", log_warning=False)
        if status_error:
            dg["dataguard_status_collection_error"] = status_error
        dg["managed_standby"], managed_error = self._query_rows_with_error(connector, "procesos managed standby", "select process, status, thread#, sequence# from v$managed_standby", log_warning=False)
        if managed_error:
            dg["managed_standby_collection_error"] = managed_error
        return {"dataguard": self._default_dataguard_inventory({**database, "dataguard": dg})}

    def _build_dataguard_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        dg = self._default_dataguard_inventory(database)
        cid = check.check_id
        evidence = {"metric": cid, "label": check.collector.get("label", check.title), "source": check.collector.get("source_view")}
        evidence.update({k: v for k, v in check.evaluator.items() if k not in {"type", "metric"} and not k.endswith("_policy")})
        if cid == "dataguard_configuration_detected":
            evidence.update({k: dg.get(k) for k in ("database_role", "protection_mode", "protection_level", "standby_detected", "signals")})
        elif cid == "dataguard_database_role":
            evidence.update({k: dg.get(k) for k in ("database_role", "open_mode", "protection_mode", "protection_level", "switchover_status")})
        elif cid == "dataguard_archive_dest_status":
            evidence["rows"] = dg.get("archive_destinations") or []
            if dg.get("archive_dest_collection_error"): evidence["collection_error"] = dg.get("archive_dest_collection_error")
        elif cid in {"dataguard_transport_lag_basic", "dataguard_apply_lag_basic"}:
            name = "transport lag" if "transport" in cid else "apply lag"
            row = next((r for r in dg.get("dataguard_stats") or [] if str(r.get("name") or "").lower() == name), None)
            if row: evidence.update(row); evidence["value"] = row.get("value")
            if dg.get("stats_collection_error"): evidence["collection_error"] = dg.get("stats_collection_error")
        elif cid == "dataguard_archive_gap_basic":
            evidence["rows"] = dg.get("archive_gaps") or []
            evidence["gap_count"] = len(evidence["rows"])
            if dg.get("gap_collection_error"): evidence["collection_error"] = dg.get("gap_collection_error")
        elif cid == "dataguard_standby_redo_logs_basic":
            online = dg.get("online_logs") or []; srl = dg.get("standby_logs") or []
            evidence.update({"online_redo_groups": len(online), "standby_redo_groups": len(srl), "online_redo_max_mb": self._bytes_to_mb(max([self._safe_float(r.get("bytes")) or 0 for r in online] or [0])), "standby_redo_min_mb": self._bytes_to_mb(min([self._safe_float(r.get("bytes")) or 0 for r in srl] or [0])), "threads": dg.get("threads") or []})
            if dg.get("standby_log_collection_error"): evidence["collection_error"] = dg.get("standby_log_collection_error")
        elif cid == "dataguard_parameters_basic":
            evidence["parameters"] = dg.get("parameters") or {}
            evidence["warnings"] = self._dataguard_parameter_warnings(dg)
        elif cid == "dataguard_broker_configuration_basic":
            evidence.update({"dg_broker_start": self._parameter_value(dg.get("parameters") or {}, "dg_broker_start"), "broker_config_available": not bool(dg.get("broker_config_collection_error")), "broker_rows": dg.get("broker_config") or [], "rows": dg.get("broker_config") or [], "scope_note": "Evaluación SQL básica; no se ejecutan herramientas externas."})
        elif cid == "dataguard_broker_status_basic":
            rows = list(dg.get("broker_config") or []) + list(dg.get("dataguard_status") or [])
            evidence.update({"broker_available": bool(dg.get("broker_config")) or str(self._parameter_value(dg.get("parameters") or {}, "dg_broker_start") or "").upper() in {"TRUE", "ON", "1"}, "rows": rows})
            if dg.get("broker_config_collection_error") and dg.get("dataguard_status_collection_error"): evidence["collection_error"] = dg.get("broker_config_collection_error")
        elif cid == "dataguard_fsfo_status_basic":
            evidence.update({"broker_available": bool(dg.get("broker_config")) or str(self._parameter_value(dg.get("parameters") or {}, "dg_broker_start") or "").upper() in {"TRUE", "ON", "1"}, "properties": self._dataguard_broker_properties(dg)})
            if dg.get("broker_property_collection_error") and not evidence["properties"]: evidence["collection_error"] = dg.get("broker_property_collection_error")
        elif cid == "dataguard_observer_status_basic":
            props = self._dataguard_broker_properties(dg)
            status_rows = dg.get("dataguard_status") or []
            text = " ".join(str(v).upper() for r in status_rows for v in r.values())
            fsfo = str(props.get("faststartfailover") or "").upper() in {"TRUE", "YES", "ENABLED", "ON"}
            evidence.update({"fsfo_enabled": fsfo, "observer_visible": "OBSERVER" in text and not any(t in text for t in ("NO OBSERVER", "OBSERVER NOT", "ORA-")), "properties": props, "rows": status_rows})
        elif cid == "dataguard_managed_standby_processes":
            evidence.update({"database_role": dg.get("database_role"), "rows": dg.get("managed_standby") or [], "processes": dg.get("managed_standby") or [], "expected_processes_note": "Los procesos esperados dependen del rol y de la versión."})
            if dg.get("managed_standby_collection_error"): evidence["collection_error"] = dg.get("managed_standby_collection_error")
        elif cid == "dataguard_switchover_readiness_basic":
            evidence.update({k: dg.get(k) for k in ("database_role", "open_mode", "protection_mode", "protection_level", "switchover_status")})
            evidence.update({"archive_gaps": dg.get("archive_gaps") or [], "dataguard_stats": dg.get("dataguard_stats") or [], "archive_destinations": dg.get("archive_destinations") or []})
        elif cid == "dataguard_protection_consistency":
            evidence.update({k: dg.get(k) for k in ("database_role", "protection_mode", "protection_level")})
            evidence["rows"] = dg.get("archive_destinations") or []
        elif cid == "dataguard_redo_transport_services_basic":
            evidence["rows"] = dg.get("archive_destinations") or []
            if dg.get("archive_dest_collection_error"): evidence["collection_error"] = dg.get("archive_dest_collection_error")
        return evidence

    def _dataguard_broker_properties(self, dg: dict[str, Any]) -> dict[str, Any]:
        props: dict[str, Any] = {}
        for row in dg.get("broker_properties") or []:
            if not isinstance(row, dict):
                continue
            name = row.get("property_name") or row.get("name") or row.get("property")
            value = row.get("property_value") or row.get("value")
            if name is not None:
                props[str(name).replace("_", "").lower()] = value
        return props

    def _is_standby_archive_dest(self, row: dict[str, Any]) -> bool:
        status = str(row.get("status") or "").upper()
        if status == "INACTIVE":
            return False
        target = str(row.get("target") or "").upper()
        destination = str(row.get("destination") or "").upper()
        if target in {"STANDBY", "REMOTE STANDBY"}:
            return True
        if "LOCATION=" in destination or "USE_DB_RECOVERY_FILE_DEST" in destination:
            return False
        if "SERVICE=" not in destination:
            return False
        return any(token in destination for token in ("DB_UNIQUE_NAME=", "VALID_FOR=", "ASYNC", "SYNC"))

    def _has_explicit_dg_config(self, parameters: dict[str, Any], local_db_unique_name: Any = None) -> bool:
        value = str(self._parameter_value(parameters, "log_archive_config") or "").strip().upper()
        if "DG_CONFIG" not in value:
            return False
        match = re.search(r"DG_CONFIG\s*=\s*\(([^)]*)\)", value)
        if not match:
            return True
        names = [item.strip().strip("'\"") for item in match.group(1).split(",") if item.strip()]
        if len(names) >= 2:
            return True
        local = str(local_db_unique_name or "").strip().upper()
        return bool(names and local and any(name.upper() != local for name in names))

    def _has_remote_standby_archive_parameter(self, parameters: dict[str, Any]) -> bool:
        for index in range(1, 32):
            value = str(self._parameter_value(parameters, f"log_archive_dest_{index}") or "").upper()
            if "SERVICE=" not in value:
                continue
            if "LOCATION=" in value or "USE_DB_RECOVERY_FILE_DEST" in value:
                continue
            if any(token in value for token in ("DB_UNIQUE_NAME=", "VALID_FOR=", "ASYNC", "SYNC")):
                return True
        return False

    def _has_meaningful_dataguard_stats(self, rows: Any) -> bool:
        metrics = {"transport lag", "apply lag", "apply finish time", "estimated startup time"}
        return any(str(row.get("name") or "").strip().lower() in metrics and row.get("value") is not None for row in rows or [] if isinstance(row, dict))

    def _dataguard_parameter_warnings(self, dg: dict[str, Any]) -> list[str]:
        params = dg.get("parameters") if isinstance(dg.get("parameters"), dict) else {}
        warnings = []
        if str(self._parameter_value(params, "standby_file_management") or "").upper() not in {"AUTO"}:
            warnings.append("standby_file_management no está en AUTO")
        lac = str(self._parameter_value(params, "log_archive_config") or "").upper()
        if "DG_CONFIG" not in lac:
            warnings.append("log_archive_config no muestra DG_CONFIG")
        if str(dg.get("database_role") or "").upper() == "PRIMARY" and not dg.get("archive_destinations"):
            warnings.append("primary sin destino remoto/standby observado")
        if str(dg.get("database_role") or "").upper() != "PRIMARY" and not self._parameter_value(params, "fal_server"):
            warnings.append("standby sin fal_server observado")
        return warnings
