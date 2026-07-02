import copy
import json
import logging
import re
import shlex
import time
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from orahealthcheck.connectors import LocalConnector, OracleConnector, SSHConnector
from orahealthcheck.engine.applicability import ApplicabilityEngine
from orahealthcheck.engine.scoring import summarize
from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.evaluators.oracle_resources import OracleResourcesEvaluator
from orahealthcheck.models import Check, Inventory, Result, ResultStatus, Target
from orahealthcheck.os_adapters import AIXAdapter, LinuxAdapter
from orahealthcheck.reports.html_reporter import HTMLReporter
from orahealthcheck.utils.filesystem import ensure_dir
from orahealthcheck.utils.masking import mask_secrets
from orahealthcheck.utils.time import timestamp

# Allowlists de seguridad Oracle para reducir falsos positivos de cuentas internas
# esperadas por diseño. No incluyen usuarios de aplicación ni roles custom.
ORACLE_DBA_ROLE_ALLOWED_GRANTEES = {"SYS", "SYSTEM"}
ORACLE_EXPECTED_ADMIN_USERS = {"SYS", "SYSTEM"}
ORACLE_EXPECTED_DICTIONARY_ACCESS_GRANTEES = {
    "SYS", "SYSTEM", "DBA", "SELECT_CATALOG_ROLE", "EXECUTE_CATALOG_ROLE",
    "EXP_FULL_DATABASE", "IMP_FULL_DATABASE", "OEM_MONITOR", "SYSBACKUP",
    "SYSDG", "SYSKM", "SYSRAC", "SYSASM",
}
ORACLE_INTERNAL_SCHEMAS = {
    "SYS", "SYSTEM", "XDB", "MDSYS", "CTXSYS", "ORDSYS", "ORDDATA", "ORDPLUGINS",
    "WMSYS", "OUTLN", "DBSNMP", "GSMADMIN_INTERNAL", "AUDSYS", "OJVMSYS",
    "DVSYS", "DVF", "LBACSYS", "OLAPSYS", "MDDATA", "SI_INFORMTN_SCHEMA",
    "ANONYMOUS", "APEX_PUBLIC_USER", "FLOWS_FILES", "DIP", "EXFSYS", "MGMT_VIEW",
}


class CheckRunner:
    def __init__(self, config: dict[str, Any], oracle_connector_factory: Any = OracleConnector) -> None:
        self.config = config
        self.applicability = ApplicabilityEngine()
        self.oracle_connector_factory = oracle_connector_factory

    def run_target(self, target_id: str, profile_id: str | None = None) -> Path:
        run_start = time.monotonic()
        target: Target = self.config["targets"][target_id]
        selected_profile_id = profile_id or target.profile
        profile = self.config["profiles"][selected_profile_id]
        base_output = self.config["settings"].get("app", {}).get("default_output_dir", "output")
        output_dir = ensure_dir(Path(base_output) / f"{target_id}_{timestamp()}")
        self._configure_logging(output_dir)
        logging.info("Starting OraHealthCheck execution")
        logging.info("Target: %s (%s)", target.target_id, target.name)
        logging.info("Profile: %s", profile.profile_id)
        logging.info("Enabled groups: %s", ", ".join(profile.enabled_groups) or "none")
        inventory = self._discover_inventory(target)
        checks = self._resolve_checks(profile)
        logging.info("Loaded checks (%s): %s", len(checks), ", ".join(check.check_id for check in checks) or "none")
        results = [self._run_check(check, target, inventory) for check in checks]
        summary = summarize(results)
        executed = [result.check_id for result in results if result.status != ResultStatus.SKIPPED]
        skipped = [result.check_id for result in results if result.status == ResultStatus.SKIPPED]
        logging.info("Executed checks (%s): %s", len(executed), ", ".join(executed) or "none")
        logging.info("Skipped checks (%s): %s", len(skipped), ", ".join(skipped) or "none")
        logging.info("Status summary: %s", json.dumps(summary, sort_keys=True))
        self._write_json(output_dir / "inventory.json", inventory.to_dict())
        self._write_json(output_dir / "evidence.json", {"summary": summary, "results": [r.to_dict() for r in results]})
        HTMLReporter(Path("templates/html")).generate(output_dir, target, inventory, results, summary, self.config)
        total_duration_ms = int((time.monotonic() - run_start) * 1000)
        logging.info("Output directory: %s", output_dir)
        logging.info("Total duration_ms: %s", total_duration_ms)
        logging.info("Finished OraHealthCheck execution")
        return output_dir

    def _configure_logging(self, output_dir: Path) -> None:
        root = logging.getLogger()
        root.handlers.clear()
        root.setLevel(logging.INFO)
        handler = logging.FileHandler(output_dir / "execution.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        root.addHandler(handler)

    def _discover_inventory(self, target: Target) -> Inventory:
        if "mock_inventory" in target.database:
            logging.info("Using mock database inventory for target %s", target.target_id)
            db = dict(target.database.get("mock_inventory", {}))
        else:
            logging.info("Using OracleConnector for database inventory on target %s", target.target_id)
            db = self._discover_oracle_inventory(target)
        db.setdefault("status", "OPEN")
        db.setdefault("open_mode", "READ WRITE")
        db.setdefault("role", "PRIMARY")
        db.setdefault("version", "19.0")
        db.setdefault("oracle_resources", self._default_oracle_resources_inventory(db.get("parameters", {}), healthy_defaults="mock_inventory" in target.database))
        db.setdefault("io_redo_archive", self._default_io_redo_archive_inventory(db, db.get("parameters", {})))
        db.setdefault("recoverability_drp", self._default_recoverability_drp_inventory(db.get("parameters", {}), healthy_defaults="mock_inventory" in target.database))
        db.setdefault("rac", self._default_rac_inventory(db.get("parameters", {})))
        db.setdefault("multitenant", self._default_multitenant_inventory())
        db.setdefault("alert_log", self._default_alert_log_inventory(db))
        db.setdefault("performance", self._default_performance_inventory())
        db.setdefault("capacity", self._default_capacity_inventory(db, healthy_defaults="mock_inventory" in target.database))
        db.setdefault("asm", self._default_asm_inventory(db))
        db.setdefault("dataguard", self._default_dataguard_inventory(db))
        if "mock_inventory" in target.database:
            db["parameters"] = self._with_default_mock_parameters(db.get("parameters", {}))
        features = self._detect_oracle_features_from_inventory(db)
        os_data = {"platform": target.operating_system.get("platform", "linux")}
        if target.operating_system.get("use_local_discovery", False):
            adapter = LinuxAdapter(LocalConnector()) if os_data["platform"] == "linux" else AIXAdapter(LocalConnector())
            os_data.update({"os_info": adapter.get_os_info(), "cpu": adapter.get_cpu_info(), "memory": adapter.get_memory_info()})
        return Inventory(target.target_id, target.expected_architecture, target.environment, db, os_data, {**features, **target.features})


    def _with_default_mock_parameters(self, parameters: Any) -> dict[str, Any]:
        existing = parameters if isinstance(parameters, dict) else {}
        defaults = {
            "plsql_optimize_level": "2",
            "plsql_code_type": "INTERPRETED",
            "plsql_debug": "FALSE",
            "sql_trace": "FALSE",
            "timed_statistics": "TRUE",
            "timed_os_statistics": "0",
            "result_cache_mode": "MANUAL",
            "result_cache_max_result": "5%",
            "result_cache_remote_expiration": "0",
            "db_ultra_safe": "OFF",
            "optimizer_capture_sql_plan_baselines": "FALSE",
            "optimizer_use_invisible_indexes": "FALSE",
        }
        normalized_defaults = {
            name: {"name": name, "value": value, "display_value": value}
            for name, value in defaults.items()
        }
        return {**normalized_defaults, **existing}

    def _discover_oracle_inventory(self, target: Target) -> dict[str, Any]:
        connection_id = target.database.get("primary_connection")
        if not connection_id:
            return {}
        profile = self.config["connections"]["db_connections"].get(connection_id)
        connector = self.oracle_connector_factory(profile)
        try:
            connector.connect()
            inventory: dict[str, Any] = {}
            inventory.update(self._query_one(connector, "database status", """
                select
                  name as db_name,
                  db_unique_name,
                  open_mode,
                  database_role as role,
                  log_mode as archivelog_mode,
                  force_logging,
                  cdb,
                  protection_mode,
                  protection_level,
                  flashback_on
                from v$database
            """))
            inventory.update(self._query_one(connector, "instance status", """
                select status from v$instance
            """))
            inventory.update(self._query_one(connector, "database version", """
                select version, instance_name from v$instance
            """))
            parameter_rows = self._query_rows(connector, "Oracle parameters", """
                select name, value, display_value, isdefault
                from v$parameter
                where name in (
                  'compatible',
                  'optimizer_features_enable',
                  'db_block_size',
                  'open_cursors',
                  'processes',
                  'sessions',
                  'audit_trail',
                  'remote_login_passwordfile',
                  'recyclebin',
                  'filesystemio_options',
                  'control_files',
                  'undo_tablespace',
                  'undo_retention',
                  'db_recovery_file_dest',
                  'db_recovery_file_dest_size',
                  'sec_case_sensitive_logon',
                  'sga_target',
                  'sga_max_size',
                  'memory_target',
                  'memory_max_target',
                  'pga_aggregate_target',
                  'pga_aggregate_limit',
                  'db_flashback_retention_target',
                  'control_file_record_keep_time',
                  'diagnostic_dest',
                  'cluster_database',
                  'plsql_optimize_level',
                  'plsql_code_type',
                  'plsql_debug',
                  'sql_trace',
                  'timed_statistics',
                  'timed_os_statistics',
                  'result_cache_mode',
                  'result_cache_max_result',
                  'result_cache_remote_expiration',
                  'db_ultra_safe',
                  'optimizer_capture_sql_plan_baselines',
                  'optimizer_use_invisible_indexes',
                  'log_archive_config',
                  'log_archive_dest_1',
                  'log_archive_dest_2',
                  'log_archive_dest_3',
                  'log_archive_dest_4',
                  'log_archive_dest_5',
                  'fal_server',
                  'fal_client',
                  'standby_file_management',
                  'log_file_name_convert',
                  'db_file_name_convert'
                )
            """)
            if parameter_rows:
                inventory["parameters"] = {str(row.get("name", "")).lower(): row for row in parameter_rows if row.get("name")}
            inventory.update(self._query_one(connector, "control file count", """
                select count(*) as control_file_count
                from v$controlfile
            """))
            inventory.update(self._query_one(connector, "redo log group count", """
                select count(*) as redo_log_group_count
                from v$log
            """))
            redo_members = self._query_rows(connector, "redo log member counts", """
                select group# as group_number, count(*) as member_count
                from v$logfile
                group by group#
                order by group#
            """)
            if redo_members:
                inventory["redo_log_members"] = redo_members
                member_counts = [row.get("member_count") for row in redo_members if row.get("member_count") is not None]
                if member_counts:
                    inventory["min_redo_log_members_per_group"] = min(member_counts)
            inventory.update(self._query_one(connector, "invalid objects", """
                select count(*) as invalid_objects_count
                from dba_objects
                where status = 'INVALID'
            """))
            inventory.update(self._discover_schema_objects_inventory(connector))
            inventory.update(self._discover_storage_inventory(connector, inventory.get("parameters", {})))
            inventory.update(self._discover_security_inventory(connector))
            inventory.update(self._discover_oracle_resources_inventory(connector, inventory.get("parameters", {})))
            inventory.update(self._discover_performance_inventory(connector))
            inventory.update(self._discover_capacity_inventory(connector, inventory))
            inventory.update(self._discover_asm_inventory(connector, inventory))
            inventory.update(self._discover_dataguard_inventory(connector, inventory))
            inventory.update(self._discover_io_redo_archive_inventory(connector, inventory.get("parameters", {}), inventory))
            inventory.update(self._discover_recoverability_drp_inventory(connector, inventory.get("parameters", {})))
            inventory.update(self._discover_rac_inventory(connector, inventory.get("parameters", {})))
            inventory.update(self._discover_multitenant_inventory(connector, inventory.get("cdb")))
            inventory["alert_log"] = self._discover_alert_log_inventory(connector, target, inventory)
            inventory.update(self._discover_oracle_feature_signals(connector))
            return inventory
        finally:
            connector.close()

    def _default_alert_log_inventory(self, database: dict[str, Any]) -> dict[str, Any]:
        excerpt = database.get("alert_log_excerpt")
        if excerpt is not None:
            return {
                "available": True,
                "source": "mock_inventory",
                "events": self._alert_log_events_from_text(str(excerpt), "mock_inventory"),
                "message": "Muestra de alert log proporcionada por el inventario mock.",
            }
        return {
            "available": False,
            "status": "skipped",
            "source": "no_configurado",
            "events": [],
            "message": "No fue posible acceder al alert log. La instancia Oracle genera alert log, pero este target no tiene privilegios SQL suficientes sobre V$DIAG_ALERT_EXT ni conexión OS/SSH/local configurada para leer el archivo alert_<INSTANCE_NAME>.log.",
        }

    def _discover_alert_log_inventory(self, connector: Any, target: Target, inventory: dict[str, Any]) -> dict[str, Any]:
        lookback_hours = int(self.config.get("settings", {}).get("alert_log", {}).get("lookback_hours", 72) or 72)
        rows, diag_alert_error = self._query_rows_with_error(connector, "alert log desde V$DIAG_ALERT_EXT", f"""
            select
              originating_timestamp,
              message_level,
              message_type,
              message_group,
              problem_key,
              message_text,
              filename,
              log_name,
              con_id,
              container_name
            from v$diag_alert_ext
            where originating_timestamp >= systimestamp - numtodsinterval({lookback_hours}, 'HOUR')
            order by originating_timestamp desc
        """, log_warning=False)
        if diag_alert_error is None:
            return {
                "available": True,
                "source": "v$diag_alert_ext",
                "lookback_hours": lookback_hours,
                "events": [self._normalize_alert_log_sql_event(row) for row in rows],
                "message": "Alert log consultado desde V$DIAG_ALERT_EXT.",
            }

        diag_info = self._query_rows(connector, "ubicación de alert log desde V$DIAG_INFO", """
            select name, value
            from v$diag_info
            where name in ('Diag Trace', 'Diag Alert', 'ADR Home', 'ADR Base')
        """)
        diag_info_by_name = {str(row.get("name")): row.get("value") for row in diag_info}
        instance_name = str(inventory.get("instance_name") or "").strip()
        candidate_path = None
        source = "alert_log_file"
        if diag_info_by_name.get("Diag Trace") and instance_name:
            candidate_path = f"{str(diag_info_by_name['Diag Trace']).rstrip('/')}/alert_{instance_name}.log"
        else:
            diagnostic_dest = self._parameter_value(inventory.get("parameters", {}), "diagnostic_dest")
            db_identity = inventory.get("db_unique_name") or inventory.get("db_name")
            if diagnostic_dest and db_identity and instance_name:
                candidate_path = f"{str(diagnostic_dest).rstrip('/')}/diag/rdbms/{str(db_identity).lower()}/{instance_name}/trace/alert_{instance_name}.log"
                source = "diagnostic_dest_fallback"

        os_connector = self._build_alert_log_os_connector(target)
        if candidate_path and os_connector is not None:
            command = f"tail -n 5000 {shlex.quote(candidate_path)}"
            try:
                output = os_connector.run_command(command, timeout=60)
            except Exception as exc:
                return self._alert_log_read_error(candidate_path, source, str(exc), diag_alert_error)
            finally:
                close = getattr(os_connector, "close", None)
                if callable(close):
                    close()
            if int(output.get("exit_code", 1) or 0) != 0:
                detail = output.get("stderr") or output.get("stdout") or f"exit_code={output.get('exit_code')}"
                return self._alert_log_read_error(candidate_path, source, str(detail).strip(), diag_alert_error)
            return {
                "available": True,
                "source": source,
                "path": candidate_path,
                "events": self._alert_log_events_from_text(output.get("stdout", ""), source, filename=candidate_path),
                "diag_alert_error": diag_alert_error,
                "message": f"Alert log leído desde {candidate_path}.",
            }

        return {
            "available": False,
            "status": "skipped",
            "source": "sin_acceso",
            "events": [],
            "candidate_path": candidate_path,
            "diag_alert_error": diag_alert_error,
            "message": "No fue posible acceder al alert log. La instancia Oracle genera alert log, pero este target no tiene privilegios SQL suficientes sobre V$DIAG_ALERT_EXT ni conexión OS/SSH/local configurada para leer el archivo alert_<INSTANCE_NAME>.log.",
        }

    def _build_alert_log_os_connector(self, target: Target) -> Any | None:
        if target.operating_system.get("use_local_discovery", False):
            return LocalConnector()
        connections = target.operating_system.get("connections", []) or []
        if not connections:
            return None
        profile = self.config.get("connections", {}).get("os_connections", {}).get(connections[0])
        if not profile:
            return None
        return SSHConnector(profile)

    def _alert_log_read_error(self, path: str, source: str, detail: str, diag_alert_error: str | None) -> dict[str, Any]:
        return {
            "available": False,
            "status": "error",
            "source": source,
            "path": path,
            "events": [],
            "diag_alert_error": diag_alert_error,
            "read_error": detail,
            "message": f"Se intentó leer el alert log en {path}, pero ocurrió un error técnico: {detail}.",
        }

    def _normalize_alert_log_sql_event(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "timestamp": row.get("originating_timestamp"),
            "message_text": row.get("message_text"),
            "message_level": row.get("message_level"),
            "message_type": row.get("message_type"),
            "message_group": row.get("message_group"),
            "problem_key": row.get("problem_key"),
            "filename": row.get("filename"),
            "log_name": row.get("log_name"),
            "con_id": row.get("con_id"),
            "container_name": row.get("container_name"),
            "source": "v$diag_alert_ext",
        }

    def _alert_log_events_from_text(self, text: str, source: str, filename: str | None = None) -> list[dict[str, Any]]:
        return [
            {"timestamp": None, "message_text": line, "filename": filename, "source": source}
            for line in text.splitlines()
        ]

    def _discover_oracle_feature_signals(self, connector: Any) -> dict[str, Any]:
        signals: dict[str, Any] = {}
        fra = self._query_one(connector, "FRA para detección de características", """
            select space_limit as fra_space_limit
            from v$recovery_file_dest
        """)
        if fra:
            signals.update(fra)
        remote_destinations = self._query_rows(connector, "destinos remotos de archive para bases standby", """
            select dest_id, status, target, destination
            from v$archive_dest
            where status <> 'INACTIVE'
              and target = 'STANDBY'
        """)
        if remote_destinations:
            signals["remote_archive_destinations"] = remote_destinations
        return signals

    def _detect_oracle_features_from_inventory(self, database: dict[str, Any]) -> dict[str, Any]:
        parameters = database.get("parameters", {}) if isinstance(database.get("parameters"), dict) else {}
        cluster_value = str((parameters.get("cluster_database") or {}).get("value", "FALSE")).upper()
        rac_detected = cluster_value == "TRUE"

        cdb_value = str(database.get("cdb", "NO")).upper()
        multitenant_detected = cdb_value == "YES"

        database_role = str(database.get("role", database.get("database_role", "PRIMARY"))).upper()
        dg_info = self._default_dataguard_inventory(database)
        standby_detected = bool(dg_info.get("standby_detected"))

        fra_space_limit = database.get("fra_space_limit")
        if fra_space_limit is None:
            fra_space_limit = database.get("recovery_file_dest_size")
        if fra_space_limit is None and isinstance(database.get("storage"), dict):
            fra_space_limit = (database["storage"].get("fra") or {}).get("space_limit") or (database["storage"].get("fra") or {}).get("recovery_file_dest_size")
        fra_detected = bool(database.get("fra_configured")) or self._safe_number(fra_space_limit) > 0

        flashback_value = str(database.get("flashback_on", "NO")).upper()
        asm_info = self._default_asm_inventory(database)
        asm_detected = bool(asm_info.get("usa_asm"))
        asm_diskgroups = asm_info.get("diskgroups_detectados") or []
        return {
            "oracle_rac": {
                "detected": rac_detected,
                "status": "detected" if rac_detected else "not_detected",
                "source": "V$PARAMETER.CLUSTER_DATABASE",
                "value": cluster_value,
                "reason": f"cluster_database = {cluster_value}",
            },
            "multitenant": {
                "detected": multitenant_detected,
                "status": "detected" if multitenant_detected else "not_detected",
                "source": "V$DATABASE.CDB",
                "value": cdb_value,
                "reason": "La base de datos está configurada como CDB." if multitenant_detected else "La base de datos no está configurada como CDB.",
            },
            "standby_configuration": {
                "detected": standby_detected,
                "status": "detected" if standby_detected else "not_detected",
                "source": "V$DATABASE.DATABASE_ROLE / V$ARCHIVE_DEST / V$PARAMETER",
                "database_role": database_role,
                "protection_mode": database.get("protection_mode"),
                "protection_level": database.get("protection_level"),
                "signals": dg_info.get("signals") or [],
                "reason": "Configuración de bases standby detectada." if standby_detected else "No se detectaron señales locales de configuración con bases standby.",
            },
            "fra_configured": {
                "detected": fra_detected,
                "status": "detected" if fra_detected else "not_detected",
                "source": "V$RECOVERY_FILE_DEST",
                "space_limit": self._safe_number(fra_space_limit),
                "reason": "FRA configurada." if fra_detected else "FRA no configurada o space_limit = 0.",
            },
            "flashback_database": {
                "detected": flashback_value == "YES",
                "status": "detected" if flashback_value == "YES" else "not_detected",
                "source": "V$DATABASE.FLASHBACK_ON",
                "value": flashback_value,
                "reason": "Flashback Database está habilitado." if flashback_value == "YES" else "Flashback Database no está habilitado.",
            },
            "asm": {
                "detected": asm_detected,
                "status": "detected" if asm_detected else "not_detected",
                "source": "V$DATAFILE/V$TEMPFILE/V$LOGFILE/V$CONTROLFILE/V$PARAMETER/V$RECOVERY_FILE_DEST",
                "diskgroups": asm_diskgroups,
                "reason": f"Se encontraron archivos de base de datos sobre diskgroups ASM: {', '.join(asm_diskgroups)}" if asm_detected else "No se encontraron archivos de base de datos sobre ASM desde la conexión actual.",
            },
        }

    def _safe_number(self, value: Any) -> float:
        try:
            return float(value or 0)
        except (TypeError, ValueError):
            return 0


    def _discover_schema_objects_inventory(self, connector: Any) -> dict[str, Any]:
        schema_objects: dict[str, Any] = {}
        schema_objects["invalid_objects_detail"] = self._query_schema_rows(connector, "objetos inválidos no mantenidos por Oracle", """
            select o.owner, o.object_name, o.object_type, o.status, o.created, o.last_ddl_time,
                   u.oracle_maintained
            from dba_objects o
            left join dba_users u on u.username = o.owner
            where o.status <> 'VALID'
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by o.owner, o.object_type, o.object_name
        """, """
            select o.owner, o.object_name, o.object_type, o.status, o.created, o.last_ddl_time,
                   null as oracle_maintained
            from dba_objects o
            where o.status <> 'VALID'
              and o.owner not in ({internal_schemas})
            order by o.owner, o.object_type, o.object_name
        """)
        schema_objects["unusable_indexes"] = self._query_schema_rows(connector, "índices no utilizables", """
            select i.owner, i.index_name, i.table_owner, i.table_name, i.status, i.partitioned,
                   i.index_type, i.tablespace_name, u.oracle_maintained
            from dba_indexes i
            left join dba_users u on u.username = i.owner
            where i.status = 'UNUSABLE'
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by i.owner, i.index_name
        """, """
            select i.owner, i.index_name, i.table_owner, i.table_name, i.status, i.partitioned,
                   i.index_type, i.tablespace_name, null as oracle_maintained
            from dba_indexes i
            where i.status = 'UNUSABLE'
              and i.owner not in ({internal_schemas})
            order by i.owner, i.index_name
        """)
        schema_objects["unusable_index_partitions"] = self._query_schema_rows(connector, "particiones de índices no utilizables", """
            select i.owner, i.index_name, p.partition_name, cast(null as varchar2(128)) as subpartition_name,
                   i.table_owner, i.table_name, p.status, 'PARTITION' as "level", u.oracle_maintained
            from dba_ind_partitions p
            join dba_indexes i on i.owner = p.index_owner and i.index_name = p.index_name
            left join dba_users u on u.username = i.owner
            where p.status = 'UNUSABLE'
              and nvl(u.oracle_maintained, 'N') = 'N'
            union all
            select i.owner, i.index_name, sp.partition_name, sp.subpartition_name,
                   i.table_owner, i.table_name, sp.status, 'SUBPARTITION' as "level", u.oracle_maintained
            from dba_ind_subpartitions sp
            join dba_indexes i on i.owner = sp.index_owner and i.index_name = sp.index_name
            left join dba_users u on u.username = i.owner
            where sp.status = 'UNUSABLE'
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by owner, index_name, "level", partition_name, subpartition_name
        """, """
            select i.owner, i.index_name, p.partition_name, cast(null as varchar2(128)) as subpartition_name,
                   i.table_owner, i.table_name, p.status, 'PARTITION' as "level", null as oracle_maintained
            from dba_ind_partitions p
            join dba_indexes i on i.owner = p.index_owner and i.index_name = p.index_name
            where p.status = 'UNUSABLE'
              and i.owner not in ({internal_schemas})
            union all
            select i.owner, i.index_name, sp.partition_name, sp.subpartition_name,
                   i.table_owner, i.table_name, sp.status, 'SUBPARTITION' as "level", null as oracle_maintained
            from dba_ind_subpartitions sp
            join dba_indexes i on i.owner = sp.index_owner and i.index_name = sp.index_name
            where sp.status = 'UNUSABLE'
              and i.owner not in ({internal_schemas})
            order by owner, index_name, "level", partition_name, subpartition_name
        """)
        schema_objects["disabled_constraints"] = self._query_schema_rows(connector, "constraints deshabilitadas", """
            select c.owner, c.constraint_name, c.constraint_type, c.table_name, c.status, c.validated,
                   c.deferrable, c.deferred, c.generated,
                   case when c.constraint_type = 'C' then substr(c.search_condition_vc, 1, 1000) else null end as search_condition,
                   u.oracle_maintained
            from dba_constraints c
            left join dba_users u on u.username = c.owner
            where c.status = 'DISABLED'
              and c.constraint_type in ('P','R','U','C')
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by c.owner, c.table_name, c.constraint_name
        """, """
            select c.owner, c.constraint_name, c.constraint_type, c.table_name, c.status, c.validated,
                   c.deferrable, c.deferred, c.generated,
                   case when c.constraint_type = 'C' then substr(c.search_condition_vc, 1, 1000) else null end as search_condition,
                   null as oracle_maintained
            from dba_constraints c
            where c.status = 'DISABLED'
              and c.constraint_type in ('P','R','U','C')
              and c.owner not in ({internal_schemas})
            order by c.owner, c.table_name, c.constraint_name
        """)
        schema_objects["disabled_triggers"] = self._query_schema_rows(connector, "triggers deshabilitados", """
            select t.owner, t.trigger_name, t.table_owner, t.table_name, t.trigger_type,
                   t.triggering_event, t.status, u.oracle_maintained
            from dba_triggers t
            left join dba_users u on u.username = t.owner
            where t.status = 'DISABLED'
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by t.owner, t.trigger_name
        """, """
            select t.owner, t.trigger_name, t.table_owner, t.table_name, t.trigger_type,
                   t.triggering_event, t.status, null as oracle_maintained
            from dba_triggers t
            where t.status = 'DISABLED'
              and t.owner not in ({internal_schemas})
            order by t.owner, t.trigger_name
        """)
        table_stats_where = "and s.object_type = 'TABLE' and nvl(s.global_stats, 'YES') = 'YES' and nvl(t.temporary, 'N') = 'N'"
        schema_objects["stale_table_statistics"] = self._query_schema_rows(connector, "tablas con estadísticas desactualizadas", f"""
            select s.owner, s.table_name, s.object_type, s.stale_stats, s.last_analyzed, s.num_rows,
                   s.blocks, s.stattype_locked, t.temporary, u.oracle_maintained
            from dba_tab_statistics s
            join dba_tables t on t.owner = s.owner and t.table_name = s.table_name
            left join dba_users u on u.username = s.owner
            where s.stale_stats = 'YES'
              {table_stats_where}
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by s.owner, s.table_name
        """, f"""
            select s.owner, s.table_name, s.object_type, s.stale_stats, s.last_analyzed, s.num_rows,
                   s.blocks, s.stattype_locked, t.temporary, null as oracle_maintained
            from dba_tab_statistics s
            join dba_tables t on t.owner = s.owner and t.table_name = s.table_name
            where s.stale_stats = 'YES'
              {table_stats_where}
              and s.owner not in ({{internal_schemas}})
            order by s.owner, s.table_name
        """)
        schema_objects["missing_table_statistics"] = self._query_schema_rows(connector, "tablas sin estadísticas", f"""
            select s.owner, s.table_name, s.object_type, s.stale_stats, s.last_analyzed, s.num_rows,
                   s.blocks, t.temporary, u.oracle_maintained
            from dba_tab_statistics s
            join dba_tables t on t.owner = s.owner and t.table_name = s.table_name
            left join dba_users u on u.username = s.owner
            where s.last_analyzed is null
              {table_stats_where}
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by s.owner, s.table_name
        """, f"""
            select s.owner, s.table_name, s.object_type, s.stale_stats, s.last_analyzed, s.num_rows,
                   s.blocks, t.temporary, null as oracle_maintained
            from dba_tab_statistics s
            join dba_tables t on t.owner = s.owner and t.table_name = s.table_name
            where s.last_analyzed is null
              {table_stats_where}
              and s.owner not in ({{internal_schemas}})
            order by s.owner, s.table_name
        """)
        schema_objects["locked_table_statistics"] = self._query_schema_rows(connector, "tablas con estadísticas bloqueadas", f"""
            select s.owner, s.table_name, s.object_type, s.stattype_locked, s.last_analyzed,
                   s.stale_stats, s.num_rows, t.temporary, u.oracle_maintained
            from dba_tab_statistics s
            join dba_tables t on t.owner = s.owner and t.table_name = s.table_name
            left join dba_users u on u.username = s.owner
            where s.stattype_locked is not null
              {table_stats_where}
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by s.owner, s.table_name
        """, f"""
            select s.owner, s.table_name, s.object_type, s.stattype_locked, s.last_analyzed,
                   s.stale_stats, s.num_rows, t.temporary, null as oracle_maintained
            from dba_tab_statistics s
            join dba_tables t on t.owner = s.owner and t.table_name = s.table_name
            where s.stattype_locked is not null
              {table_stats_where}
              and s.owner not in ({{internal_schemas}})
            order by s.owner, s.table_name
        """)
        recyclebin_rows = self._query_schema_rows(connector, "objetos en recyclebin", """
            select r.owner, r.object_name, r.original_name, r.type, r.ts_name, r.createtime,
                   r.droptime, r.can_undrop, r.can_purge,
                   round(nvl(s.bytes, r.space * ts.block_size) / 1024 / 1024, 2) as space_mb,
                   u.oracle_maintained
            from dba_recyclebin r
            left join dba_users u on u.username = r.owner
            left join dba_segments s on s.owner = r.owner and s.segment_name = r.object_name
            left join dba_tablespaces ts on ts.tablespace_name = r.ts_name
            where nvl(u.oracle_maintained, 'N') = 'N'
            order by r.owner, r.droptime desc, r.object_name
        """, """
            select r.owner, r.object_name, r.original_name, r.type, r.ts_name, r.createtime,
                   r.droptime, r.can_undrop, r.can_purge,
                   round(nvl(s.bytes, r.space * ts.block_size) / 1024 / 1024, 2) as space_mb,
                   null as oracle_maintained
            from dba_recyclebin r
            left join dba_segments s on s.owner = r.owner and s.segment_name = r.object_name
            left join dba_tablespaces ts on ts.tablespace_name = r.ts_name
            where r.owner not in ({internal_schemas})
            order by r.owner, r.droptime desc, r.object_name
        """)
        schema_objects["recyclebin_objects"] = recyclebin_rows
        schema_objects["recyclebin_total_mb"] = round(sum(float(row.get("space_mb") or 0) for row in recyclebin_rows), 2)

        schema_objects["tables_without_primary_key"] = self._query_schema_rows(connector, "tablas de aplicación sin llave primaria", """
            select t.owner, t.table_name, t.tablespace_name, t.temporary, t.nested, t.dropped, u.oracle_maintained
            from dba_tables t
            left join dba_users u on u.username = t.owner
            where nvl(u.oracle_maintained, 'N') = 'N'
              and nvl(t.temporary, 'N') = 'N'
              and nvl(t.nested, 'NO') = 'NO'
              and nvl(t.dropped, 'NO') = 'NO'
              and not exists (
                select 1 from dba_constraints c
                where c.owner = t.owner and c.table_name = t.table_name and c.constraint_type = 'P'
              )
            order by t.owner, t.table_name
        """, """
            select t.owner, t.table_name, t.tablespace_name, t.temporary, t.nested, t.dropped, null as oracle_maintained
            from dba_tables t
            where t.owner not in ({internal_schemas})
              and nvl(t.temporary, 'N') = 'N'
              and nvl(t.nested, 'NO') = 'NO'
              and nvl(t.dropped, 'NO') = 'NO'
              and not exists (
                select 1 from dba_constraints c
                where c.owner = t.owner and c.table_name = t.table_name and c.constraint_type = 'P'
              )
            order by t.owner, t.table_name
        """)
        schema_objects["foreign_keys_without_index"] = self._query_schema_rows(connector, "llaves foráneas sin índice compatible", """
            with fk_cols as (
              select owner, constraint_name, table_name,
                     listagg(column_name, ',') within group (order by position) as fk_columns,
                     count(*) as column_count
              from dba_cons_columns
              group by owner, constraint_name, table_name
            ), idx_cols as (
              select index_owner, index_name, table_owner, table_name,
                     listagg(column_name, ',') within group (order by column_position) as leading_columns
              from dba_ind_columns
              group by index_owner, index_name, table_owner, table_name
            )
            select c.owner, c.constraint_name, c.table_name, fc.fk_columns, fc.column_count, c.status, c.validated, u.oracle_maintained
            from dba_constraints c
            join fk_cols fc on fc.owner = c.owner and fc.constraint_name = c.constraint_name
            join dba_tables t on t.owner = c.owner and t.table_name = c.table_name
            left join dba_users u on u.username = c.owner
            where c.constraint_type = 'R'
              and c.status = 'ENABLED'
              and nvl(u.oracle_maintained, 'N') = 'N'
              and nvl(t.temporary, 'N') = 'N'
              and not exists (
                select 1 from idx_cols i
                where i.table_owner = c.owner and i.table_name = c.table_name
                  and substr(i.leading_columns || ',', 1, length(fc.fk_columns || ',')) = fc.fk_columns || ','
              )
            order by c.owner, c.table_name, c.constraint_name
        """, """
            with fk_cols as (
              select owner, constraint_name, table_name, listagg(column_name, ',') within group (order by position) as fk_columns, count(*) as column_count from dba_cons_columns group by owner, constraint_name, table_name
            ), idx_cols as (
              select index_owner, index_name, table_owner, table_name, listagg(column_name, ',') within group (order by column_position) as leading_columns from dba_ind_columns group by index_owner, index_name, table_owner, table_name
            )
            select c.owner, c.constraint_name, c.table_name, fc.fk_columns, fc.column_count, c.status, c.validated, null as oracle_maintained
            from dba_constraints c join fk_cols fc on fc.owner = c.owner and fc.constraint_name = c.constraint_name join dba_tables t on t.owner = c.owner and t.table_name = c.table_name
            where c.constraint_type = 'R' and c.status = 'ENABLED' and c.owner not in ({internal_schemas}) and nvl(t.temporary, 'N') = 'N'
              and not exists (select 1 from idx_cols i where i.table_owner = c.owner and i.table_name = c.table_name and substr(i.leading_columns || ',', 1, length(fc.fk_columns || ',')) = fc.fk_columns || ',')
            order by c.owner, c.table_name, c.constraint_name
        """)
        schema_objects["tables_with_long_columns"] = self._query_schema_rows(connector, "columnas LONG o LONG RAW en tablas de aplicación", """
            select c.owner, c.table_name, c.column_name, c.data_type, u.oracle_maintained
            from dba_tab_columns c
            join dba_tables t on t.owner = c.owner and t.table_name = c.table_name
            left join dba_users u on u.username = c.owner
            where c.data_type in ('LONG', 'LONG RAW')
              and nvl(u.oracle_maintained, 'N') = 'N'
              and nvl(t.temporary, 'N') = 'N'
            order by c.owner, c.table_name, c.column_id
        """, """
            select c.owner, c.table_name, c.column_name, c.data_type, null as oracle_maintained
            from dba_tab_columns c join dba_tables t on t.owner = c.owner and t.table_name = c.table_name
            where c.data_type in ('LONG', 'LONG RAW') and c.owner not in ({internal_schemas}) and nvl(t.temporary, 'N') = 'N'
            order by c.owner, c.table_name, c.column_id
        """)
        schema_objects["indexes_too_many_columns"] = self._query_schema_rows(connector, "índices con demasiadas columnas", """
            select i.owner, i.index_name, i.table_owner, i.table_name, count(c.column_name) as column_count, i.index_type, i.status, u.oracle_maintained
            from dba_indexes i
            join dba_ind_columns c on c.index_owner = i.owner and c.index_name = i.index_name
            left join dba_users u on u.username = i.owner
            where nvl(u.oracle_maintained, 'N') = 'N'
            group by i.owner, i.index_name, i.table_owner, i.table_name, i.index_type, i.status, u.oracle_maintained
            order by column_count desc, i.owner, i.index_name
        """, """
            select i.owner, i.index_name, i.table_owner, i.table_name, count(c.column_name) as column_count, i.index_type, i.status, null as oracle_maintained
            from dba_indexes i join dba_ind_columns c on c.index_owner = i.owner and c.index_name = i.index_name
            where i.owner not in ({internal_schemas})
            group by i.owner, i.index_name, i.table_owner, i.table_name, i.index_type, i.status
            order by column_count desc, i.owner, i.index_name
        """)
        schema_objects["invalid_synonyms"] = self._query_schema_rows(connector, "sinónimos locales con destino inexistente", """
            select s.owner, s.synonym_name, s.table_owner, s.table_name, s.db_link,
                   u.oracle_maintained,
                   tu.oracle_maintained as table_owner_oracle_maintained
            from dba_synonyms s
            left join dba_users u on u.username = s.owner
            left join dba_users tu on tu.username = s.table_owner
            left join dba_objects o on o.owner = s.table_owner and o.object_name = s.table_name
            where s.db_link is null
              and o.object_name is null
              and s.owner <> 'PUBLIC'
              and nvl(u.oracle_maintained, 'N') = 'N'
              and nvl(tu.oracle_maintained, 'N') = 'N'
            order by s.owner, s.synonym_name
        """, """
            select s.owner, s.synonym_name, s.table_owner, s.table_name, s.db_link,
                   null as oracle_maintained,
                   null as table_owner_oracle_maintained
            from dba_synonyms s
            left join dba_objects o on o.owner = s.table_owner and o.object_name = s.table_name
            where s.db_link is null
              and o.object_name is null
              and s.owner <> 'PUBLIC'
              and s.owner not in ({internal_schemas})
              and s.table_owner not in ({internal_schemas})
            order by s.owner, s.synonym_name
        """)
        return {"schema_objects": schema_objects}

    def _query_schema_rows(self, connector: Any, label: str, sql: str, fallback_sql: str | None = None) -> list[dict[str, Any]]:
        rows, error = self._query_rows_with_error(connector, label, sql, log_warning=False)
        if error and fallback_sql:
            logging.info("Retrying Oracle schema object query without ORACLE_MAINTAINED for %s", label)
            rows = self._query_rows(connector, f"{label} sin columna oracle_maintained", fallback_sql.format(internal_schemas=self._sql_in_list(ORACLE_INTERNAL_SCHEMAS)))
        return rows

    def _discover_security_inventory(self, connector: Any) -> dict[str, Any]:
        security: dict[str, Any] = {}
        default_accounts = "'ANONYMOUS','APEX_PUBLIC_USER','CTXSYS','DBSNMP','DIP','EXFSYS','FLOWS_FILES','GSMADMIN_INTERNAL','MDSYS','MGMT_VIEW','OLAPSYS','ORDDATA','ORDPLUGINS','ORDSYS','OUTLN','SI_INFORMTN_SCHEMA','WMSYS','XDB'"
        security["locked_users"] = self._query_rows(connector, "usuarios bloqueados", """
            select username, account_status, profile, oracle_maintained, common
            from dba_users
            where account_status like '%LOCKED%'
            order by username
        """)
        security["expired_users"] = self._query_rows(connector, "usuarios expirados", """
            select username, account_status, profile, oracle_maintained, common
            from dba_users
            where account_status like 'EXPIRED%'
              and account_status not like '%LOCKED%'
            order by username
        """)
        security["default_open_users"] = self._query_rows(connector, "usuarios default abiertos", f"""
            select username, account_status, profile, oracle_maintained, common
            from dba_users
            where username in ({default_accounts})
              and account_status = 'OPEN'
            order by username
        """)
        default_profile_users, default_profile_error = self._query_rows_with_error(connector, "usuarios con perfil DEFAULT", """
            select username, account_status, profile, oracle_maintained, common
            from dba_users
            where profile = 'DEFAULT'
              and account_status = 'OPEN'
              and username not in ('SYS', 'SYSTEM')
              and nvl(oracle_maintained, 'N') = 'N'
            order by username
        """, log_warning=False)
        if default_profile_error:
            default_profile_users = self._query_rows(connector, "usuarios con perfil DEFAULT sin columna oracle_maintained", """
                select username, account_status, profile, null as oracle_maintained, null as common
                from dba_users
                where profile = 'DEFAULT'
                  and account_status = 'OPEN'
                  and username not in ('SYS', 'SYSTEM')
                order by username
            """)
        security["default_profile_users"] = default_profile_users
        allowed_dba_grantees = self._sql_in_list(ORACLE_DBA_ROLE_ALLOWED_GRANTEES)
        security["dba_role_users"] = self._query_rows(connector, "usuarios o roles no esperados con rol DBA", f"""
            select
              rp.grantee,
              rp.granted_role,
              rp.admin_option,
              rp.default_role,
              u.account_status,
              u.oracle_maintained,
              u.common,
              u.profile,
              case when u.username is not null then 'USER' else 'ROLE' end as grantee_type
            from dba_role_privs rp
            left join dba_users u on u.username = rp.grantee
            where rp.granted_role = 'DBA'
              and rp.grantee not in ({allowed_dba_grantees})
            order by rp.grantee
        """)
        security["critical_privilege_users"] = self._query_rows(connector, "usuarios o roles no esperados con privilegios críticos", f"""
            select
              sp.grantee,
              sp.privilege,
              sp.admin_option,
              u.account_status,
              u.oracle_maintained,
              u.common,
              u.profile,
              r.oracle_maintained as role_oracle_maintained,
              case when u.username is not null then 'USER' else 'ROLE' end as grantee_type
            from dba_sys_privs sp
            left join dba_users u on u.username = sp.grantee
            left join dba_roles r on r.role = sp.grantee
            where sp.privilege in (
              'ALTER SYSTEM','ALTER DATABASE','CREATE ANY DIRECTORY','CREATE ANY LIBRARY',
              'CREATE ANY PROCEDURE','CREATE ANY TABLE','DROP ANY TABLE','GRANT ANY PRIVILEGE',
              'GRANT ANY ROLE','SELECT ANY DICTIONARY','SELECT ANY TABLE'
            )
              and nvl(u.oracle_maintained, 'N') <> 'Y'
              and nvl(r.oracle_maintained, 'N') <> 'Y'
            order by sp.grantee, sp.privilege
        """)
        security["permissive_failed_login_profiles"] = self._query_rows(connector, "perfiles con failed_login_attempts permisivo", """
            select profile, resource_name, limit
            from dba_profiles
            where resource_name = 'FAILED_LOGIN_ATTEMPTS'
              and (limit = 'UNLIMITED' or limit = 'DEFAULT' or regexp_like(limit, '^[0-9]+$') and to_number(limit) > 10)
            order by profile
        """)
        security["unlimited_password_life_profiles"] = self._query_rows(connector, "perfiles con password_life_time ilimitado", """
            select profile, resource_name, limit
            from dba_profiles
            where resource_name = 'PASSWORD_LIFE_TIME'
              and limit in ('UNLIMITED','DEFAULT')
            order by profile
        """)
        security["missing_password_verify_profiles"] = self._query_rows(connector, "perfiles sin password_verify_function", """
            select profile, resource_name, limit
            from dba_profiles
            where resource_name = 'PASSWORD_VERIFY_FUNCTION'
              and limit in ('NULL','DEFAULT')
            order by profile
        """)
        security["common_accounts_not_locked_or_expired"] = self._query_rows(connector, "cuentas comunes no bloqueadas", f"""
            select username, account_status, profile, oracle_maintained, common
            from dba_users
            where username in ({default_accounts})
              and account_status not like '%LOCKED%'
            order by username
        """)
        self._set_security_query(security, "oracle_maintained_open_users", connector, "usuarios Oracle-maintained abiertos", """
            select username, account_status, authentication_type, common, oracle_maintained
            from dba_users
            where oracle_maintained = 'Y'
              and username not in ('SYS', 'SYSTEM')
              and account_status = 'OPEN'
            order by username
        """, log_warning=False)
        admin_privilege_columns = self._available_pwfile_admin_columns(connector)
        admin_privilege_select = ", ".join(["username", *admin_privilege_columns])
        admin_privilege_predicate = " or ".join(f"{column.lower()} = 'TRUE'" for column in admin_privilege_columns)
        self._set_security_query(security, "admin_privilege_users", connector, "usuarios con privilegios administrativos especiales", f"""
            select {admin_privilege_select}
            from v$pwfile_users
            where username not in ('SYS', 'SYSTEM')
              and ({admin_privilege_predicate})
            order by username
        """, log_warning=False)
        self._set_security_query(security, "external_authenticated_users", connector, "usuarios con autenticación externa", """
            select username, account_status, authentication_type, external_name, common, oracle_maintained
            from dba_users
            where authentication_type = 'EXTERNAL'
              and username not in ('SYS', 'SYSTEM')
              and nvl(oracle_maintained, 'N') <> 'Y'
            order by username
        """, log_warning=False)
        self._set_security_query(security, "proxy_users_configured", connector, "relaciones de autenticación proxy", """
            select proxy, client, authentication, authorization_constraint, role
            from dba_proxies
            order by proxy, client, role
        """, log_warning=False)
        self._set_security_query(security, "any_privilege_users", connector, "usuarios o roles no esperados con privilegios ANY", """
            select sp.grantee, sp.privilege, sp.admin_option, u.account_status, u.oracle_maintained, u.common, r.oracle_maintained as role_oracle_maintained,
                   case when u.username is not null then 'USER' else 'ROLE' end as grantee_type
            from dba_sys_privs sp
            left join dba_users u on u.username = sp.grantee
            left join dba_roles r on r.role = sp.grantee
            where sp.privilege in (
              'ALTER ANY TABLE','DROP ANY PROCEDURE','CREATE ANY TRIGGER','ALTER ANY TRIGGER','DROP ANY TRIGGER',
              'CREATE ANY SYNONYM','CREATE ANY VIEW','ALTER ANY INDEX','DROP ANY INDEX','UPDATE ANY TABLE','DELETE ANY TABLE',
              'EXECUTE ANY PROCEDURE','ALTER ANY PROCEDURE'
            )
              and sp.grantee not in ('SYS', 'SYSTEM')
              and nvl(u.oracle_maintained, 'N') <> 'Y'
              and nvl(r.oracle_maintained, 'N') <> 'Y'
            order by sp.grantee, sp.privilege
        """, log_warning=False)
        self._set_security_query(security, "admin_option_grants", connector, "privilegios de sistema con admin option", """
            select sp.grantee, sp.privilege, sp.admin_option, u.account_status, u.oracle_maintained, r.oracle_maintained as role_oracle_maintained,
                   case when u.username is not null then 'USER' else 'ROLE' end as grantee_type
            from dba_sys_privs sp
            left join dba_users u on u.username = sp.grantee
            left join dba_roles r on r.role = sp.grantee
            where sp.admin_option = 'YES'
              and sp.grantee not in ('SYS', 'SYSTEM')
              and nvl(u.oracle_maintained, 'N') <> 'Y'
              and nvl(r.oracle_maintained, 'N') <> 'Y'
            order by sp.grantee, sp.privilege
        """, log_warning=False)
        self._set_security_query(security, "grant_option_object_privileges", connector, "privilegios de objeto con grant option", """
            select tp.grantee, tp.owner, tp.table_name, tp.privilege, tp.grantable, tp.type
            from dba_tab_privs tp
            left join dba_users owner_u on owner_u.username = tp.owner
            left join dba_users grantee_u on grantee_u.username = tp.grantee
            where tp.grantable = 'YES'
              and nvl(owner_u.oracle_maintained, 'N') <> 'Y'
              and nvl(grantee_u.oracle_maintained, 'N') <> 'Y'
              and tp.grantee not in ('SYS', 'SYSTEM')
            order by tp.grantee, tp.owner, tp.table_name, tp.privilege
        """, log_warning=False)
        self._set_security_query(security, "legacy_roles_assigned", connector, "roles legacy asignados directamente", """
            select rp.grantee, rp.granted_role, rp.admin_option, rp.default_role, u.account_status, u.oracle_maintained
            from dba_role_privs rp
            left join dba_users u on u.username = rp.grantee
            where rp.granted_role in ('CONNECT', 'RESOURCE')
              and rp.grantee not in ('SYS', 'SYSTEM')
              and nvl(u.oracle_maintained, 'N') <> 'Y'
            order by rp.grantee, rp.granted_role
        """, log_warning=False)
        expected_dictionary_grantees = self._sql_in_list(ORACLE_EXPECTED_DICTIONARY_ACCESS_GRANTEES)
        self._set_security_query(security, "dictionary_access_privileges", connector, "acceso sensible al diccionario", f"""
            select grantee, access_name, option_flag, source
            from (
              select sp.grantee, sp.privilege as access_name, sp.admin_option as option_flag, 'DBA_SYS_PRIVS' as source
              from dba_sys_privs sp
              left join dba_users u on u.username = sp.grantee
              left join dba_roles r on r.role = sp.grantee
              where sp.privilege = 'SELECT ANY DICTIONARY'
                and sp.grantee not in ({expected_dictionary_grantees})
                and nvl(u.oracle_maintained, 'N') <> 'Y'
                and nvl(r.oracle_maintained, 'N') <> 'Y'
              union all
              select rp.grantee, rp.granted_role as access_name, rp.admin_option as option_flag, 'DBA_ROLE_PRIVS' as source
              from dba_role_privs rp
              left join dba_users u on u.username = rp.grantee
              left join dba_roles r on r.role = rp.grantee
              where rp.granted_role in ('SELECT_CATALOG_ROLE', 'EXECUTE_CATALOG_ROLE')
                and rp.grantee not in ({expected_dictionary_grantees})
                and nvl(u.oracle_maintained, 'N') <> 'Y'
                and nvl(r.oracle_maintained, 'N') <> 'Y'
            )
            order by grantee, access_name
        """, log_warning=False)
        self._set_security_query(security, "inactive_users_by_last_login", connector, "usuarios abiertos inactivos por último login", """
            select username, account_status, last_login, authentication_type, common, oracle_maintained
            from dba_users
            where account_status = 'OPEN'
              and username not in ('SYS', 'SYSTEM')
              and nvl(oracle_maintained, 'N') <> 'Y'
              and (last_login is null or last_login < systimestamp - interval '90' day)
            order by username
        """, log_warning=False)
        self._set_security_query(security, "legacy_password_versions", connector, "usuarios con versiones antiguas de contraseña", """
            select username, account_status, password_versions, authentication_type, common, oracle_maintained
            from dba_users
            where password_versions like '%10G%'
              and username not in ('SYS', 'SYSTEM')
              and nvl(oracle_maintained, 'N') <> 'Y'
            order by username
        """, log_warning=False)
        return {"security": security}

    def _available_pwfile_admin_columns(self, connector: Any) -> list[str]:
        candidate_columns = ["SYSDBA", "SYSOPER", "SYSASM", "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC"]
        rows, error = self._query_rows_with_error(connector, "columnas disponibles de V$PWFILE_USERS", """
            select column_name
            from all_tab_columns
            where owner = 'SYS'
              and table_name = 'V_$PWFILE_USERS'
              and column_name in ('SYSDBA','SYSOPER','SYSASM','SYSBACKUP','SYSDG','SYSKM','SYSRAC')
            order by column_id
        """, log_warning=False)
        if not error and rows:
            available = {str(row.get("column_name") or row.get("COLUMN_NAME") or "").upper() for row in rows}
            columns = [column for column in candidate_columns if column in available]
            if columns:
                return columns
        return [column for column in candidate_columns if column != "SYSRAC"]

    def _set_security_query(self, security: dict[str, Any], field: str, connector: Any, label: str, sql: str, log_warning: bool = True) -> None:
        rows, error = self._query_rows_with_error(connector, label, sql, log_warning=log_warning)
        security[field] = rows
        if error:
            security[f"{field}_error"] = error

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


    def _default_oracle_resources_inventory(self, parameters: dict[str, Any] | None = None, healthy_defaults: bool = False) -> dict[str, Any]:
        parameters = parameters if isinstance(parameters, dict) else {}

        def parameter_data(name: str) -> dict[str, Any]:
            data = parameters.get(name.lower(), {}) if isinstance(parameters, dict) else {}
            return data if isinstance(data, dict) else {}

        def parameter_value(name: str) -> Any:
            data = parameter_data(name)
            value = data.get("value")
            if value is None:
                value = data.get("display_value")
            if value is None and healthy_defaults:
                defaults = {
                    "sga_target": 2147483648,
                    "sga_max_size": 2147483648,
                    "memory_target": 0,
                    "memory_max_target": 0,
                    "pga_aggregate_target": 536870912,
                    "pga_aggregate_limit": 2147483648,
                }
                return defaults.get(name)
            return value

        def parameter_display(name: str) -> Any:
            data = parameter_data(name)
            display = data.get("display_value")
            if display is None:
                display = data.get("value")
            if display is None:
                display = parameter_value(name)
            return display

        def memory_parameter(name: str) -> dict[str, Any]:
            value = parameter_value(name)
            display = parameter_display(name)
            normalized_bytes = self._parse_memory_value_bytes(value)
            if normalized_bytes is None:
                normalized_bytes = self._parse_memory_value_bytes(display)
            return {
                name: display,
                f"{name}_value": value,
                f"{name}_bytes": normalized_bytes,
                f"{name}_mb": round(normalized_bytes / 1024 / 1024, 2) if normalized_bytes is not None else None,
            }

        memory_parameters: dict[str, Any] = {}
        for memory_name in (
            "sga_target",
            "sga_max_size",
            "memory_target",
            "memory_max_target",
            "pga_aggregate_target",
            "pga_aggregate_limit",
        ):
            memory_parameters.update(memory_parameter(memory_name))

        return {
            "resource_limits": [
                {"resource_name": "processes", "current_utilization": 50, "max_utilization": 80, "limit_value": 500},
                {"resource_name": "sessions", "current_utilization": 70, "max_utilization": 100, "limit_value": 776},
                {"resource_name": "transactions", "current_utilization": 10, "max_utilization": 20, "limit_value": 854},
            ] if healthy_defaults else [],
            "memory": {
                "parameters": memory_parameters,
                "pga_stats": [
                    {"name": "aggregate PGA target parameter", "value": 536870912, "unit": "bytes"},
                    {"name": "aggregate PGA auto target", "value": 402653184, "unit": "bytes"},
                    {"name": "total PGA allocated", "value": 268435456, "unit": "bytes"},
                    {"name": "total PGA inuse", "value": 134217728, "unit": "bytes"},
                    {"name": "maximum PGA allocated", "value": 402653184, "unit": "bytes"},
                    {"name": "over allocation count", "value": 0, "unit": "count"},
                    {"name": "cache hit percentage", "value": 95, "unit": "percent"},
                ] if healthy_defaults else [],
                "sga_info": [
                    {"name": "Buffer Cache Size", "bytes": 1073741824, "mb": 1024, "resizeable": "Yes"},
                    {"name": "Shared Pool Size", "bytes": 536870912, "mb": 512, "resizeable": "Yes"},
                    {"name": "Large Pool Size", "bytes": 134217728, "mb": 128, "resizeable": "Yes"},
                    {"name": "Java Pool Size", "bytes": 67108864, "mb": 64, "resizeable": "Yes"},
                    {"name": "Streams Pool Size", "bytes": 67108864, "mb": 64, "resizeable": "Yes"},
                    {"name": "Granule Size", "bytes": 16777216, "mb": 16, "resizeable": "No"},
                    {"name": "Maximum SGA Size", "bytes": 2147483648, "mb": 2048, "resizeable": "No"},
                    {"name": "Free SGA Memory Available", "bytes": 268435456, "mb": 256, "resizeable": "No"},
                ] if healthy_defaults else [],
            },
            "sessions": {"blocked_sessions": [], "blocking_sessions": [], "inactive_sessions": []},
            "scheduler_jobs": {"failed_recent": [], "disabled": [], "broken": []},
            "legacy_jobs": {"broken": []},
        }

    def _discover_oracle_resources_inventory(self, connector: Any, parameters: dict[str, Any]) -> dict[str, Any]:
        resources = self._default_oracle_resources_inventory(parameters)
        resources["resource_limits"] = self._query_rows(connector, "límites de recursos Oracle", """
            select resource_name, current_utilization, max_utilization, limit_value
            from v$resource_limit
            where resource_name in ('processes', 'sessions', 'transactions')
            order by resource_name
        """)
        pga_stats = self._query_rows(connector, "estadísticas básicas de PGA", """
            select name, value, unit
            from v$pgastat
            where name in (
              'aggregate PGA target parameter',
              'aggregate PGA auto target',
              'total PGA allocated',
              'total PGA inuse',
              'maximum PGA allocated',
              'over allocation count',
              'cache hit percentage'
            )
        """)
        resources["memory"]["pga_stats"] = pga_stats
        resources["memory"]["sga_info"] = self._query_rows(connector, "información básica de SGA", """
            select name, bytes, round(bytes / 1024 / 1024, 2) as mb, resizeable
            from v$sgainfo
            where name in (
              'Buffer Cache Size',
              'Shared Pool Size',
              'Large Pool Size',
              'Java Pool Size',
              'Streams Pool Size',
              'Granule Size',
              'Maximum SGA Size',
              'Free SGA Memory Available'
            )
            order by name
        """)
        resources["sessions"]["blocked_sessions"] = self._query_rows(connector, "sesiones bloqueadas actuales", """
            select sid, serial#, username, status, event, wait_class, seconds_in_wait,
                   blocking_session, blocking_instance, machine, program, module
            from v$session
            where blocking_session is not null
              and type <> 'BACKGROUND'
            order by seconds_in_wait desc, sid
        """)
        resources["sessions"]["blocking_sessions"] = self._query_rows(connector, "sesiones bloqueadoras actuales", """
            select b.sid as blocker_sid, b.serial# as blocker_serial, b.username as blocker_username,
                   b.status as blocker_status, b.machine, b.program, b.module,
                   count(w.sid) as blocked_count, max(w.seconds_in_wait) as max_seconds_in_wait
            from v$session w
            left join v$session b on b.sid = w.blocking_session
            where w.blocking_session is not null
              and w.type <> 'BACKGROUND'
            group by b.sid, b.serial#, b.username, b.status, b.machine, b.program, b.module
            order by blocked_count desc, max_seconds_in_wait desc
        """)
        resources["sessions"]["inactive_sessions"] = self._query_schema_rows(connector, "sesiones inactivas de aplicación", """
            select s.username, s.machine, s.program, count(*) as inactive_sessions, u.oracle_maintained
            from v$session s
            left join dba_users u on u.username = s.username
            where s.status = 'INACTIVE'
              and s.type <> 'BACKGROUND'
              and s.username is not null
              and nvl(u.oracle_maintained, 'N') = 'N'
            group by s.username, s.machine, s.program, u.oracle_maintained
            order by inactive_sessions desc, s.username, s.machine, s.program
        """, """
            select s.username, s.machine, s.program, count(*) as inactive_sessions, null as oracle_maintained
            from v$session s
            where s.status = 'INACTIVE'
              and s.type <> 'BACKGROUND'
              and s.username is not null
              and s.username not in ({internal_schemas})
            group by s.username, s.machine, s.program
            order by inactive_sessions desc, s.username, s.machine, s.program
        """)
        resources["scheduler_jobs"]["failed_recent"] = self._query_schema_rows(connector, "jobs scheduler fallidos recientes", """
            select r.owner, r.job_name, r.status, r.actual_start_date, r.run_duration, r.error#,
                   substr(r.additional_info, 1, 500) as additional_info, u.oracle_maintained
            from dba_scheduler_job_run_details r
            left join dba_users u on u.username = r.owner
            where r.actual_start_date >= systimestamp - interval '7' day
              and r.status in ('FAILED', 'STOPPED', 'BROKEN')
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by r.actual_start_date desc
        """, """
            select r.owner, r.job_name, r.status, r.actual_start_date, r.run_duration, r.error#,
                   substr(r.additional_info, 1, 500) as additional_info, null as oracle_maintained
            from dba_scheduler_job_run_details r
            where r.actual_start_date >= systimestamp - interval '7' day
              and r.status in ('FAILED', 'STOPPED', 'BROKEN')
              and r.owner not in ({internal_schemas})
            order by r.actual_start_date desc
        """)
        resources["scheduler_jobs"]["disabled"] = self._query_schema_rows(connector, "jobs scheduler deshabilitados", """
            select j.owner, j.job_name, j.job_type, j.enabled, j.state, j.schedule_type,
                   j.repeat_interval, j.last_start_date, j.next_run_date, u.oracle_maintained
            from dba_scheduler_jobs j
            left join dba_users u on u.username = j.owner
            where j.enabled = 'FALSE'
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by j.owner, j.job_name
        """, """
            select j.owner, j.job_name, j.job_type, j.enabled, j.state, j.schedule_type,
                   j.repeat_interval, j.last_start_date, j.next_run_date, null as oracle_maintained
            from dba_scheduler_jobs j
            where j.enabled = 'FALSE'
              and j.owner not in ({internal_schemas})
            order by j.owner, j.job_name
        """)
        resources["scheduler_jobs"]["broken"] = self._query_schema_rows(connector, "jobs scheduler en estado problemático", """
            select j.owner, j.job_name, j.state, j.failure_count, j.retry_count,
                   j.last_start_date, j.next_run_date, u.oracle_maintained
            from dba_scheduler_jobs j
            left join dba_users u on u.username = j.owner
            where j.state in ('BROKEN', 'FAILED', 'RETRY SCHEDULED', 'CHAIN_STALLED')
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by j.owner, j.job_name
        """, """
            select j.owner, j.job_name, j.state, j.failure_count, j.retry_count,
                   j.last_start_date, j.next_run_date, null as oracle_maintained
            from dba_scheduler_jobs j
            where j.state in ('BROKEN', 'FAILED', 'RETRY SCHEDULED', 'CHAIN_STALLED')
              and j.owner not in ({internal_schemas})
            order by j.owner, j.job_name
        """)
        resources["legacy_jobs"]["broken"] = self._query_schema_rows(connector, "jobs legacy DBMS_JOB rotos", """
            select j.schema_user, j.job, j.broken, j.failures, j.last_date, j.next_date,
                   substr(j.what, 1, 500) as what, u.oracle_maintained
            from dba_jobs j
            left join dba_users u on u.username = j.schema_user
            where j.broken = 'Y'
              and nvl(u.oracle_maintained, 'N') = 'N'
            order by j.schema_user, j.job
        """, """
            select j.schema_user, j.job, j.broken, j.failures, j.last_date, j.next_date,
                   substr(j.what, 1, 500) as what, null as oracle_maintained
            from dba_jobs j
            where j.broken = 'Y'
              and j.schema_user not in ({internal_schemas})
            order by j.schema_user, j.job
        """)
        return {"oracle_resources": resources}



    def _default_performance_inventory(self) -> dict[str, Any]:
        return {
            "instance_uptime": {"startup_time": None, "current_time": None, "uptime_days": None, "uptime_hours": None},
            "active_user_sessions": [],
            "wait_sessions": [],
            "long_operations": [],
            "sysstat": {"parse_total": 0, "parse_hard": 0},
            "library_cache": [],
            "sql_current_activity": [],
        }

    def _discover_performance_inventory(self, connector: Any) -> dict[str, Any]:
        perf = self._default_performance_inventory()
        perf["instance_uptime"] = self._query_one(connector, "uptime actual de instancia", """
            select startup_time,
                   sysdate as current_time,
                   round(sysdate - startup_time, 4) as uptime_days,
                   round((sysdate - startup_time) * 24, 2) as uptime_hours
            from v$instance
        """)
        perf["active_user_sessions"] = self._query_rows(connector, "sesiones de usuario activas actuales", """
            select sid, serial#, username, status, wait_class, event, sql_id, module, machine, program
            from v$session
            where type = 'USER'
              and status = 'ACTIVE'
            order by sid
        """)
        perf["wait_sessions"] = self._query_rows(connector, "esperas no idle actuales por sesión", """
            select sid, serial#, username, status, wait_class, event, seconds_in_wait, state,
                   sql_id, module, machine, program
            from v$session
            where type = 'USER'
              and wait_class is not null
              and wait_class <> 'Idle'
            order by seconds_in_wait desc, sid
        """)
        perf["long_operations"] = self._query_rows(connector, "operaciones largas activas", """
            select sid, serial#, opname, target, sofar, totalwork, units,
                   elapsed_seconds, time_remaining, sql_id
            from v$session_longops
            where time_remaining > 0
            order by time_remaining desc, elapsed_seconds desc
        """)
        stats = self._query_rows(connector, "parse count total/hard", """
            select name, value
            from v$sysstat
            where name in ('parse count (total)', 'parse count (hard)')
        """)
        perf["sysstat"] = {
            "parse_total": next((r.get("value") for r in stats if str(r.get("name", "")).lower() == "parse count (total)"), 0),
            "parse_hard": next((r.get("value") for r in stats if str(r.get("name", "")).lower() == "parse count (hard)"), 0),
        }
        perf["library_cache"] = self._query_rows(connector, "library cache básico", """
            select namespace, gets, gethits, pins, pinhits, reloads, invalidations
            from v$librarycache
            order by namespace
        """)
        perf["sql_current_activity"] = self._query_rows(connector, "SQL actualmente activo", """
            select s.sid, s.serial#, s.username, s.sql_id, s.sql_child_number, s.status,
                   s.wait_class, s.event, s.module, s.machine, s.program,
                   substr(q.sql_text, 1, 200) as sql_text_sample
            from v$session s
            left join v$sql q on q.sql_id = s.sql_id and q.child_number = s.sql_child_number
            where s.type = 'USER'
              and s.status = 'ACTIVE'
              and s.sql_id is not null
            order by s.sid
        """)
        return {"performance": perf}


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

    def _is_recent_datetime(self, value: Any, days: int) -> bool:
        if value is None:
            return False
        try:
            from datetime import datetime, timedelta
            if isinstance(value, datetime):
                return value >= datetime.now(value.tzinfo) - timedelta(days=days)
            text = str(value).strip()
            candidates = (text[:19].replace("T", " "), text[:10])
            for candidate, fmt in ((candidates[0], "%Y-%m-%d %H:%M:%S"), (candidates[1], "%Y-%m-%d")):
                try:
                    parsed = datetime.strptime(candidate, fmt)
                    return parsed >= datetime.now() - timedelta(days=days)
                except ValueError:
                    continue
        except Exception:
            return False
        return False

    def _bytes_to_mb(self, value: Any) -> float | None:
        raw = self._safe_float(value)
        return round(raw / 1024 / 1024, 2) if raw is not None else None

    def _parameter_value(self, parameters: dict[str, Any], name: str) -> Any:
        data = parameters.get(name.lower(), {}) if isinstance(parameters, dict) else {}
        if not isinstance(data, dict):
            return None
        return data.get("display_value", data.get("value"))

    def _query_one(self, connector: Any, label: str, sql: str) -> dict[str, Any]:
        rows = self._query_rows(connector, label, sql)
        return rows[0] if rows else {}

    def _query_rows(self, connector: Any, label: str, sql: str) -> list[dict[str, Any]]:
        rows, _ = self._query_rows_with_error(connector, label, sql)
        return rows

    def _query_rows_with_error(self, connector: Any, label: str, sql: str, log_warning: bool = True) -> tuple[list[dict[str, Any]], str | None]:
        try:
            rows = connector.query(sql)
        except Exception as exc:
            if log_warning:
                logging.warning("Oracle inventory query failed for %s: %s", label, exc)
            return [], str(exc)
        return [
            {key: self._normalize_inventory_value(value) for key, value in dict(row).items()}
            for row in rows
        ], None

    def _normalize_inventory_value(self, value: Any) -> Any:
        if isinstance(value, Decimal):
            return int(value) if value == value.to_integral_value() else float(value)
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        return value

    def _resolve_checks(self, profile: Any) -> list[Check]:
        policies = self._resolve_policies(profile)
        checks: list[Check] = []
        for group_id in profile.enabled_groups:
            if group_id in profile.disabled_groups:
                continue
            group = self.config["groups"][group_id]
            for check_id in group.checks:
                if check_id not in profile.disabled_checks:
                    check = copy.deepcopy(self.config["checks"][check_id])
                    self._apply_policy_values(check, policies)
                    checks.append(check)
        return checks

    def _resolve_policies(self, profile: Any) -> dict[str, Any]:
        policies: dict[str, Any] = {}
        for standard_id in profile.standards:
            standard = self.config.get("standards", {}).get(standard_id)
            if standard:
                policies.update(standard.policies)
        policies.update(profile.overrides.get("policies", {}))
        return policies

    def _apply_policy_values(self, check: Check, policies: dict[str, Any]) -> None:
        for section_name in ("collector", "evaluator"):
            section = getattr(check, section_name)
            for field_name, policy_name in list(section.items()):
                if field_name.endswith("_policy") and policy_name in policies:
                    section[field_name.removesuffix("_policy")] = policies[policy_name]

    def _run_check(self, check: Check, target: Target, inventory: Inventory) -> Result:
        start = time.monotonic()
        logging.info("Check %s started", check.check_id)
        applicable, reason = self.applicability.evaluate(check, target, inventory)
        if check.check_id in ("fra_usage", "fra_usage_pct") and inventory.database.get("fra_configured") is False:
            duration_ms = int((time.monotonic() - start) * 1000)
            message = inventory.database.get("fra_message", "FRA no está configurada")
            logging.info("Check %s skipped: %s duration_ms=%s", check.check_id, message, duration_ms)
            return Result(
                check_id=check.check_id,
                group_id=check.group_id,
                status=ResultStatus.SKIPPED,
                title=check.title,
                failure_severity=check.failure_severity,
                message=message,
                evidence={"fra_configured": False},
                remediation=check.remediation,
                skipped_reason=message,
                duration_ms=duration_ms,
            )
        if not applicable:
            duration_ms = int((time.monotonic() - start) * 1000)
            logging.info("Check %s skipped: %s duration_ms=%s", check.check_id, reason, duration_ms)
            evidence = None
            required_feature = (check.applicability or {}).get("requires_feature")
            if required_feature:
                feature = inventory.features.get(required_feature, {}) if isinstance(inventory.features, dict) else {}
                evidence = {
                    "required_feature": required_feature,
                    "feature_detected": feature.get("detected") if isinstance(feature, dict) else None,
                    "feature_status": feature.get("status") if isinstance(feature, dict) else "missing",
                    "feature_reason": feature.get("reason") if isinstance(feature, dict) else "La característica requerida no existe en el inventario.",
                }
            return Result(
                check_id=check.check_id,
                group_id=check.group_id,
                status=ResultStatus.SKIPPED,
                title=check.title,
                failure_severity=check.failure_severity,
                message="La validación no aplica para este target." if required_feature else None,
                evidence=evidence,
                skipped_reason=reason,
                duration_ms=duration_ms,
            )
        try:
            evidence = self._collect(check, inventory)
            evaluator_type = check.evaluator.get("type", "expected_value")
            evaluator_config = dict(check.evaluator)
            if evaluator_type == "threshold" and "field" not in evaluator_config and check.collector.get("field"):
                evaluator_config["field"] = check.collector["field"]
                evidence = {check.collector["field"]: evidence}
            status, message = EVALUATORS[evaluator_type].evaluate(evidence, evaluator_config)
            duration_ms = int((time.monotonic() - start) * 1000)
            logging.info("Check %s finished with status=%s duration_ms=%s", check.check_id, status.value, duration_ms)
            return Result(
                check_id=check.check_id,
                group_id=check.group_id,
                status=status,
                title=check.title,
                failure_severity=check.failure_severity,
                message=message,
                evidence=mask_secrets(evidence),
                remediation=check.remediation,
                duration_ms=duration_ms,
            )
        except Exception as exc:  # technical execution errors become ERROR by design
            duration_ms = int((time.monotonic() - start) * 1000)
            logging.error("Technical error running check %s duration_ms=%s error=%s", check.check_id, duration_ms, exc)
            return Result(
                check_id=check.check_id,
                group_id=check.group_id,
                status=ResultStatus.ERROR,
                title=check.title,
                failure_severity=check.failure_severity,
                message="Error técnico de ejecución",
                error=str(exc),
                duration_ms=duration_ms,
            )

    def _collect(self, check: Check, inventory: Inventory) -> Any:
        collector = check.collector
        ctype = collector.get("type", "inventory")
        if ctype == "alert_log_family":
            return self._build_alert_log_evidence(check, inventory.database)
        if ctype == "inventory":
            source = collector.get("source", "database")
            field = collector.get("field")
            data = inventory.database if source == "database" else inventory.operating_system if source == "operating_system" else inventory.features
            return data.get(field) if field else data
        if ctype == "oracle_parameter":
            parameter = collector["parameter"].lower()
            parameters = inventory.database.get("parameters", {})
            parameter_data = parameters.get(parameter, {}) if isinstance(parameters, dict) else {}
            actual = parameter_data.get("display_value", parameter_data.get("value")) if isinstance(parameter_data, dict) else None
            return self._build_oracle_config_evidence(check, parameter, actual, "v$parameter", exists=bool(parameter_data))
        if ctype == "oracle_storage":
            return self._build_storage_evidence(check, inventory.database)
        if ctype == "oracle_security":
            return self._build_security_evidence(check, inventory.database)
        if ctype == "oracle_resources":
            return self._build_oracle_resources_evidence(check, inventory.database)
        if ctype == "performance":
            return self._build_performance_evidence(check, inventory.database)
        if ctype == "capacity":
            return self._build_capacity_evidence(check, inventory.database)
        if ctype == "asm":
            return self._build_asm_evidence(check, inventory.database)
        if ctype == "dataguard":
            return self._build_dataguard_evidence(check, inventory.database)
        if ctype == "oracle_schema_objects":
            return self._build_schema_objects_evidence(check, inventory.database)
        if ctype == "io_redo_archive":
            return self._build_io_redo_archive_evidence(check, inventory.database)
        if ctype == "recoverability_drp":
            return self._build_recoverability_drp_evidence(check, inventory.database)
        if ctype == "rac":
            return self._build_rac_evidence(check, inventory.database)
        if ctype == "multitenant":
            return self._build_multitenant_evidence(check, inventory.database)
        if ctype == "oracle_metric":
            field = collector["field"]
            return self._build_oracle_config_evidence(
                check,
                collector.get("label", field),
                inventory.database.get(field),
                collector.get("source_view", "inventory"),
                extra={key: inventory.database.get(key) for key in collector.get("include_fields", [])},
            )
        if ctype == "static":
            return collector.get("value")
        if ctype == "os_adapter":
            adapter = LinuxAdapter(LocalConnector()) if inventory.operating_system.get("platform") == "linux" else AIXAdapter(LocalConnector())
            return getattr(adapter, collector["method"])()
        raise ValueError(f"Tipo de colector no soportado: {ctype}")




    def _build_performance_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        perf = database.get("performance") if isinstance(database.get("performance"), dict) else self._default_performance_inventory()
        check_id = check.check_id
        thresholds = {k: v for k, v in check.evaluator.items() if k not in {"type", "metric"} and not k.endswith("_policy")}
        evidence: dict[str, Any] = {
            "metric": check_id,
            "label": check.collector.get("label", check.title),
            "source": check.collector.get("source_view", "inventario performance"),
            "scope_note": "Fotografía actual sin repositorios históricos licenciados; los segundos observados no son DB Time histórico.",
        }
        evidence.update(thresholds)
        max_rows = int(check.evaluator.get("max_rows", check.collector.get("max_rows", 20)) or 20)
        if check_id == "performance_instance_uptime":
            evidence.update(perf.get("instance_uptime") if isinstance(perf.get("instance_uptime"), dict) else {})
            return evidence
        if check_id == "performance_active_user_sessions":
            rows = perf.get("active_user_sessions") if isinstance(perf.get("active_user_sessions"), list) else []
            evidence.update({"active_user_sessions": len(rows), "sample_sessions": rows[:max_rows]})
            return evidence
        if check_id == "performance_wait_class_snapshot":
            rows = self._performance_wait_rows(perf, exclude=check.evaluator.get("exclude_wait_classes", ["Idle"]), max_rows=max_rows)
            evidence.update({"rows": rows, "affected_count": sum(int(r.get("session_count") or 0) for r in rows)})
            return evidence
        if check_id == "performance_current_event_summary":
            rows = self._performance_event_rows(perf, exclude=check.evaluator.get("exclude_wait_classes", ["Idle"]), max_rows=max_rows)
            evidence.update({"rows": rows, "affected_count": sum(int(r.get("session_count") or 0) for r in rows), "future_note": "Thresholds específicos por EVENT pueden agregarse en una fase futura."})
            return evidence
        if check_id == "performance_non_idle_wait_sessions":
            rows = self._filtered_wait_sessions(perf, check.evaluator.get("exclude_wait_classes", ["Idle"]))
            evidence.update({"rows": rows[:max_rows], "affected_count": len(rows), "filters": ["TYPE = 'USER'", "WAIT_CLASS IS NOT NULL", "WAIT_CLASS <> 'Idle'"]})
            return evidence
        if check_id == "performance_long_operations_active":
            rows = perf.get("long_operations") if isinstance(perf.get("long_operations"), list) else []
            max_remaining = max([self._safe_float(r.get("time_remaining")) or 0 for r in rows], default=0)
            evidence.update({"rows": rows[:max_rows], "affected_count": len(rows), "max_time_remaining": max_remaining})
            return evidence
        if check_id == "performance_parse_ratio_basic":
            stats = perf.get("sysstat") if isinstance(perf.get("sysstat"), dict) else {}
            total = self._safe_float(stats.get("parse_total")) or 0
            hard = self._safe_float(stats.get("parse_hard")) or 0
            evidence.update({"parse_total": total, "parse_hard": hard, "hard_parse_pct": round((hard / total) * 100, 2) if total > 0 else None, "interpretation_note": "Métrica acumulada desde startup; interpretar junto con performance_instance_uptime."})
            return evidence
        if check_id == "performance_library_cache_hit_ratio":
            rows = perf.get("library_cache") if isinstance(perf.get("library_cache"), list) else []
            gets = sum(self._safe_float(r.get("gets")) or 0 for r in rows)
            gethits = sum(self._safe_float(r.get("gethits")) or 0 for r in rows)
            pins = sum(self._safe_float(r.get("pins")) or 0 for r in rows)
            pinhits = sum(self._safe_float(r.get("pinhits")) or 0 for r in rows)
            evidence.update({"rows": rows[:max_rows], "gets": gets, "gethits": gethits, "pins": pins, "pinhits": pinhits, "reloads": sum(self._safe_float(r.get("reloads")) or 0 for r in rows), "invalidations": sum(self._safe_float(r.get("invalidations")) or 0 for r in rows), "get_hit_pct": round((gethits / gets) * 100, 2) if gets > 0 else None, "pin_hit_pct": round((pinhits / pins) * 100, 2) if pins > 0 else None})
            return evidence
        if check_id == "performance_sql_current_activity":
            rows = perf.get("sql_current_activity") if isinstance(perf.get("sql_current_activity"), list) else []
            evidence.update({"rows": rows[:max_rows], "affected_count": len(rows), "privacy_note": "SQL_TEXT se trunca a 200 caracteres y no representa top SQL histórico."})
            return evidence
        return evidence

    def _filtered_wait_sessions(self, perf: dict[str, Any], exclude: Any) -> list[dict[str, Any]]:
        rows = perf.get("wait_sessions") if isinstance(perf.get("wait_sessions"), list) else []
        excluded = {str(x) for x in (exclude if isinstance(exclude, list) else ["Idle"])}
        return [r for r in rows if r.get("wait_class") and str(r.get("wait_class")) not in excluded]

    def _performance_wait_rows(self, perf: dict[str, Any], exclude: Any, max_rows: int) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in self._filtered_wait_sessions(perf, exclude):
            grouped.setdefault(str(row.get("wait_class") or "Other"), []).append(row)
        result = []
        for wait_class, rows in grouped.items():
            events: dict[str, int] = {}
            for row in rows:
                events[str(row.get("event") or "UNKNOWN")] = events.get(str(row.get("event") or "UNKNOWN"), 0) + 1
            result.append({"wait_class": wait_class, "session_count": len(rows), "total_observed_wait_seconds": sum(self._safe_float(r.get("seconds_in_wait")) or 0 for r in rows), "max_wait_seconds": max([self._safe_float(r.get("seconds_in_wait")) or 0 for r in rows], default=0), "top_events": [{"event": k, "session_count": v} for k, v in sorted(events.items(), key=lambda i: i[1], reverse=True)[:5]], "sample_sessions": rows[:max_rows]})
        return sorted(result, key=lambda r: (r["session_count"], r["total_observed_wait_seconds"]), reverse=True)

    def _performance_event_rows(self, perf: dict[str, Any], exclude: Any, max_rows: int) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in self._filtered_wait_sessions(perf, exclude):
            grouped.setdefault((str(row.get("wait_class") or "Other"), str(row.get("event") or "UNKNOWN")), []).append(row)
        result = []
        for (wait_class, event), rows in grouped.items():
            result.append({"wait_class": wait_class, "event": event, "session_count": len(rows), "total_observed_wait_seconds": sum(self._safe_float(r.get("seconds_in_wait")) or 0 for r in rows), "max_wait_seconds": max([self._safe_float(r.get("seconds_in_wait")) or 0 for r in rows], default=0), "sample_sql_ids": sorted({str(r.get("sql_id")) for r in rows if r.get("sql_id")})[:max_rows], "sample_modules": sorted({str(r.get("module")) for r in rows if r.get("module")})[:max_rows]})
        return sorted(result, key=lambda r: (r["session_count"], r["total_observed_wait_seconds"]), reverse=True)

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
        return evidence

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

    def _bytes_to_mb(self, value: Any) -> float | None:
        num = self._safe_float(value)
        return round(num / 1024 / 1024, 2) if num else None

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


    def _build_alert_log_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        collector = check.collector
        alert_log = database.get("alert_log") if isinstance(database.get("alert_log"), dict) else self._default_alert_log_inventory(database)
        if alert_log.get("available") is False:
            return {
                "available": False,
                "status": alert_log.get("status", "skipped"),
                "source": alert_log.get("source", "sin_acceso"),
                "path": alert_log.get("path"),
                "candidate_path": alert_log.get("candidate_path"),
                "diag_alert_error": alert_log.get("diag_alert_error"),
                "read_error": alert_log.get("read_error"),
                "message": alert_log.get("message"),
            }

        events = alert_log.get("events") or []
        patterns = collector.get("patterns", [])
        max_samples = int(collector.get("max_samples", 5) or 5)
        matches: list[dict[str, Any]] = []
        counts_by_pattern: dict[str, int] = {str(pattern): 0 for pattern in patterns}
        counts_by_family = {
            "internos": 0,
            "memoria": 0,
            "espacio": 0,
            "undo_snapshot": 0,
            "corrupcion_recovery": 0,
            "redo_archive": 0,
            "texto_standby": 0,
            "asm_storage": 0,
        }

        family_patterns = {
            "internos": [r"ORA-00600", r"ORA-07445"],
            "memoria": [r"ORA-04031", r"ORA-04030"],
            "espacio": [r"ORA-00257", r"ORA-01652", r"ORA-01653", r"ORA-01654"],
            "undo_snapshot": [r"ORA-01555"],
            "corrupcion_recovery": [r"ORA-01578", r"ORA-01110", r"block corruption", r"media corruption", r"corrupt block", r"DBVERIFY"],
            "redo_archive": [r"archive error", r"archiver error", r"\bARC[0-9A-Z]*\b", r"\bLGWR\b", r"checkpoint not complete", r"redo log error", r"log file switch", r"cannot allocate new log"],
            "texto_standby": [r"standby", r"\bMRP[0-9A-Z]*\b", r"\bRFS[0-9A-Z]*\b", r"\bFAL\b"],
            "asm_storage": [r"ASM", r"diskgroup", r"I/O error"],
        }

        for index, event in enumerate(events, start=1):
            text = str(event.get("message_text") or "") if isinstance(event, dict) else str(event)
            for pattern in patterns:
                pattern_text = str(pattern)
                if re.search(pattern_text, text, re.IGNORECASE):
                    counts_by_pattern[pattern_text] = counts_by_pattern.get(pattern_text, 0) + 1
                    if len(matches) < max_samples:
                        matches.append({
                            "linea": index,
                            "timestamp": event.get("timestamp") if isinstance(event, dict) else None,
                            "patron": pattern_text,
                            "texto": text.strip(),
                            "filename": event.get("filename") if isinstance(event, dict) else None,
                            "source": event.get("source", alert_log.get("source")) if isinstance(event, dict) else alert_log.get("source"),
                        })
            if collector.get("summary"):
                for family, family_regexes in family_patterns.items():
                    if any(re.search(family_pattern, text, re.IGNORECASE) for family_pattern in family_regexes):
                        counts_by_family[family] += 1

        occurrences = sum(counts_by_pattern.values())
        truncated = occurrences > len(matches)
        message = (
            f"Se detectaron {occurrences} ocurrencias en el alert log dentro de la muestra evaluada"
            if occurrences else
            collector.get("no_match_message", "No se encontraron patrones de esta familia en el alert log dentro de la muestra evaluada.")
        )
        evidence: dict[str, Any] = {
            "available": True,
            "source": alert_log.get("source"),
            "path": alert_log.get("path"),
            "lookback_hours": alert_log.get("lookback_hours"),
            "family": collector.get("family", check.check_id),
            "occurrences": occurrences,
            "patterns": patterns,
            "counts_by_pattern": counts_by_pattern,
            "sample_lines": matches,
            "sample_limit": max_samples,
            "truncated": truncated,
            "message": message,
            "scope_note": "Se analiza la muestra de alert log disponible mediante V$DIAG_ALERT_EXT o archivo físico; una correlación avanzada de ADR queda fuera de esta fase.",
        }
        if collector.get("summary"):
            evidence["counts_by_family"] = counts_by_family
            evidence["standby_note"] = "Se reportan solo coincidencias textuales con procesos o términos de standby; este check no evalúa la salud de Data Guard."
        return evidence

    def _build_oracle_resources_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        resources = database.get("oracle_resources") if isinstance(database.get("oracle_resources"), dict) else self._default_oracle_resources_inventory(database.get("parameters", {}))
        check_id = check.check_id
        thresholds = {k: v for k, v in check.evaluator.items() if k not in {"type"}}
        evidence: dict[str, Any] = {"metric": check_id, "label": check.collector.get("label", check.title), "source": check.collector.get("source_view", "inventario de recursos Oracle")}
        evidence.update(thresholds)
        if check_id in {"processes_usage_pct", "sessions_usage_pct", "transactions_usage_pct"}:
            resource_name = check.collector.get("resource_name", check_id.replace("_usage_pct", ""))
            rows = resources.get("resource_limits") or []
            row = next((item for item in rows if str(item.get("resource_name", "")).lower() == resource_name), None)
            evidence.update({"resource_name": resource_name, "exists": bool(row)})
            if row:
                limit_value = row.get("limit_value")
                limit_numeric = self._safe_float(limit_value)
                current = self._safe_float(row.get("current_utilization"))
                used_pct = round((current / limit_numeric) * 100, 2) if current is not None and limit_numeric and limit_numeric > 0 else None
                evidence.update({
                    "current_utilization": row.get("current_utilization"),
                    "max_utilization": row.get("max_utilization"),
                    "limit_value": limit_value,
                    "limit_numeric": limit_numeric is not None and limit_numeric > 0,
                    "used_pct": used_pct,
                })
            return evidence
        memory = resources.get("memory") if isinstance(resources.get("memory"), dict) else {}
        params = memory.get("parameters") if isinstance(memory.get("parameters"), dict) else {}
        if check_id == "sga_target_configured":
            sga_target_bytes = self._parse_memory_value_bytes(params.get("sga_target_bytes", params.get("sga_target_value", params.get("sga_target")))) or 0
            memory_target_bytes = self._parse_memory_value_bytes(params.get("memory_target_bytes", params.get("memory_target_value", params.get("memory_target")))) or 0
            mode = "AMM" if memory_target_bytes > 0 else "ASMM" if sga_target_bytes > 0 else "MANUAL"
            evidence.update({
                "source": "v$parameter",
                "sga_target": params.get("sga_target"),
                "sga_target_value": params.get("sga_target_value"),
                "sga_target_bytes": sga_target_bytes,
                "sga_target_mb": round(sga_target_bytes / 1024 / 1024, 2) if sga_target_bytes is not None else None,
                "sga_max_size": params.get("sga_max_size"),
                "sga_max_size_value": params.get("sga_max_size_value"),
                "sga_max_size_bytes": params.get("sga_max_size_bytes"),
                "sga_max_size_mb": params.get("sga_max_size_mb"),
                "memory_target": params.get("memory_target"),
                "memory_target_value": params.get("memory_target_value"),
                "memory_target_bytes": memory_target_bytes,
                "memory_target_mb": round(memory_target_bytes / 1024 / 1024, 2) if memory_target_bytes is not None else None,
                "memory_max_target": params.get("memory_max_target"),
                "memory_max_target_value": params.get("memory_max_target_value"),
                "memory_max_target_bytes": params.get("memory_max_target_bytes"),
                "memory_max_target_mb": params.get("memory_max_target_mb"),
                "management_mode": mode,
            })
            return evidence
        if check_id in {"pga_aggregate_target_configured", "pga_aggregate_limit_configured"}:
            parameter = check_id.replace("_configured", "")
            raw_value = params.get(f"{parameter}_value", params.get(parameter))
            normalized_bytes = self._parse_memory_value_bytes(params.get(f"{parameter}_bytes", raw_value))
            if normalized_bytes is None:
                normalized_bytes = self._parse_memory_value_bytes(params.get(parameter))
            evidence.update({
                "source": "v$parameter",
                "exists": parameter in params and params.get(parameter) is not None,
                parameter: params.get(parameter),
                f"{parameter}_display": params.get(parameter),
                f"{parameter}_value": raw_value,
                f"{parameter}_bytes": normalized_bytes,
                f"{parameter}_mb": round(normalized_bytes / 1024 / 1024, 2) if normalized_bytes is not None else None,
            })
            return evidence
        if check_id == "pga_memory_usage_info":
            stats = memory.get("pga_stats") or []
            by_name = {str(row.get("name", "")).lower(): row.get("value") for row in stats if isinstance(row, dict)}
            bytes_to_mb = {
                "aggregate PGA target parameter": "aggregate_pga_target_parameter_mb",
                "aggregate PGA auto target": "aggregate_pga_auto_target_mb",
                "total PGA allocated": "total_pga_allocated_mb",
                "total PGA inuse": "total_pga_inuse_mb",
                "maximum PGA allocated": "maximum_pga_allocated_mb",
            }
            for name, field in bytes_to_mb.items():
                value = self._safe_float(by_name.get(name.lower()))
                evidence[field] = round(value / 1024 / 1024, 2) if value is not None else None
            evidence["over_allocation_count"] = by_name.get("over allocation count")
            evidence["cache_hit_percentage"] = by_name.get("cache hit percentage")
            evidence["rows"] = stats
            return evidence
        if check_id == "sga_memory_info":
            rows = memory.get("sga_info") or []
            normalized = []
            max_sga = None
            free_sga = None
            for row in rows:
                item = dict(row)
                value = self._safe_float(item.get("mb"))
                if value is None:
                    bytes_value = self._safe_float(item.get("bytes"))
                    value = round(bytes_value / 1024 / 1024, 2) if bytes_value is not None else None
                    item["mb"] = value
                if item.get("name") == "Maximum SGA Size":
                    max_sga = value
                if item.get("name") == "Free SGA Memory Available":
                    free_sga = value
                normalized.append(item)
            evidence["rows"] = normalized
            evidence["free_sga_memory_mb"] = free_sga
            evidence["maximum_sga_size_mb"] = max_sga
            evidence["free_sga_memory_pct"] = round((free_sga / max_sga) * 100, 2) if free_sga is not None and max_sga else None
            return evidence
        sessions = resources.get("sessions") if isinstance(resources.get("sessions"), dict) else {}
        if check_id == "blocked_sessions_basic":
            rows = sessions.get("blocked_sessions") or []
            evidence.update({"affected_count": len(rows), "rows": rows, "thresholds": thresholds, "max_seconds_in_wait": max([float(row.get("seconds_in_wait") or 0) for row in rows], default=0)})
            return evidence
        if check_id == "blocking_sessions_basic":
            rows = sessions.get("blocking_sessions") or []
            evidence.update({"affected_count": len(rows), "rows": rows, "thresholds": thresholds})
            return evidence
        if check_id == "inactive_sessions_high":
            rows = sessions.get("inactive_sessions") or []
            total = sum(int(row.get("inactive_sessions") or 0) for row in rows if isinstance(row, dict))
            evidence.update({"total_inactive_sessions": total, "affected_count": total, "rows": rows, "thresholds": thresholds})
            return evidence
        scheduler = resources.get("scheduler_jobs") if isinstance(resources.get("scheduler_jobs"), dict) else {}
        legacy = resources.get("legacy_jobs") if isinstance(resources.get("legacy_jobs"), dict) else {}
        field_map = {
            "scheduler_failed_jobs_recent": (scheduler.get("failed_recent") or [], {"lookback_days": check.evaluator.get("lookback_days", 7)}),
            "scheduler_disabled_jobs": (scheduler.get("disabled") or [], {}),
            "scheduler_broken_jobs": (scheduler.get("broken") or [], {}),
            "legacy_dba_jobs_broken": (legacy.get("broken") or [], {}),
        }
        rows, extra = field_map.get(check_id, ([], {}))
        evidence.update({"affected_count": len(rows), "rows": rows})
        evidence.update(extra)
        return evidence


    def _parse_memory_value_bytes(self, value: Any) -> float | None:
        parsed = OracleResourcesEvaluator()._memory_value_bytes(value)
        return parsed if parsed is not None else self._safe_float(value)

    def _safe_float(self, value: Any) -> float | None:
        try:
            if value is None:
                return None
            if isinstance(value, str):
                cleaned = value.strip().replace(",", "")
                if not cleaned or cleaned.upper() == "UNLIMITED":
                    return None
                return float(cleaned)
            return float(value)
        except (TypeError, ValueError):
            return None

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

    def _build_schema_objects_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        schema_objects = database.get("schema_objects") if isinstance(database.get("schema_objects"), dict) else {}
        field = check.collector.get("field", check.check_id)
        rows = schema_objects.get(field, [])
        if rows is None:
            rows = []
        original_rows = rows if isinstance(rows, list) else [rows]
        filtered_rows = self._filter_oracle_maintained_schema_rows(original_rows)
        if check.check_id == "indexes_too_many_columns":
            max_columns = int(check.evaluator.get("warning", check.evaluator.get("max_columns", 8)) or 8)
            filtered_rows = [row for row in filtered_rows if isinstance(row, dict) and int(row.get("column_count") or 0) > max_columns]
        evidence = {
            "metric": check.check_id,
            "label": check.collector.get("label", check.title),
            "source": check.collector.get("source_view", "inventario de esquemas y objetos Oracle"),
            "affected_count": len(filtered_rows),
            "rows": filtered_rows,
        }
        if check.check_id == "indexes_too_many_columns":
            evidence["max_columns"] = int(check.evaluator.get("warning", check.evaluator.get("max_columns", 8)) or 8)
        if check.check_id == "recyclebin_objects":
            evidence["total_mb"] = round(sum(float(row.get("space_mb") or 0) for row in filtered_rows if isinstance(row, dict)), 2)
        if filtered_rows != original_rows:
            evidence["inventory_count"] = len(original_rows)
            evidence["excluded_count"] = len(original_rows) - len(filtered_rows)
            evidence["classification_note"] = "Se excluyeron objetos de usuarios mantenidos por Oracle del hallazgo principal."
        if field not in schema_objects and check.collector.get("missing_status"):
            evidence["collection_error"] = f"No se encontró la sección {field} en el inventario de esquemas y objetos"
        return evidence

    def _filter_oracle_maintained_schema_rows(self, rows: list[Any]) -> list[Any]:
        filtered = []
        for row in rows:
            if not isinstance(row, dict):
                filtered.append(row)
                continue
            oracle_maintained = str(row.get("oracle_maintained", "")).upper() == "Y"
            owner = str(row.get("owner", row.get("username", row.get("table_owner", "")))).upper()
            table_owner = str(row.get("table_owner", "")).upper()
            table_owner_oracle_maintained = str(row.get("table_owner_oracle_maintained", "")).upper() == "Y"
            if not owner or oracle_maintained or owner in ORACLE_INTERNAL_SCHEMAS:
                continue
            if row.get("synonym_name") and (owner == "PUBLIC" or table_owner in ORACLE_INTERNAL_SCHEMAS or table_owner_oracle_maintained):
                continue
            filtered.append(row)
        return filtered

    def _build_security_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        security = database.get("security") if isinstance(database.get("security"), dict) else {}
        field = check.collector.get("field", check.check_id)
        rows = security.get(field, [])
        if rows is None:
            rows = []
        original_rows = rows if isinstance(rows, list) else [rows]
        filtered_rows = self._filter_security_rows(check.check_id, original_rows)
        evidence = {
            "metric": check.check_id,
            "label": check.collector.get("label", check.title),
            "source": check.collector.get("source_view", "inventario de seguridad Oracle"),
            "affected_count": len(filtered_rows),
            "rows": filtered_rows,
        }
        if filtered_rows != original_rows and check.check_id in ("dba_role_users", "critical_privilege_users"):
            evidence["inventory_count"] = len(original_rows)
            evidence["excluded_count"] = len(original_rows) - len(filtered_rows)
            evidence["classification_note"] = "Se excluyeron usuarios o roles Oracle-maintained esperados del hallazgo principal."
        if security.get(f"{field}_error"):
            evidence["collection_error"] = security.get(f"{field}_error")
        return evidence

    def _filter_security_rows(self, check_id: str, rows: list[Any]) -> list[Any]:
        if check_id == "default_profile_users":
            return [row for row in rows if not self._is_expected_oracle_security_row(row)]
        if check_id == "dba_role_users":
            return [row for row in rows if not self._is_allowed_dba_grantee(row)]
        if check_id == "critical_privilege_users":
            return [row for row in rows if not self._is_allowed_critical_privilege_grantee(row)]
        if check_id == "dictionary_access_privileges":
            return [row for row in rows if not self._is_expected_dictionary_access_grantee(row)]
        if check_id in {"admin_privilege_users", "any_privilege_users", "admin_option_grants", "legacy_roles_assigned", "external_authenticated_users", "legacy_password_versions", "inactive_users_by_last_login"}:
            return [row for row in rows if not self._is_expected_oracle_security_row(row)]
        if check_id == "oracle_maintained_open_users":
            return [row for row in rows if str(row.get("username", "")).upper() not in ORACLE_EXPECTED_ADMIN_USERS] if all(isinstance(row, dict) for row in rows) else rows
        return rows

    def _is_expected_dictionary_access_grantee(self, row: Any) -> bool:
        if not isinstance(row, dict):
            return False
        grantee = str(row.get("grantee", "")).upper()
        return grantee in ORACLE_EXPECTED_DICTIONARY_ACCESS_GRANTEES or self._is_expected_oracle_security_row(row)

    def _is_expected_oracle_security_row(self, row: Any) -> bool:
        if not isinstance(row, dict):
            return False
        principal = str(row.get("grantee") or row.get("username") or "").upper()
        oracle_maintained = str(row.get("oracle_maintained", "")).upper() == "Y"
        role_oracle_maintained = str(row.get("role_oracle_maintained", "")).upper() == "Y"
        return principal in ORACLE_EXPECTED_ADMIN_USERS or oracle_maintained or role_oracle_maintained

    def _is_allowed_dba_grantee(self, row: Any) -> bool:
        if not isinstance(row, dict):
            return False
        return str(row.get("grantee", "")).upper() in ORACLE_DBA_ROLE_ALLOWED_GRANTEES

    def _is_allowed_critical_privilege_grantee(self, row: Any) -> bool:
        if not isinstance(row, dict):
            return False
        grantee = str(row.get("grantee", "")).upper()
        grantee_type = str(row.get("grantee_type", "")).upper()
        oracle_maintained = str(row.get("oracle_maintained", "")).upper() == "Y"
        role_oracle_maintained = str(row.get("role_oracle_maintained", "")).upper() == "Y"
        return oracle_maintained or role_oracle_maintained

    def _sql_in_list(self, values: set[str]) -> str:
        return ",".join(f"'{value}'" for value in sorted(values))

    def _build_oracle_config_evidence(
        self,
        check: Check,
        name: str,
        actual: Any,
        source: str,
        exists: bool = True,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        evidence = {
            "metric": name,
            "parameter": name if check.collector.get("type") == "oracle_parameter" else None,
            "actual_value": actual,
            "source": source,
            "exists": exists and actual is not None,
        }
        if check.evaluator.get("expected") is not None:
            evidence["expected_value"] = check.evaluator.get("expected")
        if check.evaluator.get("minimum") is not None:
            evidence["minimum"] = check.evaluator.get("minimum")
        if check.evaluator.get("disallowed_values") is not None:
            evidence["disallowed_values"] = check.evaluator.get("disallowed_values")
        if extra:
            evidence.update({key: value for key, value in extra.items() if value is not None})
        return evidence

    def _write_json(self, path: Path, data: Any) -> None:
        path.write_text(json.dumps(mask_secrets(data), indent=2, ensure_ascii=False), encoding="utf-8")
