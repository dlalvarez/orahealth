import copy
import json
import logging
import time
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from orahealthcheck.connectors import LocalConnector, OracleConnector
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

    def run_target(self, target_id: str) -> Path:
        run_start = time.monotonic()
        target: Target = self.config["targets"][target_id]
        profile = self.config["profiles"][target.profile]
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
        features = self._detect_oracle_features_from_inventory(db)
        os_data = {"platform": target.operating_system.get("platform", "linux")}
        if target.operating_system.get("use_local_discovery", False):
            adapter = LinuxAdapter(LocalConnector()) if os_data["platform"] == "linux" else AIXAdapter(LocalConnector())
            os_data.update({"os_info": adapter.get_os_info(), "cpu": adapter.get_cpu_info(), "memory": adapter.get_memory_info()})
        return Inventory(target.target_id, target.expected_architecture, target.environment, db, os_data, {**features, **target.features})

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
                select version from v$instance
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
                  'control_file_record_keep_time'
                  ,'cluster_database'
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
            inventory.update(self._discover_io_redo_archive_inventory(connector, inventory.get("parameters", {}), inventory))
            inventory.update(self._discover_recoverability_drp_inventory(connector, inventory.get("parameters", {})))
            inventory.update(self._discover_oracle_feature_signals(connector))
            return inventory
        finally:
            connector.close()

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
        standby_roles = {"PHYSICAL STANDBY", "LOGICAL STANDBY", "SNAPSHOT STANDBY"}
        remote_archive_destinations = database.get("remote_archive_destinations") or []
        standby_detected = database_role in standby_roles or bool(remote_archive_destinations)

        fra_space_limit = database.get("fra_space_limit")
        if fra_space_limit is None:
            fra_space_limit = database.get("recovery_file_dest_size")
        if fra_space_limit is None and isinstance(database.get("storage"), dict):
            fra_space_limit = (database["storage"].get("fra") or {}).get("space_limit") or (database["storage"].get("fra") or {}).get("recovery_file_dest_size")
        fra_detected = bool(database.get("fra_configured")) or self._safe_number(fra_space_limit) > 0

        flashback_value = str(database.get("flashback_on", "NO")).upper()
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
                "source": "V$DATABASE.DATABASE_ROLE / V$ARCHIVE_DEST",
                "database_role": database_role,
                "protection_mode": database.get("protection_mode"),
                "protection_level": database.get("protection_level"),
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
        security["default_profile_users"] = self._query_rows(connector, "usuarios con perfil DEFAULT", """
            select username, account_status, profile, oracle_maintained, common
            from dba_users
            where profile = 'DEFAULT'
              and account_status = 'OPEN'
            order by username
        """)
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
        return {"security": security}

    def _discover_storage_inventory(self, connector: Any, parameters: dict[str, Any]) -> dict[str, Any]:
        storage: dict[str, Any] = {"tablespaces": [], "datafiles": [], "tempfiles": [], "temp_usage": [], "fra": {}, "undo": {}}
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
        if ctype == "oracle_schema_objects":
            return self._build_schema_objects_evidence(check, inventory.database)
        if ctype == "io_redo_archive":
            return self._build_io_redo_archive_evidence(check, inventory.database)
        if ctype == "recoverability_drp":
            return self._build_recoverability_drp_evidence(check, inventory.database)
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
        thresholds = {k: v for k, v in check.evaluator.items() if k in {"warning", "fail", "critical", "missing_fra_status"}}
        evidence: dict[str, Any] = {"metric": check_id, "source": check.collector.get("source_view", "oracle storage inventory"), **thresholds}
        tablespaces = storage.get("tablespaces") or []
        datafiles = storage.get("datafiles") or []
        tempfiles = storage.get("tempfiles") or []
        temp_usage = storage.get("temp_usage") or []
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
        evidence = {
            "metric": check.check_id,
            "label": check.collector.get("label", check.title),
            "source": check.collector.get("source_view", "inventario de esquemas y objetos Oracle"),
            "affected_count": len(filtered_rows),
            "rows": filtered_rows,
        }
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
            owner = str(row.get("owner", row.get("table_owner", ""))).upper()
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
        if field not in security and check.collector.get("missing_status"):
            evidence["collection_error"] = f"No se encontró la sección {field} en el inventario de seguridad"
        return evidence

    def _filter_security_rows(self, check_id: str, rows: list[Any]) -> list[Any]:
        if check_id == "dba_role_users":
            return [row for row in rows if not self._is_allowed_dba_grantee(row)]
        if check_id == "critical_privilege_users":
            return [row for row in rows if not self._is_allowed_critical_privilege_grantee(row)]
        return rows

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
