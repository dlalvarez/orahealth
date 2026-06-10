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
from orahealthcheck.models import Check, Inventory, Result, ResultStatus, Target
from orahealthcheck.os_adapters import AIXAdapter, LinuxAdapter
from orahealthcheck.reports.html_reporter import HTMLReporter
from orahealthcheck.utils.filesystem import ensure_dir
from orahealthcheck.utils.masking import mask_secrets
from orahealthcheck.utils.time import timestamp


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
        os_data = {"platform": target.operating_system.get("platform", "linux")}
        if target.operating_system.get("use_local_discovery", False):
            adapter = LinuxAdapter(LocalConnector()) if os_data["platform"] == "linux" else AIXAdapter(LocalConnector())
            os_data.update({"os_info": adapter.get_os_info(), "cpu": adapter.get_cpu_info(), "memory": adapter.get_memory_info()})
        return Inventory(target.target_id, target.expected_architecture, target.environment, db, os_data, target.features)

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
                  force_logging
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
                  'db_recovery_file_dest_size'
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
            inventory.update(self._discover_storage_inventory(connector, inventory.get("parameters", {})))
            return inventory
        finally:
            connector.close()


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
        storage["temp_usage"] = self._query_rows(connector, "temporary tablespace usage", """
            select tf.tablespace_name,
                   round(tf.total_bytes / 1024 / 1024, 2) as total_mb,
                   round(nvl(th.used_bytes, 0) / 1024 / 1024, 2) as used_mb,
                   round((tf.total_bytes - nvl(th.used_bytes, 0)) / 1024 / 1024, 2) as free_mb,
                   case when tf.total_bytes > 0 then round((nvl(th.used_bytes, 0) / tf.total_bytes) * 100, 2) else 0 end as used_pct
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
            fra["message"] = "FRA is not configured or space_limit is 0"
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

    def _parameter_value(self, parameters: dict[str, Any], name: str) -> Any:
        data = parameters.get(name.lower(), {}) if isinstance(parameters, dict) else {}
        if not isinstance(data, dict):
            return None
        return data.get("display_value", data.get("value"))

    def _query_one(self, connector: Any, label: str, sql: str) -> dict[str, Any]:
        rows = self._query_rows(connector, label, sql)
        return rows[0] if rows else {}

    def _query_rows(self, connector: Any, label: str, sql: str) -> list[dict[str, Any]]:
        try:
            rows = connector.query(sql)
        except Exception as exc:
            logging.warning("Oracle inventory query failed for %s: %s", label, exc)
            return []
        return [
            {key: self._normalize_inventory_value(value) for key, value in dict(row).items()}
            for row in rows
        ]

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
            message = inventory.database.get("fra_message", "FRA is not configured")
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
            return Result(
                check_id=check.check_id,
                group_id=check.group_id,
                status=ResultStatus.SKIPPED,
                title=check.title,
                failure_severity=check.failure_severity,
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
                message="Technical execution error",
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
        raise ValueError(f"Unsupported collector type {ctype}")


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
            evidence.update({"max_used_pct": worst.get("used_pct"), "worst_tablespace": worst.get("tablespace_name"), "tablespaces": temp_usage})
        elif check_id == "undo_tablespace_status":
            evidence.update(undo)
        elif check_id == "fra_configured":
            evidence.update(fra)
        elif check_id in ("fra_usage", "fra_usage_pct"):
            evidence.update(fra)
            if "used_pct" in fra:
                evidence["fra_used_pct"] = fra.get("used_pct")
        return evidence

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
