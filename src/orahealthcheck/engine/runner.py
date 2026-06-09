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
        HTMLReporter(Path("templates/html")).generate(output_dir, target, inventory, results, summary)
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
                  log_mode as archivelog_mode
                from v$database
            """))
            inventory.update(self._query_one(connector, "instance status", """
                select status from v$instance
            """))
            inventory.update(self._query_one(connector, "database version", """
                select version from v$instance
            """))
            inventory.update(self._query_one(connector, "invalid objects", """
                select count(*) as invalid_objects_count
                from dba_objects
                where status = 'INVALID'
            """))
            inventory.update(self._query_one(connector, "tablespace free percentage", """
                select min(round((nvl(f.free_bytes, 0) / df.bytes) * 100, 2)) as tablespace_min_free_pct
                from (
                  select tablespace_name, sum(bytes) as bytes
                  from dba_data_files
                  group by tablespace_name
                ) df
                left join (
                  select tablespace_name, sum(bytes) as free_bytes
                  from dba_free_space
                  group by tablespace_name
                ) f on f.tablespace_name = df.tablespace_name
            """))
            fra = self._query_one(connector, "FRA usage", """
                select
                  space_limit,
                  space_used,
                  case
                    when nvl(space_limit, 0) > 0 then round((space_used / space_limit) * 100, 2)
                    else null
                  end as fra_used_pct
                from v$recovery_file_dest
            """)
            if fra and fra.get("space_limit") not in (None, 0):
                inventory.update(fra)
                inventory["fra_configured"] = True
            else:
                inventory["fra_configured"] = False
                inventory["fra_message"] = "FRA is not configured or space_limit is 0"
            return inventory
        finally:
            connector.close()

    def _query_one(self, connector: Any, label: str, sql: str) -> dict[str, Any]:
        try:
            rows = connector.query(sql)
        except Exception as exc:
            logging.warning("Oracle inventory query failed for %s: %s", label, exc)
            return {}
        return {key: self._normalize_inventory_value(value) for key, value in dict(rows[0]).items()} if rows else {}

    def _normalize_inventory_value(self, value: Any) -> Any:
        if isinstance(value, Decimal):
            return int(value) if value == value.to_integral_value() else float(value)
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        return value

    def _resolve_checks(self, profile: Any) -> list[Check]:
        checks: list[Check] = []
        for group_id in profile.enabled_groups:
            if group_id in profile.disabled_groups:
                continue
            group = self.config["groups"][group_id]
            for check_id in group.checks:
                if check_id not in profile.disabled_checks:
                    checks.append(self.config["checks"][check_id])
        return checks

    def _run_check(self, check: Check, target: Target, inventory: Inventory) -> Result:
        start = time.monotonic()
        logging.info("Check %s started", check.check_id)
        applicable, reason = self.applicability.evaluate(check, target, inventory)
        if check.check_id == "fra_usage" and inventory.database.get("fra_configured") is False:
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
        if ctype == "static":
            return collector.get("value")
        if ctype == "os_adapter":
            adapter = LinuxAdapter(LocalConnector()) if inventory.operating_system.get("platform") == "linux" else AIXAdapter(LocalConnector())
            return getattr(adapter, collector["method"])()
        raise ValueError(f"Unsupported collector type {ctype}")

    def _write_json(self, path: Path, data: Any) -> None:
        path.write_text(json.dumps(mask_secrets(data), indent=2, ensure_ascii=False), encoding="utf-8")
