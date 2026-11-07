import copy
import json
import logging
import time
from pathlib import Path
from typing import Any

from orahealthcheck.connectors import LocalConnector, OracleConnector, build_os_connector
from orahealthcheck.engine.applicability import ApplicabilityEngine
from orahealthcheck.engine.scoring import summarize
from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.models import Check, Inventory, Result, ResultStatus, Target
from orahealthcheck.os_adapters import AIXAdapter, LinuxAdapter
from orahealthcheck.reports.html_reporter import HTMLReporter
from orahealthcheck.utils.filesystem import ensure_dir
from orahealthcheck.utils.masking import mask_secrets
from orahealthcheck.utils.time import timestamp
from orahealthcheck.engine.discovery import (
    AlertLogMixin,
    FeaturesMixin,
    SchemaObjectsMixin,
    SecurityMixin,
    StorageMixin,
    OracleResourcesMixin,
    PerformanceMixin,
    IoRedoArchiveMixin,
    RacMixin,
    PatchingMixin,
    MultitenantMixin,
    RecoverabilityDrpMixin,
    CapacityMixin,
    AsmMixin,
    DataguardMixin,
)
from orahealthcheck.engine.requirements import CORE_VIEWS, required_views, requires_database  # re-export



class CheckRunner(AlertLogMixin, FeaturesMixin, SchemaObjectsMixin, SecurityMixin, StorageMixin, OracleResourcesMixin, PerformanceMixin, IoRedoArchiveMixin, RacMixin, PatchingMixin, MultitenantMixin, RecoverabilityDrpMixin, CapacityMixin, AsmMixin, DataguardMixin):
    def __init__(
        self,
        config: dict[str, Any],
        oracle_connector_factory: Any = OracleConnector,
        os_connector_factory: Any = None,
    ) -> None:
        self.config = config
        self.applicability = ApplicabilityEngine()
        self.oracle_connector_factory = oracle_connector_factory
        # Se resuelve en tiempo de ejecución para permitir que las pruebas reemplacen
        # ``build_os_connector`` del módulo sin tocar cada instancia.
        self._os_connector_factory_override = os_connector_factory
        self._os_connector_cache: dict[str, Any] = {}

    @property
    def os_connector_factory(self) -> Any:
        return self._os_connector_factory_override or build_os_connector

    def _os_connection_ids(self, target: Target) -> list[str]:
        """Conexiones OS declaradas por el target (lista ``connections`` o ``hosts``)."""
        os_cfg = target.operating_system or {}
        ids = [str(item) for item in (os_cfg.get("connections") or []) if item]
        for host in os_cfg.get("hosts") or []:
            if isinstance(host, dict) and host.get("connection_profile"):
                ids.append(str(host["connection_profile"]))
        return ids

    def _os_connector(self, target: Target) -> Any | None:
        """Conector del primer host OS del target; ``None`` si no hay conexión OS.

        ``use_local_discovery`` se conserva por compatibilidad y equivale a una
        conexión local explícita.
        """
        if target.target_id in self._os_connector_cache:
            return self._os_connector_cache[target.target_id]
        connector = None
        connection_ids = self._os_connection_ids(target)
        if connection_ids:
            profile = self.config.get("connections", {}).get("os_connections", {}).get(connection_ids[0])
            if profile is None:
                raise ValueError(f"El perfil de conexión OS '{connection_ids[0]}' no existe")
            connector = self.os_connector_factory(profile)
        elif target.operating_system.get("use_local_discovery", False):
            connector = LocalConnector()
        self._os_connector_cache[target.target_id] = connector
        return connector

    def _os_adapter(self, target: Target, platform: str) -> Any:
        connector = self._os_connector(target)
        if connector is None:
            raise RuntimeError("El target no tiene conexión de sistema operativo configurada")
        return AIXAdapter(connector) if platform == "aix" else LinuxAdapter(connector)

    def _close_os_connectors(self) -> None:
        for connector in self._os_connector_cache.values():
            close = getattr(connector, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as exc:  # cierre best-effort
                    logging.warning("Error cerrando conexión OS: %s", exc)
        self._os_connector_cache.clear()

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
        try:
            checks = self._resolve_checks(profile)
            inventory = self._discover_inventory(target, checks)
            logging.info("Loaded checks (%s): %s", len(checks), ", ".join(check.check_id for check in checks) or "none")
            results = [self._run_check(check, target, inventory) for check in checks]
        finally:
            self._close_os_connectors()
        min_coverage = self.config.get("settings", {}).get("app", {}).get("min_evidence_coverage_pct", 80)
        summary = summarize(results, min_coverage_pct=float(min_coverage))
        summary["data_source"] = "simulado" if "mock_inventory" in target.database else "oracle"
        summary["discovery_error_count"] = len(inventory.database.get("discovery_errors") or [])
        summary["inaccessible_views"] = sorted(
            view for view, access in (inventory.database.get("view_access") or {}).items()
            if not access.get("accessible")
        )
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

    def _discover_inventory(self, target: Target, checks: list[Check] | None = None) -> Inventory:
        is_mock = "mock_inventory" in target.database
        if is_mock:
            logging.info("Using mock database inventory for target %s", target.target_id)
            db = dict(target.database.get("mock_inventory", {}))
            db.setdefault("data_source", "simulado")
            # Identidad por defecto SOLO para inventarios simulados (demo/pruebas).
            db.setdefault("status", "OPEN")
            db.setdefault("open_mode", "READ WRITE")
            db.setdefault("role", "PRIMARY")
            db.setdefault("version", "19.0")
        else:
            logging.info("Using OracleConnector for database inventory on target %s", target.target_id)
            db = self._discover_oracle_inventory(target, self._views_to_probe(checks))
            db.setdefault("data_source", "oracle")
            # Para bases reales nunca se inventa la identidad: si V$DATABASE/V$INSTANCE
            # no se pudieron leer, los checks quedan en ERROR por la compuerta de evidencia.
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
        db.setdefault("patching", self._default_patching_inventory(db, healthy_defaults="mock_inventory" in target.database))
        if "mock_inventory" in target.database:
            db["parameters"] = self._with_default_mock_parameters(db.get("parameters", {}))
        features = self._detect_oracle_features_from_inventory(db)
        os_data = {"platform": target.operating_system.get("platform", "linux")}
        os_connection_ids = self._os_connection_ids(target)
        os_data["connection"] = os_connection_ids[0] if os_connection_ids else ("local" if target.operating_system.get("use_local_discovery") else None)
        if target.operating_system.get("use_local_discovery", False) or os_connection_ids:
            try:
                adapter = self._os_adapter(target, os_data["platform"])
                os_data.update({"os_info": adapter.get_os_info(), "cpu": adapter.get_cpu_info(), "memory": adapter.get_memory_info()})
            except Exception as exc:
                logging.warning("No fue posible descubrir el inventario OS del target %s: %s", target.target_id, exc)
                os_data["discovery_error"] = str(exc)
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

    def _discover_oracle_inventory(self, target: Target, probe_views: list[str] | None = None) -> dict[str, Any]:
        connection_id = target.database.get("primary_connection")
        if not connection_id:
            return {}
        profile = self.config["connections"]["db_connections"].get(connection_id)
        self._query_failures = []
        try:
            connector = self.oracle_connector_factory(profile)
            connector.connect()
        except Exception as exc:
            logging.error("No fue posible conectar a la base de datos (%s): %s", connection_id, exc)
            return {"connection_error": str(exc), "data_source": "oracle"}
        try:
            inventory: dict[str, Any] = {}
            inventory["view_access"] = self._probe_view_access(connector, probe_views or list(CORE_VIEWS))
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
            inventory.update(self._discover_patching_inventory(connector, inventory))
            inventory.update(self._discover_io_redo_archive_inventory(connector, inventory.get("parameters", {}), inventory))
            inventory.update(self._discover_recoverability_drp_inventory(connector, inventory.get("parameters", {})))
            inventory.update(self._discover_rac_inventory(connector, inventory.get("parameters", {})))
            inventory.update(self._discover_multitenant_inventory(connector, inventory.get("cdb")))
            inventory["alert_log"] = self._discover_alert_log_inventory(connector, target, inventory)
            inventory.update(self._discover_oracle_feature_signals(connector))
            inventory["discovery_errors"] = list(self._query_failures)
            return inventory
        finally:
            try:
                connector.close()
            except Exception as exc:  # cierre best-effort
                logging.warning("Error cerrando conexión Oracle: %s", exc)

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

    def _evidence_gate(self, check: Check, inventory: Inventory, stage: str) -> str | None:
        """Motivo por el que el check no tiene evidencia confiable, o ``None``.

        ``stage='pre'`` valida conexión y vistas núcleo (antes de aplicabilidad, porque
        la aplicabilidad depende del rol/open mode leídos de esas vistas).
        ``stage='post'`` valida las vistas propias del check (después de aplicabilidad,
        para que un check no aplicable quede SKIPPED aunque su vista no sea accesible).
        """
        if not requires_database(check) or inventory.database.get("data_source") == "simulado":
            return None
        db = inventory.database
        access = db.get("view_access")
        if stage == "pre":
            if db.get("connection_error"):
                return f"No fue posible conectar a la base de datos: {db['connection_error']}"
            if access is None:
                return None  # inventario construido sin preflight (compatibilidad)
            blocked = [view for view in CORE_VIEWS if not access.get(view, {}).get("accessible", False)]
            if blocked:
                details = "; ".join(f"{view.upper()}: {access.get(view, {}).get('error') or 'no verificada'}" for view in blocked)
                return f"No es posible identificar la base de datos por falta de acceso a vistas núcleo ({details})"
            return None
        if access is None:
            return None
        blocked = [view for view in required_views(check) if view in access and not access[view].get("accessible")]
        if blocked:
            details = "; ".join(f"{view.upper()}: {access[view].get('error')}" for view in blocked)
            return f"Sin acceso de lectura a vistas requeridas ({details}). Otorgue el privilegio y reejecute."
        return None

    def _evidence_error_result(self, check: Check, reason: str, start: float) -> Result:
        duration_ms = int((time.monotonic() - start) * 1000)
        logging.error("Check %s sin evidencia confiable: %s", check.check_id, reason)
        return Result(
            check_id=check.check_id,
            group_id=check.group_id,
            status=ResultStatus.ERROR,
            title=check.title,
            failure_severity=check.failure_severity,
            message="No se obtuvo evidencia confiable; el check no se evaluó",
            evidence={"required_views": required_views(check)},
            error=reason,
            duration_ms=duration_ms,
        )

    def _run_check(self, check: Check, target: Target, inventory: Inventory) -> Result:
        start = time.monotonic()
        logging.info("Check %s started", check.check_id)
        gate_reason = self._evidence_gate(check, inventory, "pre")
        if gate_reason:
            return self._evidence_error_result(check, gate_reason, start)
        applicable, reason = self.applicability.evaluate(check, target, inventory)
        if applicable:
            gate_reason = self._evidence_gate(check, inventory, "post")
            if gate_reason:
                return self._evidence_error_result(check, gate_reason, start)
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
            evidence = self._collect(check, inventory, target)
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

    def _collect(self, check: Check, inventory: Inventory, target: Target | None = None) -> Any:
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
        if ctype == "patching":
            return self._build_patching_evidence(check, inventory.database)
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
            if target is None:
                raise RuntimeError("El colector os_adapter requiere el target para resolver la conexión OS")
            adapter = self._os_adapter(target, str(inventory.operating_system.get("platform", "linux")))
            return getattr(adapter, collector["method"])()
        raise ValueError(f"Tipo de colector no soportado: {ctype}")

    def _write_json(self, path: Path, data: Any) -> None:
        path.write_text(json.dumps(mask_secrets(data), indent=2, ensure_ascii=False), encoding="utf-8")
