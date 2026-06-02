import json
import logging
import time
from pathlib import Path
from typing import Any

from orahealthcheck.connectors import LocalConnector
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
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.applicability = ApplicabilityEngine()

    def run_target(self, target_id: str) -> Path:
        target: Target = self.config["targets"][target_id]
        profile = self.config["profiles"][target.profile]
        base_output = self.config["settings"].get("app", {}).get("default_output_dir", "output")
        output_dir = ensure_dir(Path(base_output) / f"{target_id}_{timestamp()}")
        self._configure_logging(output_dir)
        logging.info("Starting OraHealthCheck execution for target %s", target_id)
        inventory = self._discover_inventory(target)
        checks = self._resolve_checks(profile)
        results = [self._run_check(check, target, inventory) for check in checks]
        summary = summarize(results)
        self._write_json(output_dir / "inventory.json", inventory.to_dict())
        self._write_json(output_dir / "evidence.json", {"summary": summary, "results": [r.to_dict() for r in results]})
        HTMLReporter(Path("templates/html")).generate(output_dir, target, inventory, results, summary)
        logging.info("Finished OraHealthCheck execution for target %s", target_id)
        return output_dir

    def _configure_logging(self, output_dir: Path) -> None:
        root = logging.getLogger()
        root.handlers.clear()
        root.setLevel(logging.INFO)
        handler = logging.FileHandler(output_dir / "execution.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        root.addHandler(handler)

    def _discover_inventory(self, target: Target) -> Inventory:
        db = dict(target.database.get("mock_inventory", {}))
        db.setdefault("status", "OPEN")
        db.setdefault("open_mode", "READ WRITE")
        db.setdefault("role", "PRIMARY")
        db.setdefault("version", "19.0")
        os_data = {"platform": target.operating_system.get("platform", "linux")}
        if target.operating_system.get("use_local_discovery", False):
            adapter = LinuxAdapter(LocalConnector()) if os_data["platform"] == "linux" else AIXAdapter(LocalConnector())
            os_data.update({"os_info": adapter.get_os_info(), "cpu": adapter.get_cpu_info(), "memory": adapter.get_memory_info()})
        return Inventory(target.target_id, target.expected_architecture, target.environment, db, os_data, target.features)

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
        applicable, reason = self.applicability.evaluate(check, target, inventory)
        if not applicable:
            return Result(check.check_id, check.group_id, ResultStatus.SKIPPED, check.title, check.severity, skipped_reason=reason)
        try:
            evidence = self._collect(check, inventory)
            evaluator_type = check.evaluator.get("type", "expected_value")
            status, message = EVALUATORS[evaluator_type].evaluate(evidence, check.evaluator)
            return Result(check.check_id, check.group_id, status, check.title, check.severity, message, mask_secrets(evidence), check.remediation, duration_ms=int((time.monotonic() - start) * 1000))
        except Exception as exc:  # technical execution errors become ERROR by design
            logging.exception("Technical error running check %s", check.check_id)
            return Result(check.check_id, check.group_id, ResultStatus.ERROR, check.title, check.severity, "Technical execution error", error=str(exc), duration_ms=int((time.monotonic() - start) * 1000))

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
