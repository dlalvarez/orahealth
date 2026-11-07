"""Fase C1 - Integridad de evidencia: sin dato confiable no hay PASS."""

import json
from pathlib import Path

import pytest

from orahealthcheck.engine import CheckRunner
from orahealthcheck.engine.runner import CORE_VIEWS, required_views, requires_database
from orahealthcheck.engine.scoring import summarize
from orahealthcheck.models import Result, ResultStatus
from fakes import NoPrivilegeOracleConnector

HEALTH_STATUSES = {"PASS", "INFO", "WARNING", "FAIL", "CRITICAL"}

# Checks de base de datos que pueden no declarar vistas porque su recolección tiene
# fuentes alternativas o fallback explícito (alert log SQL→OS, vistas opcionales).
VIEWLESS_ALLOWED = {
    "dataguard_managed_standby_processes",
    "recoverability_backup_metadata_recent",
}


def _real_target(config, profile="standalone_all"):
    target = config["targets"]["example_standalone"]
    target.database = {k: v for k, v in target.database.items() if k != "mock_inventory"}
    target.operating_system = {"platform": "linux"}
    return profile


def _run(config, factory, profile="standalone_all"):
    output = CheckRunner(config, oracle_connector_factory=factory).run_target("example_standalone", profile)
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    return output, evidence, {r["check_id"]: r for r in evidence["results"]}


class PartialPrivilegeConnector:
    """Base identificable (v$database/v$instance) pero con vistas denegadas."""

    denied: set[str] = set()

    def __init__(self, profile=None):
        self.profile = profile

    def connect(self):
        return None

    def close(self):
        return None

    def query(self, sql, *args, **kwargs):
        q = " ".join(sql.lower().split())
        for view in self.denied:
            if f"from {view} " in q + " ":
                raise Exception("ORA-00942: table or view does not exist")
        if "from v$database" in q and "1 = 0" not in q:
            return [{"db_name": "ORCL", "open_mode": "READ WRITE", "role": "PRIMARY", "cdb": "NO", "archivelog_mode": "ARCHIVELOG"}]
        if "from v$instance" in q and "1 = 0" not in q:
            return [{"status": "OPEN", "version": "19.0.0.0.0", "instance_name": "orcl"}]
        return []


def test_no_privileges_never_produces_health_results(example_config):
    profile = _real_target(example_config)
    output, evidence, results = _run(example_config, NoPrivilegeOracleConnector, profile)
    db_results = [r for r in results.values() if r["group_id"] != "os"]
    assert db_results
    assert not [r["check_id"] for r in db_results if r["status"] in HEALTH_STATUSES]
    summary = evidence["summary"]
    assert summary["global_status"] == "ERROR"
    assert summary["score"] is None
    assert "dba_users" in summary["inaccessible_views"]
    assert summary["discovery_error_count"] > 0
    executive = (output / "executive_report.html").read_text(encoding="utf-8")
    assert "Evaluación no concluyente" in executive
    assert "DBA_USERS" in executive


def test_connection_failure_generates_report_with_errors(example_config):
    class Unreachable(NoPrivilegeOracleConnector):
        def connect(self):
            raise Exception("ORA-12541: TNS:no listener")

    profile = _real_target(example_config)
    output, evidence, results = _run(example_config, Unreachable, profile)
    assert (output / "executive_report.html").exists()
    database_status = results["database_status"]
    assert database_status["status"] == "ERROR"
    assert "ORA-12541" in database_status["error"]
    assert evidence["summary"]["global_status"] == "ERROR"


def test_denied_view_only_affects_checks_that_require_it(example_config):
    PartialPrivilegeConnector.denied = {"dba_role_privs", "gv$instance"}
    profile = _real_target(example_config)
    _, evidence, results = _run(example_config, PartialPrivilegeConnector, profile)

    assert results["dba_role_users"]["status"] == "ERROR"
    assert "DBA_ROLE_PRIVS" in results["dba_role_users"]["error"]
    # vistas accesibles: el check se evalúa normalmente
    assert results["locked_users"]["status"] != "ERROR"
    assert results["database_open_mode"]["status"] == "PASS"
    # RAC no detectado: queda SKIPPED aunque su vista esté denegada
    assert results["rac_instances_status"]["status"] == "SKIPPED"
    assert evidence["summary"]["inaccessible_views"] == ["dba_role_privs", "gv$instance"]


def test_real_database_identity_is_never_invented(example_config):
    PartialPrivilegeConnector.denied = {"v$database"}
    profile = _real_target(example_config)
    output, _, results = _run(example_config, PartialPrivilegeConnector, profile)
    assert results["database_open_mode"]["status"] == "ERROR"
    assert "V$DATABASE" in results["database_open_mode"]["error"]
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    assert "open_mode" not in inventory["database"]
    assert inventory["database"]["data_source"] == "oracle"


def test_mock_inventory_is_flagged_as_simulated(example_config):
    output = CheckRunner(example_config).run_target("example_standalone")
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["summary"]["data_source"] == "simulado"
    assert "SIMULADO" in (output / "executive_report.html").read_text(encoding="utf-8")


def _result(status):
    return Result(check_id=status, group_id="g", status=ResultStatus(status), title=status)


def test_errors_reduce_coverage_not_health_score():
    summary = summarize([_result("PASS")] * 9 + [_result("ERROR")])
    assert summary["score"] == 100
    assert summary["coverage_pct"] == 90.0
    assert summary["global_status"] == "PASS"


def test_low_coverage_makes_evaluation_inconclusive():
    summary = summarize([_result("PASS")] + [_result("ERROR")] * 3, min_coverage_pct=80)
    assert summary["global_status"] == "ERROR"
    assert summary["coverage_pct"] == 25.0


def test_nothing_evaluated_has_no_score():
    summary = summarize([_result("ERROR")] * 2 + [_result("SKIPPED")])
    assert summary["score"] is None


def test_all_skipped_keeps_full_score():
    summary = summarize([_result("SKIPPED")] * 3)
    assert summary["score"] == 100 and summary["global_status"] == "PASS"


def test_every_database_check_declares_required_views(example_config):
    missing = [
        check.check_id
        for check in example_config["checks"].values()
        if requires_database(check)
        and not required_views(check)
        and check.collector.get("type") != "alert_log_family"
        and check.check_id not in VIEWLESS_ALLOWED
    ]
    assert missing == [], f"Checks de base de datos sin applies_to.requires.views: {missing}"


def test_declared_views_have_valid_names(example_config):
    for check in example_config["checks"].values():
        for view in required_views(check):
            assert all(ch.isalnum() or ch in "_$" for ch in view), (check.check_id, view)


def test_core_views_are_always_probed(example_config):
    runner = CheckRunner(example_config)
    assert set(CORE_VIEWS) <= set(runner._views_to_probe([]))
