from orahealthcheck.config_loader import ConfigLoader, ConfigValidator
from orahealthcheck.engine.runner import CheckRunner
from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.models import Inventory, ResultStatus

PATCHING_CHECKS = {
    "patching_database_version",
    "patching_registry_sqlpatch_status",
    "patching_registry_sqlpatch_errors",
    "patching_registry_components_status",
    "patching_invalid_objects_prepatch",
    "patching_datapatch_inventory_consistency",
    "patching_database_open_mode_readiness",
    "patching_pdb_sqlpatch_status",
}


def test_patching_group_has_8_real_checks_and_profile_scope():
    config = ConfigLoader("config").load_all()
    assert "patching" in config["groups"]
    assert set(config["groups"]["patching"].checks) == PATCHING_CHECKS
    assert len(config["groups"]["patching"].checks) == 8
    assert "patching" in config["profiles"]["standalone_all"].enabled_groups
    assert "patching" not in config["profiles"]["standalone_basic"].enabled_groups
    assert ConfigValidator().validate(config) == []
    for cid in PATCHING_CHECKS:
        check = config["checks"][cid]
        assert check.group_id == "patching"
        assert check.collector["type"] == "patching"
        assert check.evaluator["type"] == "patching"


def test_patching_database_version_info_with_observable_version():
    ev = EVALUATORS["patching"]
    status, _ = ev.evaluate({"metric": "patching_database_version", "instance_version": "19.0.0.0.0", "database_version": "19.0.0.0.0", "product_components": []}, {"metric": "patching_database_version"})
    assert status == ResultStatus.INFO


def test_patching_registry_sqlpatch_status_rows_and_empty_inventory():
    ev = EVALUATORS["patching"]
    assert ev.evaluate({"metric": "patching_registry_sqlpatch_status", "rows": [{"patch_id": 1, "status": "SUCCESS"}]}, {"metric": "patching_registry_sqlpatch_status"})[0] == ResultStatus.INFO
    assert ev.evaluate({"metric": "patching_registry_sqlpatch_status", "rows": []}, {"metric": "patching_registry_sqlpatch_status", "empty_inventory_status": "INFO"})[0] == ResultStatus.INFO


def test_patching_registry_sqlpatch_errors_pass_and_fail():
    ev = EVALUATORS["patching"]
    assert ev.evaluate({"metric": "patching_registry_sqlpatch_errors", "rows": [{"status": "SUCCESS"}]}, {"metric": "patching_registry_sqlpatch_errors"})[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "patching_registry_sqlpatch_errors", "rows": [{"status": "WITH ERRORS"}]}, {"metric": "patching_registry_sqlpatch_errors"})[0] == ResultStatus.FAIL


def test_patching_registry_components_status_valid_and_invalid():
    ev = EVALUATORS["patching"]
    assert ev.evaluate({"metric": "patching_registry_components_status", "components": [{"status": "VALID"}]}, {"metric": "patching_registry_components_status"})[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "patching_registry_components_status", "components": [{"status": "INVALID"}]}, {"metric": "patching_registry_components_status"})[0] == ResultStatus.FAIL


def test_patching_invalid_objects_thresholds():
    ev = EVALUATORS["patching"]
    cfg = {"metric": "patching_invalid_objects_prepatch", "invalid_objects_warning": 1, "invalid_objects_fail": 20}
    assert ev.evaluate({"metric": "patching_invalid_objects_prepatch", "application_invalid_count": 0}, cfg)[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "patching_invalid_objects_prepatch", "application_invalid_count": 2}, cfg)[0] == ResultStatus.WARNING
    assert ev.evaluate({"metric": "patching_invalid_objects_prepatch", "application_invalid_count": 20}, cfg)[0] == ResultStatus.FAIL


def test_patching_datapatch_inventory_consistency():
    ev = EVALUATORS["patching"]
    metric = {"metric": "patching_datapatch_inventory_consistency"}
    assert ev.evaluate({"metric": "patching_datapatch_inventory_consistency", "rows": [{"patch_id": 1, "action": "APPLY", "status": "SUCCESS", "action_time": "2026-01-01"}]}, metric)[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "patching_datapatch_inventory_consistency", "rows": [{"patch_id": 1, "action": "APPLY", "status": "WITH ERRORS", "action_time": "2026-01-01"}]}, metric)[0] == ResultStatus.FAIL
    assert ev.evaluate({"metric": "patching_datapatch_inventory_consistency", "rows": []}, metric)[0] == ResultStatus.WARNING


def test_patching_database_open_mode_readiness_primary_and_standby():
    ev = EVALUATORS["patching"]
    metric = {"metric": "patching_database_open_mode_readiness"}
    assert ev.evaluate({"metric": "patching_database_open_mode_readiness", "database_role": "PRIMARY", "open_mode": "READ WRITE", "status": "OPEN"}, metric)[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "patching_database_open_mode_readiness", "database_role": "PHYSICAL STANDBY", "open_mode": "READ ONLY WITH APPLY", "status": "OPEN"}, metric)[0] == ResultStatus.INFO


def test_patching_pdb_sqlpatch_status_skipped_non_cdb_and_cdb_evidence():
    ev = EVALUATORS["patching"]
    metric = {"metric": "patching_pdb_sqlpatch_status"}
    assert ev.evaluate({"metric": "patching_pdb_sqlpatch_status", "is_cdb": False, "pdb_count": 0, "pdb_patch_rows": [], "problem_pdbs": []}, metric)[0] == ResultStatus.SKIPPED
    assert ev.evaluate({"metric": "patching_pdb_sqlpatch_status", "is_cdb": True, "pdbs": [{"open_mode": "READ WRITE"}], "pdb_patch_rows": [{"status": "SUCCESS"}], "problem_pdbs": []}, metric)[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "patching_pdb_sqlpatch_status", "is_cdb": True, "pdbs": [{"open_mode": "READ WRITE"}], "pdb_patch_rows": [{"status": "WITH ERRORS"}], "problem_pdbs": [{"status": "WITH ERRORS"}]}, metric)[0] == ResultStatus.FAIL


def test_patching_missing_views_do_not_traceback():
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)
    database = {"patching": {"collection_errors": {"sqlpatch_rows": "ORA-00942", "registry_components": "ORA-01031", "invalid_objects": "ORA-00942", "pdb_sqlpatch_rows": "ORA-00942"}}, "cdb": "YES", "multitenant": {"pdbs": []}}
    for cid in PATCHING_CHECKS:
        evidence = runner._build_patching_evidence(config["checks"][cid], database)
        EVALUATORS["patching"].evaluate(evidence, config["checks"][cid].evaluator)


def test_patching_runner_evidence_for_non_cdb_skips_pdb_check():
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)
    inv = Inventory("t1", "standalone", "dev", database={"cdb": "NO", "patching": runner._default_patching_inventory({}, healthy_defaults=True)}, features={"multitenant": {"detected": False, "status": "not_detected", "reason": "No CDB"}})
    result = runner._run_check(config["checks"]["patching_pdb_sqlpatch_status"], config["targets"]["example_standalone"], inv)
    assert result.status == ResultStatus.SKIPPED

class _SqlpatchWithoutBundleSeriesConnector:
    def __init__(self):
        self.queries = []

    def query(self, sql):
        normalized = " ".join(sql.lower().split())
        self.queries.append(normalized)
        assert "bundle_series" not in normalized
        if "from product_component_version" in normalized:
            return [{"product": "Oracle Database", "version": "19.0.0.0.0", "status": "Production"}]
        if "from dba_registry_sqlpatch" in normalized:
            return [{"patch_id": 123, "patch_uid": 456, "action": "APPLY", "status": "SUCCESS", "action_time": "2026-01-01", "description": "RU de prueba", "source_version": "19.0.0.0.0", "target_version": "19.0.0.0.0"}]
        if "from dba_registry" in normalized:
            return [{"comp_id": "CATALOG", "comp_name": "Oracle Database Catalog Views", "version": "19.0.0.0.0", "status": "VALID", "modified": None}]
        if "from dba_objects" in normalized:
            return []
        return []


def test_patching_sqlpatch_collection_does_not_require_bundle_series():
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)
    connector = _SqlpatchWithoutBundleSeriesConnector()
    discovered = runner._discover_patching_inventory(connector, {"cdb": "NO", "version": "19.0.0.0.0"})["patching"]
    assert discovered["collection_errors"] == {}
    assert discovered["sqlpatch_rows"][0]["patch_id"] == 123
    assert all("bundle_series" not in query for query in connector.queries)

    database = {"patching": discovered, "version": "19.0.0.0.0"}
    status_evidence = runner._build_patching_evidence(config["checks"]["patching_registry_sqlpatch_status"], database)
    errors_evidence = runner._build_patching_evidence(config["checks"]["patching_registry_sqlpatch_errors"], database)
    consistency_evidence = runner._build_patching_evidence(config["checks"]["patching_datapatch_inventory_consistency"], database)
    assert EVALUATORS["patching"].evaluate(status_evidence, config["checks"]["patching_registry_sqlpatch_status"].evaluator)[0] == ResultStatus.INFO
    assert EVALUATORS["patching"].evaluate(errors_evidence, config["checks"]["patching_registry_sqlpatch_errors"].evaluator)[0] == ResultStatus.PASS
    assert EVALUATORS["patching"].evaluate(consistency_evidence, config["checks"]["patching_datapatch_inventory_consistency"].evaluator)[0] == ResultStatus.PASS


def test_patching_registry_components_option_off_removed_are_informational():
    ev = EVALUATORS["patching"]
    evidence = {
        "metric": "patching_registry_components_status",
        "components": [
            {"comp_id": "CATALOG", "status": "VALID"},
            {"comp_id": "CATPROC", "status": "VALID"},
            {"comp_id": "RAC", "comp_name": "Oracle Real Application Clusters", "status": "OPTION OFF"},
            {"comp_id": "OLD", "status": "REMOVED"},
        ],
    }
    assert ev.evaluate(evidence, {"metric": "patching_registry_components_status"})[0] == ResultStatus.PASS


def test_patching_registry_components_intermediate_state_warns():
    ev = EVALUATORS["patching"]
    assert ev.evaluate({"metric": "patching_registry_components_status", "components": [{"comp_id": "JAVAVM", "status": "LOADING"}]}, {"metric": "patching_registry_components_status"})[0] == ResultStatus.WARNING


def test_patching_registry_component_evidence_counts_option_off():
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)
    database = {"patching": {"registry_components": [{"comp_id": "CATALOG", "status": "VALID"}, {"comp_id": "RAC", "status": "OPTION OFF"}], "collection_errors": {}}}
    evidence = runner._build_patching_evidence(config["checks"]["patching_registry_components_status"], database)
    assert evidence["component_count"] == 2
    assert evidence["invalid_count"] == 0
    assert evidence["warning_count"] == 0
    assert evidence["informational_count"] == 1
    assert evidence["option_off_count"] == 1
    assert evidence["removed_count"] == 0
