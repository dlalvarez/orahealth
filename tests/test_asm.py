from orahealthcheck.config_loader import ConfigLoader
from orahealthcheck.engine.runner import CheckRunner
from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.models import Inventory, ResultStatus

ASM_CHECKS = {
    "asm_database_uses_asm",
    "asm_database_files_on_asm",
    "asm_diskgroup_inventory_db_view",
    "asm_diskgroup_usage_db_view",
    "asm_diskgroup_state_db_view",
    "asm_diskgroup_free_headroom_db_view",
    "asm_disk_status_db_view",
    "asm_rebalance_operations_db_view",
}


def test_asm_group_has_real_checks_and_profile_scope():
    config = ConfigLoader("config").load_all()
    assert set(config["groups"]["asm"].checks) == ASM_CHECKS
    assert "asm" in config["profiles"]["standalone_all"].enabled_groups
    assert "asm" not in config["profiles"]["standalone_basic"].enabled_groups
    for check_id in ASM_CHECKS:
        check = config["checks"][check_id]
        assert check.group_id == "asm"
        assert check.collector["type"] == "asm"
        assert check.evaluator["type"] == "asm"
        assert check.applicability == {"requires_feature": "asm"}


def test_asm_feature_detects_database_files_on_asm():
    runner = CheckRunner({})
    features = runner._detect_oracle_features_from_inventory({"storage": {"datafiles": [{"file_name": "+DATA/ORCL/system01.dbf"}], "tempfiles": []}})
    assert features["asm"]["detected"] is True
    assert features["asm"]["diskgroups"] == ["DATA"]


def test_asm_feature_not_detected_without_asm_files():
    runner = CheckRunner({})
    features = runner._detect_oracle_features_from_inventory({"storage": {"datafiles": [{"file_name": "/u01/oradata/system01.dbf"}]}})
    assert features["asm"]["detected"] is False
    assert "No se encontraron" in features["asm"]["reason"]


def test_asm_checks_skip_by_required_feature_when_not_detected():
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)
    inventory = Inventory("t1", "standalone", "dev", database={}, features={"asm": {"detected": False, "status": "not_detected", "reason": "No se encontraron archivos de base de datos sobre ASM desde la conexión actual."}})
    results = [runner._run_check(config["checks"][cid], config["targets"]["example_standalone"], inventory) for cid in config["groups"]["asm"].checks]
    assert {r.status for r in results} == {ResultStatus.SKIPPED}
    assert all(r.message for r in results)


def test_asm_diskgroup_thresholds_warning_fail_critical():
    ev = EVALUATORS["asm"]
    cfg = {"metric": "asm_diskgroup_usage_db_view", "diskgroup_free_warning_pct": 20, "diskgroup_free_fail_pct": 10, "diskgroup_free_critical_pct": 5}
    assert ev.evaluate({"metric": "asm_diskgroup_usage_db_view", "rows": [{"free_pct": 30}]}, cfg)[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "asm_diskgroup_usage_db_view", "rows": [{"free_pct": 15}]}, cfg)[0] == ResultStatus.WARNING
    assert ev.evaluate({"metric": "asm_diskgroup_usage_db_view", "rows": [{"free_pct": 8}]}, cfg)[0] == ResultStatus.FAIL
    assert ev.evaluate({"metric": "asm_diskgroup_usage_db_view", "rows": [{"free_pct": 4}]}, cfg)[0] == ResultStatus.CRITICAL


def test_asm_state_disk_and_rebalance_evaluation():
    ev = EVALUATORS["asm"]
    assert ev.evaluate({"metric": "asm_diskgroup_state_db_view", "used_diskgroups": ["DATA"], "rows": [{"name": "DATA", "state": "CONNECTED", "offline_disks": 0}]}, {"metric": "asm_diskgroup_state_db_view", "acceptable_diskgroup_states": ["CONNECTED", "MOUNTED"]})[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "asm_diskgroup_state_db_view", "used_diskgroups": ["DATA"], "rows": [{"name": "DATA", "state": "DISMOUNTED"}]}, {"metric": "asm_diskgroup_state_db_view", "acceptable_diskgroup_states": ["CONNECTED", "MOUNTED"]})[0] == ResultStatus.FAIL
    assert ev.evaluate({"metric": "asm_disk_status_db_view", "rows": [{"disk_name": "D1", "mode_status": "OFFLINE"}]}, {"metric": "asm_disk_status_db_view", "disk_problem_statuses": ["OFFLINE"]})[0] == ResultStatus.FAIL
    assert ev.evaluate({"metric": "asm_rebalance_operations_db_view", "rows": []}, {"metric": "asm_rebalance_operations_db_view"})[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "asm_rebalance_operations_db_view", "rows": [{"operation": "REBAL"}]}, {"metric": "asm_rebalance_operations_db_view"})[0] == ResultStatus.INFO


def test_asm_unavailable_views_and_incomplete_evidence_do_not_traceback():
    ev = EVALUATORS["asm"]
    assert ev.evaluate({"metric": "asm_diskgroup_inventory_db_view", "collection_error": "ORA-00942"}, {"metric": "asm_diskgroup_inventory_db_view"})[0] == ResultStatus.INFO
    assert ev.evaluate({"metric": "asm_diskgroup_free_headroom_db_view", "rows": [{"name": "DATA"}]}, {"metric": "asm_diskgroup_free_headroom_db_view"})[0] == ResultStatus.INFO
