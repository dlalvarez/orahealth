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



def test_asm_remediation_capacity_checks_describe_real_risk():
    config = ConfigLoader("config").load_all()
    usage = config["checks"]["asm_diskgroup_usage_db_view"].remediation
    headroom = config["checks"]["asm_diskgroup_free_headroom_db_view"].remediation
    assert usage["owner"] == "Mixed"
    assert headroom["owner"] == "Mixed"
    assert "espacio libre" in usage["summary"]
    assert "pueden fallar" in usage["summary"]
    assert "margen efectivo" in headroom["summary"]
    assert "USABLE_FILE_MB" in headroom["summary"]
    assert any("No eliminar" in action for action in usage["actions"])
    assert any("DBA" in action and "almacenamiento" in action for action in headroom["actions"])


def test_asm_file_inventory_preserves_tablespace_names_and_nulls_for_non_tablespace_files():
    runner = CheckRunner({})
    asm = runner._default_asm_inventory({
        "storage": {
            "datafiles": [{"file_id": 1, "file_name": "+DATA/ORCL/DATAFILE/system01.dbf", "tablespace_name": "SYSTEM"}],
            "tempfiles": [{"file_id": 1, "file_name": "+DATA/ORCL/TEMPFILE/temp01.dbf", "tablespace_name": "TEMP"}],
        },
        "logfiles": [{"group_number": 1, "member": "+DATA/ORCL/ONLINELOG/group_1.log"}],
        "control_files": ["+DATA/ORCL/CONTROLFILE/current.ctl"],
    })
    by_type = {row["file_type"]: row for row in asm["files"]}
    assert by_type["DATAFILE"]["tablespace_name"] == "SYSTEM"
    assert by_type["TEMPFILE"]["tablespace_name"] == "TEMP"
    assert by_type["REDO"].get("tablespace_name") is None
    assert by_type["CONTROLFILE"].get("tablespace_name") is None


class _AsmFakeConnector:
    def __init__(self, fail_dba: bool = False):
        self.fail_dba = fail_dba
        self.queries = []

    def query(self, sql):
        q = " ".join(sql.lower().split())
        self.queries.append(q)
        if "from dba_data_files" in q:
            if self.fail_dba:
                raise RuntimeError("ORA-00942")
            return [{"file_type": "DATAFILE", "file_id": 1, "file_name": "+DATA/ORCL/DATAFILE/system01.dbf", "tablespace_name": "SYSTEM"}]
        if "from dba_temp_files" in q:
            if self.fail_dba:
                raise RuntimeError("ORA-00942")
            return [{"file_type": "TEMPFILE", "file_id": 1, "file_name": "+DATA/ORCL/TEMPFILE/temp01.dbf", "tablespace_name": "TEMP"}]
        if "from v$datafile" in q:
            return [{"file_type": "DATAFILE", "file_id": 1, "file_name": "+DATA/ORCL/DATAFILE/system01.dbf", "tablespace_name": None}]
        if "from v$tempfile" in q:
            return [{"file_type": "TEMPFILE", "file_id": 1, "file_name": "+DATA/ORCL/TEMPFILE/temp01.dbf", "tablespace_name": None}]
        if "from v$logfile" in q:
            return [{"file_type": "REDO", "file_id": 1, "file_name": "+DATA/ORCL/ONLINELOG/group_1.log", "tablespace_name": None}]
        if "from v$recovery_file_dest" in q:
            return []
        if "from v$asm_diskgroup_stat" in q or "from v$asm_disk_stat" in q or "from v$asm_operation" in q:
            return []
        return []


def test_asm_discovery_prefers_dba_file_tablespaces_and_falls_back_to_v_views():
    runner = CheckRunner({})
    asm = runner._discover_asm_inventory(_AsmFakeConnector(), {})["asm"]
    by_type = {row["file_type"]: row for row in asm["files"]}
    assert by_type["DATAFILE"]["tablespace_name"] == "SYSTEM"
    assert by_type["TEMPFILE"]["tablespace_name"] == "TEMP"
    fallback = runner._discover_asm_inventory(_AsmFakeConnector(fail_dba=True), {})["asm"]
    by_type = {row["file_type"]: row for row in fallback["files"]}
    assert by_type["DATAFILE"].get("tablespace_name") is None
    assert by_type["TEMPFILE"].get("tablespace_name") is None
