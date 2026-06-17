from datetime import datetime, timedelta

from orahealthcheck.config_loader import ConfigLoader
from orahealthcheck.engine.runner import CheckRunner
from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.models import ResultStatus


def evaluate(metric, evidence, **config):
    data = {"metric": metric, **evidence}
    cfg = {"type": "recoverability_drp", **config}
    return EVALUATORS["recoverability_drp"].evaluate(data, cfg)[0]


def test_backup_mode_datafiles_active_and_empty():
    assert evaluate("recoverability_backup_mode_datafiles", {"rows": []}) == ResultStatus.PASS
    assert evaluate("recoverability_backup_mode_datafiles", {"rows": [{"file_number": 1, "status": "ACTIVE"}]}) == ResultStatus.WARNING


def test_files_need_recovery_detects_rows():
    assert evaluate("recoverability_files_need_recovery", {"rows": []}) == ResultStatus.PASS
    assert evaluate("recoverability_files_need_recovery", {"rows": [{"file_number": 7, "error": "FILE NEEDS MEDIA RECOVERY"}]}) == ResultStatus.FAIL


def test_block_change_tracking_enabled_disabled_and_required():
    assert evaluate("recoverability_block_change_tracking", {"status": "ENABLED"}) == ResultStatus.PASS
    assert evaluate("recoverability_block_change_tracking", {"status": "DISABLED"}, required=False) == ResultStatus.INFO
    assert evaluate("recoverability_block_change_tracking", {"status": "DISABLED"}, required=True) == ResultStatus.WARNING


def test_backup_metadata_recent_visible_missing_and_privileges():
    assert evaluate("recoverability_backup_metadata_recent", {"rows": [{"status": "COMPLETED"}]}) == ResultStatus.PASS
    assert evaluate("recoverability_backup_metadata_recent", {"rows": []}, missing_status="INFO") == ResultStatus.INFO
    assert evaluate("recoverability_backup_metadata_recent", {"collection_error": "ORA-00942"}) == ResultStatus.SKIPPED


def test_controlfile_record_keep_time_low_and_acceptable():
    assert evaluate("recoverability_controlfile_record_retention", {"value": 7}, minimum_days=14) == ResultStatus.WARNING
    assert evaluate("recoverability_controlfile_record_retention", {"value": 30}, minimum_days=14) == ResultStatus.PASS


def test_restore_points_existing_empty_and_old_guaranteed():
    assert evaluate("recoverability_restore_points", {"rows": []}) == ResultStatus.INFO
    assert evaluate("recoverability_restore_points", {"rows": [{"name": "RP1", "guarantee_flashback_database": "NO"}]}) == ResultStatus.INFO
    old_time = (datetime.now() - timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S")
    assert evaluate("recoverability_restore_points", {"rows": [{"name": "RP2", "guarantee_flashback_database": "YES", "time": old_time}]}) == ResultStatus.WARNING


def test_config_loads_group_checks_and_profile():
    config = ConfigLoader("config").load_all()
    assert "recoverability_drp" in config["groups"]
    assert "recoverability_drp" in config["profiles"]["standalone_basic"].enabled_groups
    for check_id in config["groups"]["recoverability_drp"].checks:
        assert check_id in config["checks"]


def test_runner_builds_recoverability_evidence_from_empty_inventory():
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)
    check = config["checks"]["recoverability_backup_mode_datafiles"]
    evidence = runner._build_recoverability_drp_evidence(check, {"recoverability_drp": {"backup_mode_datafiles": []}})
    assert evidence["metric"] == "recoverability_backup_mode_datafiles"
    assert evidence["rows"] == []


def test_backup_metadata_evidence_filters_recent_rows():
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)
    check = config["checks"]["recoverability_backup_metadata_recent"]
    recent = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    old = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    evidence = runner._build_recoverability_drp_evidence(check, {"recoverability_drp": {"backup_metadata": {"rows": [{"end_time": recent}, {"end_time": old}]}}})
    assert len(evidence["rows"]) == 1
