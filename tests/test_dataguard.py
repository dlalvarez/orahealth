from orahealthcheck.config_loader import ConfigLoader
from orahealthcheck.engine.runner import CheckRunner
from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.models import Inventory, ResultStatus

DATAGUARD_CHECKS = {
    "dataguard_configuration_detected",
    "dataguard_database_role",
    "dataguard_archive_dest_status",
    "dataguard_transport_lag_basic",
    "dataguard_apply_lag_basic",
    "dataguard_archive_gap_basic",
    "dataguard_standby_redo_logs_basic",
    "dataguard_parameters_basic",
}


def test_dataguard_group_has_real_checks_and_profile_scope():
    config = ConfigLoader("config").load_all()
    assert set(config["groups"]["dataguard"].checks) == DATAGUARD_CHECKS
    assert "dataguard" in config["profiles"]["standalone_all"].enabled_groups
    assert "dataguard" not in config["profiles"]["standalone_basic"].enabled_groups
    for cid in DATAGUARD_CHECKS:
        check = config["checks"][cid]
        assert check.group_id == "dataguard"
        assert check.collector["type"] == "dataguard"
        assert check.evaluator["type"] == "dataguard"
        assert check.applicability == {"requires_feature": "standby_configuration"}


def test_dataguard_feature_not_detected_skips_group():
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)
    inventory = Inventory("t1", "standalone", "dev", database={}, features={"standby_configuration": {"detected": False, "status": "not_detected", "reason": "sin standby"}})
    results = [runner._run_check(config["checks"][cid], config["targets"]["example_standalone"], inventory) for cid in config["groups"]["dataguard"].checks]
    assert {r.status for r in results} == {ResultStatus.SKIPPED}


def test_dataguard_feature_detection_primary_and_standby_signals():
    runner = CheckRunner({})
    assert not runner._detect_oracle_features_from_inventory({"role": "PRIMARY"})["standby_configuration"]["detected"]
    assert runner._detect_oracle_features_from_inventory({"role": "PHYSICAL STANDBY"})["standby_configuration"]["detected"]
    assert runner._detect_oracle_features_from_inventory({"role": "PRIMARY", "archive_destinations": [{"target": "STANDBY", "status": "VALID"}]})["standby_configuration"]["detected"]


def test_dataguard_archive_dest_and_lag_evaluations():
    ev = EVALUATORS["dataguard"]
    assert ev.evaluate({"metric": "dataguard_archive_dest_status", "rows": [{"status": "VALID", "target": "STANDBY"}]}, {"metric": "dataguard_archive_dest_status"})[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "dataguard_archive_dest_status", "rows": [{"status": "ERROR", "error": "ORA-16057"}]}, {"metric": "dataguard_archive_dest_status"})[0] == ResultStatus.FAIL
    cfg = {"metric": "dataguard_transport_lag_basic", "transport_lag_warning_seconds": 300, "transport_lag_fail_seconds": 900, "transport_lag_critical_seconds": 1800}
    assert ev.evaluate({"metric": "dataguard_transport_lag_basic", "value": "+00 00:05:00"}, cfg)[0] == ResultStatus.WARNING
    assert ev.evaluate({"metric": "dataguard_transport_lag_basic", "value": "+00 00:20:00"}, cfg)[0] == ResultStatus.FAIL
    assert ev.evaluate({"metric": "dataguard_transport_lag_basic", "value": "no parseable"}, cfg)[0] == ResultStatus.INFO


def test_dataguard_apply_gap_srl_and_parameters():
    ev = EVALUATORS["dataguard"]
    cfg = {"metric": "dataguard_apply_lag_basic", "apply_lag_warning_seconds": 300, "apply_lag_fail_seconds": 900, "apply_lag_critical_seconds": 1800}
    assert ev.evaluate({"metric": "dataguard_apply_lag_basic", "value": "00:01:00"}, cfg)[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "dataguard_apply_lag_basic", "value": "0 00:30:00"}, cfg)[0] == ResultStatus.CRITICAL
    assert ev.evaluate({"metric": "dataguard_archive_gap_basic", "rows": []}, {"metric": "dataguard_archive_gap_basic"})[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "dataguard_archive_gap_basic", "rows": [{"thread#": 1}]}, {"metric": "dataguard_archive_gap_basic"})[0] == ResultStatus.FAIL
    assert ev.evaluate({"metric": "dataguard_standby_redo_logs_basic", "standby_redo_groups": 0}, {"metric": "dataguard_standby_redo_logs_basic"})[0] == ResultStatus.WARNING
    assert ev.evaluate({"metric": "dataguard_standby_redo_logs_basic", "standby_redo_groups": 4, "online_redo_max_mb": 200, "standby_redo_min_mb": 200}, {"metric": "dataguard_standby_redo_logs_basic"})[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "dataguard_parameters_basic", "warnings": []}, {"metric": "dataguard_parameters_basic"})[0] == ResultStatus.PASS
    assert ev.evaluate({"metric": "dataguard_parameters_basic", "warnings": ["standby_file_management"]}, {"metric": "dataguard_parameters_basic"})[0] == ResultStatus.WARNING


def test_dataguard_evidence_builders_do_not_traceback_with_missing_views():
    runner = CheckRunner({})
    config = ConfigLoader("config").load_all()
    database = {"dataguard": {"standby_detected": True, "database_role": "PRIMARY", "stats_collection_error": "ORA-00942", "gap_collection_error": "ORA-01031", "standby_log_collection_error": "ORA-00942"}}
    for cid in DATAGUARD_CHECKS:
        evidence = runner._build_dataguard_evidence(config["checks"][cid], database)
        EVALUATORS["dataguard"].evaluate(evidence, config["checks"][cid].evaluator)


def _param(value):
    return {"value": value, "display_value": value}


def test_dataguard_standby_file_management_alone_does_not_detect_or_execute_group():
    config = ConfigLoader("config").load_all()
    runner = CheckRunner(config)
    database = {"role": "PRIMARY", "parameters": {"standby_file_management": _param("AUTO")}}
    features = runner._detect_oracle_features_from_inventory(database)
    assert features["standby_configuration"]["detected"] is False
    assert "parametro_standby_file_management" not in features["standby_configuration"].get("signals", [])
    inventory = Inventory("t1", "standalone", "dev", database=database, features=features)
    results = [runner._run_check(config["checks"][cid], config["targets"]["example_standalone"], inventory) for cid in config["groups"]["dataguard"].checks]
    assert {r.status for r in results} == {ResultStatus.SKIPPED}


def test_dataguard_strong_feature_signals_only():
    runner = CheckRunner({})
    assert runner._detect_oracle_features_from_inventory({
        "role": "PRIMARY",
        "parameters": {"log_archive_config": _param("DG_CONFIG=(orcl,orclstby)")},
    })["standby_configuration"]["detected"] is True
    assert runner._detect_oracle_features_from_inventory({
        "role": "PRIMARY",
        "parameters": {"log_archive_dest_1": _param("LOCATION=USE_DB_RECOVERY_FILE_DEST")},
    })["standby_configuration"]["detected"] is False
    assert runner._detect_oracle_features_from_inventory({
        "role": "PRIMARY",
        "parameters": {"log_archive_dest_2": _param("SERVICE=orclstby ASYNC VALID_FOR=(ONLINE_LOGFILES,PRIMARY_ROLE) DB_UNIQUE_NAME=orclstby")},
    })["standby_configuration"]["detected"] is True
    assert runner._detect_oracle_features_from_inventory({"role": "PHYSICAL STANDBY"})["standby_configuration"]["detected"] is True


class _DataGuardArchiveDestConnector:
    def query(self, sql):
        normalized = " ".join(sql.lower().split())
        assert "recovery_mode" not in normalized
        if "from v$database" in normalized:
            return [{"database_role": "PRIMARY", "open_mode": "READ WRITE", "protection_mode": "MAXIMUM PERFORMANCE", "protection_level": "UNPROTECTED", "switchover_status": "NOT ALLOWED"}]
        if "from v$archive_dest" in normalized:
            return [{"dest_id": 2, "status": "ERROR", "target": "STANDBY", "destination": "SERVICE=orclstby", "error": "ORA-16057"}]
        if "from v$archive_gap" in normalized:
            return []
        if "from v$dataguard_stats" in normalized:
            return []
        if "from v$standby_log" in normalized or "from v$log" in normalized or "from v$thread" in normalized:
            return []
        return []


def test_dataguard_archive_dest_query_avoids_recovery_mode_and_preserves_error_destinations():
    runner = CheckRunner({})
    discovered = runner._discover_dataguard_inventory(_DataGuardArchiveDestConnector(), {"parameters": {}})["dataguard"]
    assert discovered["standby_detected"] is True
    assert discovered["archive_destinations"][0]["error"] == "ORA-16057"
    ev = EVALUATORS["dataguard"]
    assert ev.evaluate({"metric": "dataguard_archive_dest_status", "rows": discovered["archive_destinations"]}, {"metric": "dataguard_archive_dest_status"})[0] == ResultStatus.FAIL
