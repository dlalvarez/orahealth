from orahealthcheck.config_loader import ConfigLoader
from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.models import ResultStatus

NEW_CAPACITY_CHECKS = {
    "capacity_database_size_snapshot",
    "capacity_tablespace_headroom",
    "capacity_datafile_headroom",
    "capacity_segments_top_size",
    "capacity_temp_capacity_snapshot",
    "capacity_undo_capacity_snapshot",
    "capacity_resource_limits_headroom",
    "capacity_fra_archive_headroom",
}


def test_capacity_group_has_real_checks_and_profiles():
    config = ConfigLoader("config").load_all()
    assert set(config["groups"]["capacity"].checks) == NEW_CAPACITY_CHECKS
    assert config["groups"]["capacity"].checks[0] == "capacity_database_size_snapshot"
    assert "capacity" in config["profiles"]["standalone_all"].enabled_groups
    assert "capacity" not in config["profiles"]["standalone_basic"].enabled_groups
    for check_id in NEW_CAPACITY_CHECKS:
        check = config["checks"][check_id]
        assert check.group_id == "capacity"
        assert check.collector["type"] == "capacity"
        assert check.evaluator["type"] == "capacity"
        assert check.remediation.get("validation")


def test_capacity_headroom_thresholds():
    evaluator = EVALUATORS["capacity"]
    cfg = {"metric": "capacity_tablespace_headroom", "warning_pct": 20, "fail_pct": 10, "critical_pct": 5}
    assert evaluator.evaluate({"metric": "capacity_tablespace_headroom", "rows": [{"headroom_pct": 35}]}, cfg)[0] == ResultStatus.PASS
    assert evaluator.evaluate({"metric": "capacity_tablespace_headroom", "rows": [{"headroom_pct": 15}]}, cfg)[0] == ResultStatus.WARNING
    assert evaluator.evaluate({"metric": "capacity_tablespace_headroom", "rows": [{"headroom_pct": 8}]}, cfg)[0] == ResultStatus.FAIL
    assert evaluator.evaluate({"metric": "capacity_tablespace_headroom", "rows": [{"headroom_pct": 3}]}, cfg)[0] == ResultStatus.CRITICAL


def test_capacity_usage_and_optional_views_do_not_traceback():
    evaluator = EVALUATORS["capacity"]
    cfg = {"metric": "capacity_temp_capacity_snapshot", "warning_pct": 80, "fail_pct": 90, "critical_pct": 95}
    assert evaluator.evaluate({"metric": "capacity_temp_capacity_snapshot", "rows": []}, cfg)[0] == ResultStatus.INFO
    assert evaluator.evaluate({"metric": "capacity_temp_capacity_snapshot", "rows": [{"used_pct": 85}]}, cfg)[0] == ResultStatus.WARNING
    assert evaluator.evaluate({"metric": "capacity_undo_capacity_snapshot", "rows": [{"used_pct": 92}]}, {**cfg, "metric": "capacity_undo_capacity_snapshot"})[0] == ResultStatus.FAIL
    assert evaluator.evaluate({"metric": "capacity_temp_capacity_snapshot", "rows": [{"used_pct": 96}]}, cfg)[0] == ResultStatus.CRITICAL


def test_capacity_fra_not_configured_is_skipped_not_fail():
    evaluator = EVALUATORS["capacity"]
    status, message = evaluator.evaluate({"metric": "capacity_fra_archive_headroom", "fra_configured": False, "rows": []}, {"metric": "capacity_fra_archive_headroom"})
    assert status == ResultStatus.SKIPPED
    assert "FRA no configurada" in message


def test_capacity_resource_limits_worst_metric():
    evaluator = EVALUATORS["capacity"]
    evidence = {"metric": "capacity_resource_limits_headroom", "rows": [
        {"resource_name": "sessions", "used_pct": 40},
        {"resource_name": "processes", "used_pct": 91},
        {"resource_name": "transactions", "used_pct": 20},
    ]}
    status, message = evaluator.evaluate(evidence, {"metric": "capacity_resource_limits_headroom", "warning_pct": 80, "fail_pct": 90, "critical_pct": 95})
    assert status == ResultStatus.FAIL
    assert "processes" in message


def test_capacity_segments_top_size_filters_internal_context():
    evaluator = EVALUATORS["capacity"]
    evidence = {"metric": "capacity_segments_top_size", "rows": [{"owner": "APP", "segment_name": "T_BIG", "size_mb": 2048}], "internal_schema_filter": "ORACLE_MAINTAINED"}
    status, _ = evaluator.evaluate(evidence, {"metric": "capacity_segments_top_size", "segment_large_warning_mb": 10240, "segment_large_fail_mb": 51200})
    assert status == ResultStatus.INFO
    assert "ORACLE_MAINTAINED" in evidence["internal_schema_filter"]
