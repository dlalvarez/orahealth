from orahealthcheck.config_loader import ConfigLoader
from orahealthcheck.engine.runner import CheckRunner
from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.models import Inventory, ResultStatus


def _config():
    return ConfigLoader("config").load_all()


def test_performance_group_has_9_checks_and_profiles():
    config = _config()
    checks = config["groups"]["performance"].checks
    assert len(checks) == 9
    assert checks == [
        "performance_instance_uptime",
        "performance_active_user_sessions",
        "performance_wait_class_snapshot",
        "performance_current_event_summary",
        "performance_non_idle_wait_sessions",
        "performance_long_operations_active",
        "performance_parse_ratio_basic",
        "performance_library_cache_hit_ratio",
        "performance_sql_current_activity",
    ]
    assert "performance" in config["profiles"]["standalone_all"].enabled_groups
    assert "performance" not in config["profiles"]["standalone_basic"].enabled_groups


def test_wait_class_snapshot_uses_specific_config_and_default():
    evaluator = EVALUATORS["performance"]
    evidence = {"metric": "performance_wait_class_snapshot", "rows": [
        {"wait_class": "Concurrency", "session_count": 2, "total_observed_wait_seconds": 31, "max_wait_seconds": 10, "top_events": [{"event": "library cache lock"}]},
        {"wait_class": "Custom", "session_count": 9, "total_observed_wait_seconds": 119, "max_wait_seconds": 59, "top_events": [{"event": "custom wait"}]},
    ]}
    config = {"default": {"warning": {"sessions": 10, "total_seconds": 120, "max_seconds": 60}, "fail": {"sessions": 20, "total_seconds": 300, "max_seconds": 180}}, "classes": {"Concurrency": {"warning": {"sessions": 2, "total_seconds": 30, "max_seconds": 30}, "fail": {"sessions": 5, "total_seconds": 120, "max_seconds": 90}}}}
    status, message = evaluator.evaluate(evidence, {"metric": "performance_wait_class_snapshot", **config})
    assert status == ResultStatus.WARNING
    assert "Concurrency" in message


def test_collectors_filter_idle_and_group_by_event():
    runner = CheckRunner({})
    perf = {"wait_sessions": [
        {"type": "USER", "wait_class": "Idle", "event": "SQL*Net message", "seconds_in_wait": 100},
        {"type": "USER", "wait_class": "User I/O", "event": "db file sequential read", "seconds_in_wait": 3, "sql_id": "a", "module": "m"},
        {"type": "USER", "wait_class": "User I/O", "event": "db file sequential read", "seconds_in_wait": 7, "sql_id": "b", "module": "m"},
    ]}
    assert len(runner._filtered_wait_sessions(perf, ["Idle"])) == 2
    events = runner._performance_event_rows(perf, ["Idle"], 20)
    assert events[0]["wait_class"] == "User I/O"
    assert events[0]["event"] == "db file sequential read"
    assert events[0]["session_count"] == 2
    assert events[0]["total_observed_wait_seconds"] == 10


def test_parse_and_library_cache_handle_division_by_zero():
    evaluator = EVALUATORS["performance"]
    status, _ = evaluator.evaluate({"metric": "performance_parse_ratio_basic", "parse_total": 0, "parse_hard": 0, "hard_parse_pct": None}, {"metric": "performance_parse_ratio_basic", "min_parse_total": 1000})
    assert status == ResultStatus.INFO
    status, _ = evaluator.evaluate({"metric": "performance_library_cache_hit_ratio", "gets": 0, "pins": 0, "get_hit_pct": None, "pin_hit_pct": None}, {"metric": "performance_library_cache_hit_ratio", "min_volume": 1000})
    assert status == ResultStatus.INFO


def test_performance_sql_current_activity_is_current_only():
    check = _config()["checks"]["performance_sql_current_activity"]
    runtime_text = str(check.collector) + str(check.evaluator)
    forbidden = ["AWR", "ASH", "DBA_HIST", "DBMS_WORKLOAD_REPOSITORY", "X$"]
    assert not any(token in runtime_text.upper() for token in forbidden)
    assert "vistas dinámicas permitidas" in check.description
