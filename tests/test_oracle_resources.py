from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.evaluators.oracle_resources import OracleResourcesEvaluator
from orahealthcheck.models import ResultStatus


def _eval(metric, evidence, **config):
    payload = {"metric": metric, **evidence}
    return EVALUATORS["oracle_resources"].evaluate(payload, {"type": "oracle_resources", **config})


def test_memory_value_parser_handles_oracle_units():
    evaluator = OracleResourcesEvaluator()

    assert evaluator._memory_value_bytes("0") == 0
    assert evaluator._memory_value_bytes("2304M") > 0
    assert evaluator._memory_value_bytes("765M") > 0
    assert evaluator._memory_value_bytes("2G") > 0
    assert evaluator._memory_value_bytes("1024K") > 0
    assert evaluator._memory_value_bytes(" 2 g ") == 2 * 1024 ** 3
    assert evaluator._memory_value_bytes(123456789) == 123456789
    assert evaluator._memory_value_bytes(None) is None
    assert evaluator._memory_value_bytes("") is None


def test_processes_usage_pct_pass_warning_fail_and_unlimited():
    status, _ = _eval(
        "processes_usage_pct",
        {"resource_name": "processes", "exists": True, "limit_numeric": True, "used_pct": 20},
        warning=70,
        fail=85,
        critical=95,
    )
    assert status == ResultStatus.PASS

    status, _ = _eval(
        "processes_usage_pct",
        {"resource_name": "processes", "exists": True, "limit_numeric": True, "used_pct": 75},
        warning=70,
        fail=85,
        critical=95,
    )
    assert status == ResultStatus.WARNING

    status, _ = _eval(
        "processes_usage_pct",
        {"resource_name": "processes", "exists": True, "limit_numeric": True, "used_pct": 90},
        warning=70,
        fail=85,
        critical=95,
    )
    assert status == ResultStatus.FAIL

    status, message = _eval(
        "processes_usage_pct",
        {"resource_name": "processes", "exists": True, "limit_numeric": False, "limit_value": "UNLIMITED"},
        warning=70,
        fail=85,
    )
    assert status == ResultStatus.INFO
    assert "no es numérico" in message


def test_sessions_usage_pct_pass_warning_and_fail():
    for used_pct, expected in [(10, ResultStatus.PASS), (70, ResultStatus.WARNING), (85, ResultStatus.FAIL)]:
        status, _ = _eval(
            "sessions_usage_pct",
            {"resource_name": "sessions", "exists": True, "limit_numeric": True, "used_pct": used_pct},
            warning=70,
            fail=85,
            critical=95,
        )
        assert status == expected


def test_transactions_usage_pct_missing_resource_is_info():
    status, message = _eval("transactions_usage_pct", {"resource_name": "transactions", "exists": False}, missing_status="INFO")
    assert status == ResultStatus.INFO
    assert "no está disponible" in message


def test_sga_target_configured_modes():
    status, message = _eval("sga_target_configured", {"sga_target": "0", "memory_target": "2G", "management_mode": "AMM"})
    assert status == ResultStatus.PASS
    assert "AMM" in message

    status, message = _eval("sga_target_configured", {"sga_target": "2304M", "memory_target": "0", "management_mode": "ASMM"})
    assert status == ResultStatus.PASS
    assert "ASMM" in message

    status, message = _eval("sga_target_configured", {"sga_target": "0", "memory_target": "0", "management_mode": "MANUAL"}, manual_status="INFO")
    assert status == ResultStatus.INFO
    assert "sga_target y memory_target no tienen valor mayor a cero" in message


def test_pga_aggregate_target_configured_pass_and_warning():
    status, _ = _eval("pga_aggregate_target_configured", {"exists": True, "pga_aggregate_target": "765M"})
    assert status == ResultStatus.PASS

    status, _ = _eval("pga_aggregate_target_configured", {"exists": True, "pga_aggregate_target": "0"}, zero_status="WARNING")
    assert status == ResultStatus.WARNING


def test_pga_aggregate_limit_configured_pass_and_warning():
    status, _ = _eval("pga_aggregate_limit_configured", {"exists": True, "pga_aggregate_limit": "2G"})
    assert status == ResultStatus.PASS

    status, _ = _eval("pga_aggregate_limit_configured", {"exists": True, "pga_aggregate_limit": "0"}, zero_status="WARNING")
    assert status == ResultStatus.WARNING


def test_pga_memory_usage_info_normal_and_overallocation_warning():
    status, _ = _eval("pga_memory_usage_info", {"over_allocation_count": 0, "cache_hit_percentage": 95}, warning_cache_hit_percentage_min=70)
    assert status == ResultStatus.INFO

    status, _ = _eval("pga_memory_usage_info", {"over_allocation_count": 1, "cache_hit_percentage": 95}, warning_cache_hit_percentage_min=70)
    assert status == ResultStatus.WARNING


def test_sga_memory_info_is_informational_with_rows():
    status, _ = _eval("sga_memory_info", {"rows": [{"name": "Maximum SGA Size", "mb": 1024}], "free_sga_memory_pct": 0}, warning_free_pct_min=1)
    assert status == ResultStatus.INFO

    status, _ = _eval("sga_memory_info", {"rows": [{"name": "Maximum SGA Size", "mb": 1024}], "free_sga_memory_pct": 0}, warning_free_pct_min=1, enable_free_pct_warning=True)
    assert status == ResultStatus.WARNING


def test_blocked_sessions_basic_pass_warning_and_fail():
    status, _ = _eval("blocked_sessions_basic", {"affected_count": 0, "rows": [], "max_seconds_in_wait": 0})
    assert status == ResultStatus.PASS

    status, _ = _eval("blocked_sessions_basic", {"affected_count": 1, "rows": [{}], "max_seconds_in_wait": 30}, fail_blocked_count=10, fail_seconds_in_wait=600)
    assert status == ResultStatus.WARNING

    status, _ = _eval("blocked_sessions_basic", {"affected_count": 1, "rows": [{}], "max_seconds_in_wait": 700}, fail_blocked_count=10, fail_seconds_in_wait=600)
    assert status == ResultStatus.FAIL


def test_blocking_sessions_basic_pass_and_warning():
    status, _ = _eval("blocking_sessions_basic", {"affected_count": 0, "rows": []})
    assert status == ResultStatus.PASS

    status, _ = _eval("blocking_sessions_basic", {"affected_count": 1, "rows": [{"blocked_count": 2, "max_seconds_in_wait": 10}]}, fail_blocked_count=10)
    assert status == ResultStatus.WARNING


def test_inactive_sessions_high_info_warning_and_fail():
    status, _ = _eval("inactive_sessions_high", {"total_inactive_sessions": 10}, warning_inactive_sessions=100, fail_inactive_sessions=300, ok_status="INFO")
    assert status == ResultStatus.INFO

    status, _ = _eval("inactive_sessions_high", {"total_inactive_sessions": 120}, warning_inactive_sessions=100, fail_inactive_sessions=300)
    assert status == ResultStatus.WARNING

    status, _ = _eval("inactive_sessions_high", {"total_inactive_sessions": 300}, warning_inactive_sessions=100, fail_inactive_sessions=300)
    assert status == ResultStatus.FAIL


def test_scheduler_and_legacy_job_findings():
    for metric in ["scheduler_failed_jobs_recent", "scheduler_disabled_jobs", "scheduler_broken_jobs", "legacy_dba_jobs_broken"]:
        status, _ = _eval(metric, {"affected_count": 0, "rows": []})
        assert status == ResultStatus.PASS
        status, _ = _eval(metric, {"affected_count": 1, "rows": [{"owner": "APP"}]}, status_when_found="WARNING")
        assert status == ResultStatus.WARNING
