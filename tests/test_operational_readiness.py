from orahealthcheck.models import ResultStatus

from conftest import run_example_and_results


def _enable_operational(config):
    groups = config["profiles"]["standalone_basic"].enabled_groups
    if "operational_readiness" not in groups:
        groups.append("operational_readiness")
    return config["targets"]["example_standalone"].database["mock_inventory"].setdefault("parameters", {})


def _set_parameter(parameters, name, value):
    parameters[name] = {"name": name, "value": value, "display_value": value}


def test_plsql_optimize_level_passes_when_it_matches_standard(example_config):
    parameters = _enable_operational(example_config)
    _set_parameter(parameters, "plsql_optimize_level", 2)

    result = run_example_and_results(example_config)["plsql_optimize_level"]

    assert result["status"] == ResultStatus.PASS.value


def test_plsql_optimize_level_warns_when_it_differs_from_standard(example_config):
    parameters = _enable_operational(example_config)
    _set_parameter(parameters, "plsql_optimize_level", 1)

    result = run_example_and_results(example_config)["plsql_optimize_level"]

    assert result["status"] == ResultStatus.WARNING.value


def test_plsql_debug_passes_when_false_and_warns_when_true(example_config):
    parameters = _enable_operational(example_config)
    _set_parameter(parameters, "plsql_debug", "FALSE")
    assert run_example_and_results(example_config)["plsql_debug"]["status"] == ResultStatus.PASS.value

    _set_parameter(parameters, "plsql_debug", "TRUE")
    assert run_example_and_results(example_config)["plsql_debug"]["status"] == ResultStatus.WARNING.value


def test_sql_trace_passes_when_false_and_warns_when_true(example_config):
    parameters = _enable_operational(example_config)
    _set_parameter(parameters, "sql_trace", "FALSE")
    assert run_example_and_results(example_config)["sql_trace"]["status"] == ResultStatus.PASS.value

    _set_parameter(parameters, "sql_trace", "TRUE")
    assert run_example_and_results(example_config)["sql_trace"]["status"] == ResultStatus.WARNING.value


def test_optimizer_use_invisible_indexes_passes_when_false_and_warns_when_true(example_config):
    parameters = _enable_operational(example_config)
    _set_parameter(parameters, "optimizer_use_invisible_indexes", "FALSE")
    assert run_example_and_results(example_config)["optimizer_use_invisible_indexes"]["status"] == ResultStatus.PASS.value

    _set_parameter(parameters, "optimizer_use_invisible_indexes", "TRUE")
    assert run_example_and_results(example_config)["optimizer_use_invisible_indexes"]["status"] == ResultStatus.WARNING.value


def test_informational_operational_parameters_report_info_without_penalty(example_config):
    parameters = _enable_operational(example_config)
    values = {
        "plsql_code_type": "INTERPRETED",
        "timed_statistics": "TRUE",
        "timed_os_statistics": 0,
        "result_cache_mode": "MANUAL",
        "result_cache_max_result": "5",
        "result_cache_remote_expiration": 0,
        "db_ultra_safe": "OFF",
    }
    for name, value in values.items():
        _set_parameter(parameters, name, value)

    results = run_example_and_results(example_config)

    for check_id in values:
        assert results[check_id]["status"] == ResultStatus.INFO.value
