from orahealthcheck.models import ResultStatus

from conftest import run_example_and_results


def _database(config):
    return config["targets"]["example_standalone"].database["mock_inventory"]


def _set_parameter(config, name, value):
    parameters = _database(config).setdefault("parameters", {})
    parameters[name] = {"name": name, "value": value, "display_value": value}


def test_archivelog_mode_passes_in_archivelog(example_config):
    _database(example_config)["archivelog_mode"] = "ARCHIVELOG"

    result = run_example_and_results(example_config)["archivelog_mode"]

    assert result["status"] == ResultStatus.PASS.value


def test_archivelog_mode_fails_when_not_archivelog(example_config):
    _database(example_config)["archivelog_mode"] = "NOARCHIVELOG"

    result = run_example_and_results(example_config)["archivelog_mode"]

    assert result["status"] == ResultStatus.FAIL.value


def test_force_logging_passes_when_enabled_by_standard(example_config):
    _database(example_config)["force_logging"] = "YES"

    result = run_example_and_results(example_config)["force_logging"]

    assert result["status"] == ResultStatus.PASS.value


def test_force_logging_warns_when_standard_requires_enabled(example_config):
    _database(example_config)["force_logging"] = "NO"

    result = run_example_and_results(example_config)["force_logging"]

    assert result["status"] == ResultStatus.WARNING.value


def test_remote_login_passwordfile_validates_expected_standard_value(example_config):
    _set_parameter(example_config, "remote_login_passwordfile", "EXCLUSIVE")
    assert run_example_and_results(example_config)["remote_login_passwordfile"]["status"] == ResultStatus.PASS.value

    _set_parameter(example_config, "remote_login_passwordfile", "NONE")
    assert run_example_and_results(example_config)["remote_login_passwordfile"]["status"] == ResultStatus.WARNING.value


def test_recyclebin_validates_project_standard_value(example_config):
    profile = example_config["profiles"]["standalone_basic"]
    policies = {}
    for standard_id in profile.standards:
        policies.update(example_config["standards"][standard_id].policies)
    expected_recyclebin = str(policies["expected_recyclebin"]).upper()
    non_standard_recyclebin = "ON" if expected_recyclebin == "OFF" else "OFF"

    _set_parameter(example_config, "recyclebin", expected_recyclebin)
    assert run_example_and_results(example_config)["recyclebin"]["status"] == ResultStatus.PASS.value

    _set_parameter(example_config, "recyclebin", non_standard_recyclebin)
    assert run_example_and_results(example_config)["recyclebin"]["status"] == ResultStatus.WARNING.value


def test_db_block_size_validates_expected_standard_value(example_config):
    _set_parameter(example_config, "db_block_size", 8192)
    assert run_example_and_results(example_config)["db_block_size"]["status"] == ResultStatus.PASS.value

    _set_parameter(example_config, "db_block_size", 4096)
    assert run_example_and_results(example_config)["db_block_size"]["status"] == ResultStatus.WARNING.value


def test_open_cursors_processes_sessions_validate_configured_minimums(example_config):
    for parameter, good_value, low_value in [("open_cursors", 300, 299), ("processes", 300, 299), ("sessions", 450, 449)]:
        _set_parameter(example_config, parameter, good_value)
        assert run_example_and_results(example_config)[parameter]["status"] == ResultStatus.PASS.value

        _set_parameter(example_config, parameter, low_value)
        assert run_example_and_results(example_config)[parameter]["status"] == ResultStatus.WARNING.value
