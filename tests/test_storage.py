from orahealthcheck.models import ResultStatus

from conftest import run_example_and_results


def _storage(config):
    return config["targets"]["example_standalone"].database["mock_inventory"].setdefault("storage", {})


def test_users_system_default_tablespace_passes_without_application_users(example_config):
    _storage(example_config)["users"] = [
        {"username": "SYS", "default_tablespace": "SYSTEM", "account_status": "OPEN", "oracle_maintained": "Y"},
        {"username": "APP", "default_tablespace": "USERS", "account_status": "OPEN", "oracle_maintained": "N"},
    ]

    result = run_example_and_results(example_config)["users_system_default_tablespace"]

    assert result["status"] == ResultStatus.PASS.value
    assert result["evidence"]["affected_count"] == 0


def test_users_system_default_tablespace_warns_for_application_user(example_config):
    _storage(example_config)["users"] = [
        {"username": "APP", "default_tablespace": "SYSTEM", "account_status": "OPEN", "oracle_maintained": "N"},
    ]

    result = run_example_and_results(example_config)["users_system_default_tablespace"]

    assert result["status"] == ResultStatus.WARNING.value
    assert result["evidence"]["rows"][0]["username"] == "APP"


def test_users_system_temp_tablespace_detects_system_temp(example_config):
    _storage(example_config)["users"] = [{"username": "APP", "temporary_tablespace": "SYSTEM", "oracle_maintained": "N"}]

    result = run_example_and_results(example_config)["users_system_temp_tablespace"]

    assert result["status"] in {ResultStatus.WARNING.value, ResultStatus.FAIL.value}
    assert result["evidence"]["affected_count"] == 1


def test_users_missing_default_tablespace_detects_invalid_default(example_config):
    _storage(example_config)["users"] = [{"username": "APP", "default_tablespace": "APPDATA", "default_tablespace_exists": None, "oracle_maintained": "N"}]

    result = run_example_and_results(example_config)["users_missing_default_tablespace"]

    assert result["status"] == ResultStatus.WARNING.value
    assert result["evidence"]["rows"][0]["username"] == "APP"


def test_users_missing_temp_tablespace_detects_invalid_temporary(example_config):
    _storage(example_config)["users"] = [{"username": "APP", "temporary_tablespace": "TEMP_APP", "temporary_tablespace_exists": None, "oracle_maintained": "N"}]

    result = run_example_and_results(example_config)["users_missing_temp_tablespace"]

    assert result["status"] == ResultStatus.WARNING.value
    assert result["evidence"]["affected_count"] == 1


def test_dictionary_managed_tablespaces_detects_dictionary_extent_management(example_config):
    _storage(example_config)["dictionary_managed_tablespaces"] = [{"tablespace_name": "LEGACY", "extent_management": "DICTIONARY"}]

    result = run_example_and_results(example_config)["dictionary_managed_tablespaces"]

    assert result["status"] == ResultStatus.WARNING.value
    assert result["evidence"]["rows"][0]["tablespace_name"] == "LEGACY"
