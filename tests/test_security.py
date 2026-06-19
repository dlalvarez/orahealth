from orahealthcheck.engine import CheckRunner
from orahealthcheck.models import ResultStatus

from conftest import run_example_and_results


def _security(config):
    return config["targets"]["example_standalone"].database["mock_inventory"]["security"]


def test_oracle_maintained_open_users_passes_for_only_sys_system(example_config):
    _security(example_config)["oracle_maintained_open_users"] = [
        {"username": "SYS", "account_status": "OPEN", "oracle_maintained": "Y"},
        {"username": "SYSTEM", "account_status": "OPEN", "oracle_maintained": "Y"},
    ]

    result = run_example_and_results(example_config)["oracle_maintained_open_users"]

    assert result["status"] == ResultStatus.PASS.value
    assert result["evidence"]["affected_count"] == 0


def test_oracle_maintained_open_users_warns_for_internal_open_user(example_config):
    _security(example_config)["oracle_maintained_open_users"] = [
        {"username": "SYS", "account_status": "OPEN", "oracle_maintained": "Y"},
        {"username": "MDSYS", "account_status": "OPEN", "oracle_maintained": "Y"},
    ]

    result = run_example_and_results(example_config)["oracle_maintained_open_users"]

    assert result["status"] == ResultStatus.WARNING.value
    assert result["evidence"]["rows"] == [{"username": "MDSYS", "account_status": "OPEN", "oracle_maintained": "Y"}]


def test_admin_privilege_users_omits_sysrac_when_column_is_not_available():
    class CaptureConnector:
        queries = []

        def query(self, sql: str):
            normalized = " ".join(sql.lower().split())
            type(self).queries.append(normalized)
            if "from all_tab_columns" in normalized and "v_$pwfile_users" in normalized:
                return [{"COLUMN_NAME": name} for name in ["SYSDBA", "SYSOPER", "SYSASM", "SYSBACKUP", "SYSDG", "SYSKM"]]
            return []

    CheckRunner({})._discover_security_inventory(CaptureConnector())
    admin_query = next(query for query in CaptureConnector.queries if "from v$pwfile_users" in query)

    assert "sysrac" not in admin_query
    assert "username not in ('sys', 'system')" in admin_query


def test_admin_privilege_users_includes_sysrac_when_column_is_available():
    class CaptureConnector:
        queries = []

        def query(self, sql: str):
            normalized = " ".join(sql.lower().split())
            type(self).queries.append(normalized)
            if "from all_tab_columns" in normalized and "v_$pwfile_users" in normalized:
                return [{"COLUMN_NAME": name} for name in ["SYSDBA", "SYSOPER", "SYSASM", "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC"]]
            return []

    CheckRunner({})._discover_security_inventory(CaptureConnector())
    admin_query = next(query for query in CaptureConnector.queries if "from v$pwfile_users" in query)

    assert "sysrac" in admin_query
    assert "sysrac = 'true'" in admin_query


def test_admin_privilege_users_does_not_report_sys_system(example_config):
    _security(example_config)["admin_privilege_users"] = [
        {"username": "SYS", "sysdba": "TRUE"},
        {"username": "SYSTEM", "sysoper": "TRUE"},
    ]

    result = run_example_and_results(example_config)["admin_privilege_users"]

    assert result["status"] == ResultStatus.PASS.value
    assert result["evidence"]["affected_count"] == 0


def test_dictionary_access_privileges_filters_expected_grantees_and_reports_application_user(example_config):
    _security(example_config)["dictionary_access_privileges"] = [
        {"grantee": "SELECT_CATALOG_ROLE", "privilege": "SELECT ANY DICTIONARY"},
        {"grantee": "MDSYS", "privilege": "SELECT ANY DICTIONARY", "oracle_maintained": "Y"},
        {"grantee": "APP_READ", "granted_role": "SELECT_CATALOG_ROLE", "oracle_maintained": "N"},
    ]

    result = run_example_and_results(example_config)["dictionary_access_privileges"]

    assert result["status"] == ResultStatus.WARNING.value
    assert result["evidence"]["rows"] == [{"grantee": "APP_READ", "granted_role": "SELECT_CATALOG_ROLE", "oracle_maintained": "N"}]


def test_default_profile_users_filters_sys_system_and_reports_open_application_user(example_config):
    _security(example_config)["default_profile_users"] = [
        {"username": "SYS", "account_status": "OPEN", "profile": "DEFAULT"},
        {"username": "SYSTEM", "account_status": "OPEN", "profile": "DEFAULT"},
        {"username": "APP_OWNER", "account_status": "OPEN", "profile": "DEFAULT", "oracle_maintained": "N"},
    ]

    result = run_example_and_results(example_config)["default_profile_users"]

    assert result["status"] == ResultStatus.WARNING.value
    assert [row["username"] for row in result["evidence"]["rows"]] == ["APP_OWNER"]


def test_legacy_password_versions_reports_non_internal_legacy_user(example_config):
    _security(example_config)["legacy_password_versions"] = [
        {"username": "SYS", "password_versions": "10G 11G"},
        {"username": "APP_LEGACY", "password_versions": "10G", "oracle_maintained": "N"},
    ]

    result = run_example_and_results(example_config)["legacy_password_versions"]

    assert result["status"] == ResultStatus.WARNING.value
    assert result["evidence"]["rows"][0]["username"] == "APP_LEGACY"
