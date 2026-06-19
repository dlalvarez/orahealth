from orahealthcheck.models import ResultStatus

from conftest import run_example_and_results


def _schema(config):
    return config["targets"]["example_standalone"].database["mock_inventory"].setdefault("schema_objects", {})


def test_tables_without_primary_key_filters_oracle_internal_and_reports_application_table(example_config):
    _schema(example_config)["tables_without_primary_key"] = [
        {"owner": "SYS", "table_name": "OBJ$", "oracle_maintained": "Y"},
        {"owner": "APP", "table_name": "ORDERS", "oracle_maintained": "N"},
    ]

    result = run_example_and_results(example_config)["tables_without_primary_key"]

    assert result["status"] == ResultStatus.WARNING.value
    assert result["evidence"]["rows"] == [{"owner": "APP", "table_name": "ORDERS", "oracle_maintained": "N"}]


def test_foreign_keys_without_index_passes_when_no_unindexed_foreign_keys(example_config):
    _schema(example_config)["foreign_keys_without_index"] = []

    result = run_example_and_results(example_config)["foreign_keys_without_index"]

    assert result["status"] == ResultStatus.PASS.value
    assert result["evidence"]["affected_count"] == 0


def test_foreign_keys_without_index_warns_when_missing_compatible_index(example_config):
    _schema(example_config)["foreign_keys_without_index"] = [{"owner": "APP", "table_name": "ORDER_LINES", "constraint_name": "FK_OL_ORDER", "columns": "ORDER_ID"}]

    result = run_example_and_results(example_config)["foreign_keys_without_index"]

    assert result["status"] == ResultStatus.WARNING.value
    assert result["evidence"]["affected_count"] == 1


def test_tables_with_long_columns_detects_application_long_column(example_config):
    _schema(example_config)["tables_with_long_columns"] = [{"owner": "APP", "table_name": "LEGACY_DOCS", "column_name": "BODY", "data_type": "LONG"}]

    result = run_example_and_results(example_config)["tables_with_long_columns"]

    assert result["status"] == ResultStatus.WARNING.value
    assert result["evidence"]["rows"][0]["data_type"] == "LONG"


def test_indexes_too_many_columns_respects_configured_threshold(example_config):
    _schema(example_config)["indexes_too_many_columns"] = [
        {"owner": "APP", "index_name": "IX_OK", "column_count": 8},
        {"owner": "APP", "index_name": "IX_TOO_WIDE", "column_count": 9},
    ]

    result = run_example_and_results(example_config)["indexes_too_many_columns"]

    assert result["status"] == ResultStatus.WARNING.value
    assert result["evidence"]["rows"] == [{"owner": "APP", "index_name": "IX_TOO_WIDE", "column_count": 9}]
