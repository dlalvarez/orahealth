from pathlib import Path

import pytest

from orahealthcheck.cli import main
from orahealthcheck.config_loader import ConfigLoader, ConfigSyntaxError, ConfigValidationError, ConfigValidator


def test_example_config_is_valid():
    config = ConfigLoader("config").load_all()
    assert ConfigValidator().validate(config) == []
    assert "example_standalone" in config["targets"]
    assert "database_status" in config["checks"]


def test_invalid_yaml_reports_file_line_column_and_cause(tmp_path):
    config_file = tmp_path / "app_settings.yaml"
    config_file.write_text("app: [unclosed\n", encoding="utf-8")
    loader = ConfigLoader(tmp_path)

    with pytest.raises(ConfigSyntaxError) as excinfo:
        loader.load_app_settings()

    message = str(excinfo.value)
    assert str(config_file) in message
    assert ":1:" in message
    assert "Invalid YAML" in message


def test_validate_config_prints_friendly_yaml_error_without_traceback(tmp_path, capsys):
    (tmp_path / "app_settings.yaml").write_text("app: [unclosed\n", encoding="utf-8")

    exit_code = main(["--config-dir", str(tmp_path), "validate-config"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Configuration syntax error" in captured.err
    assert "Invalid YAML" in captured.err
    assert "Traceback" not in captured.err


def test_yaml_comparison_operators_are_quoted_in_config_files():
    for path in Path("config").glob("**/*.yaml"):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            assert stripped not in {"operator: >=", "operator: <=", "operator: >", "operator: <"}, f"{path}:{line_number}"


def test_yaml_comparison_operators_parse_as_strings():
    config = ConfigLoader("config").load_all()
    operators = [check.evaluator.get("operator") for check in config["checks"].values() if "operator" in check.evaluator]
    assert ">=" in operators
    assert "<=" in operators
    assert all(isinstance(operator, str) for operator in operators)


def test_validate_config_rejects_unquoted_yaml_comparison_operator(tmp_path):
    check_file = tmp_path / "check.yaml"
    check_file.write_text("evaluator:\n  operator: >=\n", encoding="utf-8")
    config = {
        "_config_dir": str(tmp_path),
        "targets": {},
        "profiles": {},
        "groups": {},
        "checks": {},
        "connections": {"db_connections": {}, "os_connections": {}},
    }

    with pytest.raises(ConfigValidationError) as excinfo:
        ConfigValidator().validate(config)

    assert "must be quoted" in str(excinfo.value)
