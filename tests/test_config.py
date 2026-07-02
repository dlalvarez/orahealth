from pathlib import Path

import pytest

from orahealthcheck.cli import main
from orahealthcheck.config_loader import ConfigLoader, ConfigSyntaxError, ConfigValidationError, ConfigValidator


def test_example_config_is_valid():
    config = ConfigLoader("config").load_all()
    assert ConfigValidator().validate(config) == []
    assert "example_standalone" in config["targets"]
    assert "database_status" in config["checks"]



def test_visible_check_titles_are_spanish(capsys):
    english_titles = [
        "Datafiles with autoextend disabled",
        "Temporary tablespace active usage percentage",
        "Tablespace used percentage",
        "Database status is OPEN",
        "OS CPU information can be collected",
    ]
    config = ConfigLoader("config").load_all()
    titles = "\n".join(check.title for check in config["checks"].values())
    for title in english_titles:
        assert title not in titles

    assert main(["list-checks"]) == 0
    output = capsys.readouterr().out
    assert "Datafiles con autoextend deshabilitado" in output
    assert "Porcentaje de uso activo de tablespaces temporales" in output
    for title in english_titles:
        assert title not in output

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


def test_loads_only_base_connection_and_target_files(tmp_path):
    (tmp_path / "connection_profiles.yaml").write_text(
        """
db_connections:
  base_db:
    type: oracle
    auth_method: password
os_connections:
  base_os:
    type: local
    auth_method: local
""",
        encoding="utf-8",
    )
    (tmp_path / "targets.yaml").write_text(
        """
targets:
  - target_id: base_target
    profile: standalone_basic
    database:
      primary_connection: base_db
    operating_system:
      connections:
        - base_os
""",
        encoding="utf-8",
    )

    loader = ConfigLoader(tmp_path)

    assert set(loader.load_connections()["db_connections"]) == {"base_db"}
    assert set(loader.load_connections()["os_connections"]) == {"base_os"}
    assert set(loader.load_targets()) == {"base_target"}


def test_loads_base_plus_local_connection_and_target_files(tmp_path):
    (tmp_path / "connection_profiles.yaml").write_text(
        """
db_connections:
  base_db:
    type: oracle
    auth_method: password
os_connections:
  base_os:
    type: local
    auth_method: local
""",
        encoding="utf-8",
    )
    (tmp_path / "connection_profiles.local.yaml").write_text(
        """
db_connections:
  local_db:
    type: oracle
    auth_method: env
    password_env: LOCAL_DB_PASSWORD
os_connections:
  local_os:
    type: ssh
    auth_method: private_key
""",
        encoding="utf-8",
    )
    (tmp_path / "targets.yaml").write_text(
        """
targets:
  - target_id: base_target
    profile: standalone_basic
""",
        encoding="utf-8",
    )
    (tmp_path / "targets.local.yaml").write_text(
        """
targets:
  - target_id: local_target
    profile: standalone_basic
""",
        encoding="utf-8",
    )

    loader = ConfigLoader(tmp_path)

    assert set(loader.load_connections()["db_connections"]) == {"base_db", "local_db"}
    assert set(loader.load_connections()["os_connections"]) == {"base_os", "local_os"}
    assert set(loader.load_targets()) == {"base_target", "local_target"}


def test_local_file_adds_connections(tmp_path):
    (tmp_path / "connection_profiles.yaml").write_text(
        """
db_connections:
  base_db:
    type: oracle
    auth_method: password
os_connections:
  base_os:
    type: local
    auth_method: local
""",
        encoding="utf-8",
    )
    (tmp_path / "connection_profiles.local.yaml").write_text(
        """
db_connections:
  added_db:
    type: oracle
    auth_method: env
os_connections:
  added_os:
    type: ssh
    auth_method: private_key
""",
        encoding="utf-8",
    )

    connections = ConfigLoader(tmp_path).load_connections()

    assert "added_db" in connections["db_connections"]
    assert "added_os" in connections["os_connections"]


def test_local_file_overwrites_connections_with_same_name(tmp_path):
    (tmp_path / "connection_profiles.yaml").write_text(
        """
db_connections:
  shared_db:
    type: oracle
    host: base.example.com
    auth_method: password
os_connections:
  shared_os:
    type: local
    username: base
    auth_method: local
""",
        encoding="utf-8",
    )
    (tmp_path / "connection_profiles.local.yaml").write_text(
        """
db_connections:
  shared_db:
    type: oracle
    host: local.example.com
    auth_method: env
os_connections:
  shared_os:
    type: ssh
    username: local
    auth_method: private_key
""",
        encoding="utf-8",
    )

    connections = ConfigLoader(tmp_path).load_connections()

    assert connections["db_connections"]["shared_db"].settings["host"] == "local.example.com"
    assert connections["db_connections"]["shared_db"].auth_method == "env"
    assert connections["os_connections"]["shared_os"].type == "ssh"
    assert connections["os_connections"]["shared_os"].settings["username"] == "local"


def test_local_file_adds_targets(tmp_path):
    (tmp_path / "targets.yaml").write_text(
        """
targets:
  - target_id: base_target
    profile: standalone_basic
""",
        encoding="utf-8",
    )
    (tmp_path / "targets.local.yaml").write_text(
        """
targets:
  - target_id: added_target
    name: Added Target
    profile: standalone_basic
""",
        encoding="utf-8",
    )

    targets = ConfigLoader(tmp_path).load_targets()

    assert set(targets) == {"base_target", "added_target"}
    assert targets["added_target"].name == "Added Target"


def test_local_file_overwrites_target_with_same_target_id(tmp_path):
    (tmp_path / "targets.yaml").write_text(
        """
targets:
  - target_id: shared_target
    name: Base Target
    environment: development
    profile: standalone_basic
""",
        encoding="utf-8",
    )
    (tmp_path / "targets.local.yaml").write_text(
        """
targets:
  - target_id: shared_target
    name: Local Target
    environment: production
    profile: standalone_basic
""",
        encoding="utf-8",
    )

    target = ConfigLoader(tmp_path).load_targets()["shared_target"]

    assert target.name == "Local Target"
    assert target.environment == "production"


def test_validate_config_fails_when_local_yaml_is_invalid(tmp_path, capsys):
    from shutil import copytree

    copytree("config", tmp_path, dirs_exist_ok=True)
    (tmp_path / "targets.local.yaml").write_text("targets: [unclosed\n", encoding="utf-8")

    exit_code = main(["--config-dir", str(tmp_path), "validate-config"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Configuration syntax error" in captured.err
    assert "targets.local.yaml" in captured.err


def test_validate_config_fails_when_local_target_references_missing_connection(tmp_path, capsys):
    from shutil import copytree

    copytree("config", tmp_path, dirs_exist_ok=True)
    (tmp_path / "targets.local.yaml").write_text(
        """
targets:
  - target_id: real_lab
    name: Real Lab
    environment: lab
    expected_architecture: standalone
    profile: standalone_basic
    database:
      primary_connection: missing_real_db
    operating_system:
      platform: linux
      connections:
        - local_oracle
""",
        encoding="utf-8",
    )

    exit_code = main(["--config-dir", str(tmp_path), "validate-config"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Configuration validation failed" in captured.err
    assert "Target real_lab references missing DB connection missing_real_db" in captured.err


def test_list_targets_includes_local_targets(tmp_path, capsys):
    from shutil import copytree

    copytree("config", tmp_path, dirs_exist_ok=True)
    (tmp_path / "connection_profiles.local.yaml").write_text(
        """
db_connections:
  lab_oracle:
    type: oracle
    auth_method: env
os_connections:
  lab_os:
    type: local
    auth_method: local
""",
        encoding="utf-8",
    )
    (tmp_path / "targets.local.yaml").write_text(
        """
targets:
  - target_id: lab_standalone
    name: Lab Standalone
    environment: lab
    expected_architecture: standalone
    profile: standalone_basic
    database:
      primary_connection: lab_oracle
    operating_system:
      platform: linux
      connections:
        - lab_os
""",
        encoding="utf-8",
    )

    exit_code = main(["--config-dir", str(tmp_path), "list-targets"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "example_standalone\tExample Standalone Database\tstandalone_basic" in captured.out
    assert "lab_standalone\tLab Standalone\tstandalone_basic" in captured.out


def test_run_accepts_optional_profile_override(monkeypatch, capsys):
    calls = []

    class DummyRunner:
        def __init__(self, config):
            self.config = config

        def run_target(self, target_id, profile_id=None):
            calls.append((target_id, profile_id))
            return Path("output/prueba")

    monkeypatch.setattr("orahealthcheck.cli.CheckRunner", DummyRunner)

    exit_code = main(["run", "--target", "example_standalone", "--profile", "standalone_all"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert calls == [("example_standalone", "standalone_all")]
    assert "Salida generada: output/prueba" in captured.out


def test_run_rejects_unknown_profile(capsys):
    exit_code = main(["run", "--target", "example_standalone", "--profile", "perfil_inexistente"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Perfil desconocido: perfil_inexistente" in captured.err

def test_standalone_all_profile_includes_rac_and_operational_readiness_without_changing_basic():
    config = ConfigLoader("config").load_all()

    standalone_all = config["profiles"]["standalone_all"]
    standalone_basic = config["profiles"]["standalone_basic"]

    assert "operational_readiness" in standalone_all.enabled_groups
    assert "rac" in standalone_all.enabled_groups
    assert "multitenant" in standalone_all.enabled_groups

    for group_id in [
        "rac",
        "multitenant",
        "operational_readiness",
        "performance",
        "capacity",
        "asm",
        "dataguard",
        "patching",
    ]:
        assert group_id not in standalone_basic.enabled_groups

    assert "asm" in standalone_all.enabled_groups
    assert "dataguard" in standalone_all.enabled_groups
    assert "performance" in standalone_all.enabled_groups
    assert "capacity" in standalone_all.enabled_groups
    assert "patching" in standalone_all.enabled_groups
