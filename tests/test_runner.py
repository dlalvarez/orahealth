import json
from pathlib import Path

from orahealthcheck.config_loader import ConfigLoader, ConfigValidator
from orahealthcheck.engine import CheckRunner


def _run_example(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    return CheckRunner(config).run_target("example_standalone")


def test_runner_generates_required_files(tmp_path):
    output = _run_example(tmp_path)
    expected = {
        "executive_report.html",
        "technical_report.html",
        "corrective_actions.html",
        "inventory.json",
        "evidence.json",
        "execution.log",
    }
    assert expected.issubset({path.name for path in Path(output).iterdir()})


def test_executive_report_contains_dashboard_sections(tmp_path):
    output = _run_example(tmp_path)
    html = (output / "executive_report.html").read_text(encoding="utf-8")

    assert "example_standalone" in html
    assert "Reporte Ejecutivo" in html
    assert "Información del target" in html
    assert "Puntaje de Salud" in html
    assert "Estado Global" in html
    assert "🟢 PASS / Correcto" in html
    assert "Resumen Ejecutivo" in html
    assert "Hallazgos Principales" in html


def test_technical_report_contains_inventory_grouped_checks_and_evidence(tmp_path):
    output = _run_example(tmp_path)
    html = (output / "technical_report.html").read_text(encoding="utf-8")

    assert "Reporte Técnico" in html
    assert "Información del target" in html
    assert "Inventario de Base de Datos" in html
    assert "Inventario del Sistema Operativo" in html
    assert "Configuración general" in html
    assert "<pre" in html
    assert "duration_ms" in html
    assert "Mínimo porcentaje libre en tablespaces" in html
    assert "CPU</span><strong>N/D" not in html
    assert "Memoria</span><strong>N/D" not in html
    assert "Filesystems</span><strong>N/D" not in html


def test_corrective_actions_report_shows_positive_message_when_clean(tmp_path):
    output = _run_example(tmp_path)
    html = (output / "corrective_actions.html").read_text(encoding="utf-8")

    assert "Acciones Correctivas" in html
    assert "Información del target" in html
    assert "No se requieren acciones correctivas." in html


def test_reports_show_password_env_but_never_real_password(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    profile = config["connections"]["db_connections"]["example_oracle"]
    profile.settings["password"] = "super_secret_password"
    profile.settings["password_env"] = "ORA_EXAMPLE_PASSWORD"

    output = CheckRunner(config).run_target("example_standalone")

    for report_name in ["executive_report.html", "technical_report.html", "corrective_actions.html"]:
        html = (output / report_name).read_text(encoding="utf-8")
        assert "ORA_EXAMPLE_PASSWORD" in html
        assert "super_secret_password" not in html



def test_evidence_json_has_minimum_structure(tmp_path):
    output = _run_example(tmp_path)
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))

    assert set(evidence) == {"summary", "results"}
    assert evidence["summary"]["global_status"]
    assert isinstance(evidence["summary"]["score"], int)
    assert len(evidence["results"]) == 24
    first_result = evidence["results"][0]
    assert {"check_id", "group_id", "status", "failure_severity", "evidence", "duration_ms"}.issubset(first_result)
    assert isinstance(first_result["duration_ms"], int)


def test_execution_log_contains_run_metadata(tmp_path):
    output = _run_example(tmp_path)
    log_text = (output / "execution.log").read_text(encoding="utf-8")

    assert "Target: example_standalone" in log_text
    assert "Profile: standalone_basic" in log_text
    assert "Enabled groups:" in log_text
    assert "Loaded checks (24):" in log_text
    assert "Executed checks (24):" in log_text
    assert "Skipped checks (0):" in log_text
    assert "Status summary:" in log_text
    assert f"Output directory: {output}" in log_text
    assert "Total duration_ms:" in log_text


class FakeOracleConnector:
    queries: list[str] = []
    rows_by_marker: dict[str, list[dict]] = {}
    connected = False
    closed = False

    def __init__(self, profile):
        self.profile = profile

    def connect(self):
        type(self).connected = True

    def close(self):
        type(self).closed = True

    def query(self, sql: str):
        normalized = " ".join(sql.lower().split())
        type(self).queries.append(normalized)
        for marker, rows in self.rows_by_marker.items():
            if marker in normalized:
                return rows
        return []


def _oracle_configuration_rows():
    return [
        {"name": "compatible", "value": "19.0.0", "display_value": "19.0.0", "isdefault": "FALSE"},
        {"name": "optimizer_features_enable", "value": "19.1.0", "display_value": "19.1.0", "isdefault": "TRUE"},
        {"name": "db_block_size", "value": 8192, "display_value": 8192, "isdefault": "TRUE"},
        {"name": "open_cursors", "value": 500, "display_value": 500, "isdefault": "FALSE"},
        {"name": "processes", "value": 500, "display_value": 500, "isdefault": "FALSE"},
        {"name": "sessions", "value": 776, "display_value": 776, "isdefault": "TRUE"},
        {"name": "audit_trail", "value": "DB", "display_value": "DB", "isdefault": "FALSE"},
        {"name": "remote_login_passwordfile", "value": "EXCLUSIVE", "display_value": "EXCLUSIVE", "isdefault": "TRUE"},
        {"name": "recyclebin", "value": "ON", "display_value": "ON", "isdefault": "TRUE"},
        {"name": "filesystemio_options", "value": "SETALL", "display_value": "SETALL", "isdefault": "FALSE"},
    ]


def _oracle_configuration_markers():
    return {
        "from v$parameter": _oracle_configuration_rows(),
        "from v$controlfile": [{"control_file_count": 2}],
        "from v$log group": [{"redo_log_group_count": 3}],
        "from v$logfile": [
            {"group_number": 1, "member_count": 2},
            {"group_number": 2, "member_count": 2},
            {"group_number": 3, "member_count": 2},
        ],
    }


def _real_config(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    target = config["targets"]["example_standalone"]
    target.database = {"primary_connection": "example_oracle"}
    target.operating_system["connections"] = []
    return config


def test_mock_target_does_not_use_oracle_connector(tmp_path):
    class FailingConnector:
        def __init__(self, profile):
            raise AssertionError("OracleConnector should not be used for mock_inventory targets")

    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    output = CheckRunner(config, oracle_connector_factory=FailingConnector).run_target("example_standalone")

    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    assert inventory["database"]["archivelog_mode"] == "ARCHIVELOG"


def test_real_target_without_mock_inventory_uses_oracle_connector(tmp_path):
    FakeOracleConnector.queries = []
    FakeOracleConnector.connected = False
    FakeOracleConnector.closed = False
    FakeOracleConnector.rows_by_marker = {
        "from v$database": [{"open_mode": "READ WRITE", "role": "PRIMARY", "archivelog_mode": "ARCHIVELOG", "force_logging": "YES"}],
        "from v$instance": [{"status": "OPEN", "version": "19.20.0.0.0"}],
        "from dba_objects": [{"invalid_objects_count": 2}],
        "from dba_data_files": [{"tablespace_min_free_pct": 25.5}],
        "from v$recovery_file_dest": [{"space_limit": 100, "space_used": 30, "fra_used_pct": 30}],
        **_oracle_configuration_markers(),
    }
    config = _real_config(tmp_path)

    output = CheckRunner(config, oracle_connector_factory=FakeOracleConnector).run_target("example_standalone")
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))["database"]

    assert FakeOracleConnector.connected is True
    assert FakeOracleConnector.closed is True
    assert inventory["archivelog_mode"] == "ARCHIVELOG"
    assert inventory["tablespace_min_free_pct"] == 25.5
    assert inventory["fra_used_pct"] == 30
    assert inventory["fra_configured"] is True
    assert inventory["invalid_objects_count"] == 2


def test_fra_not_configured_is_skipped_not_error(tmp_path):
    FakeOracleConnector.queries = []
    FakeOracleConnector.rows_by_marker = {
        "from v$database": [{"open_mode": "READ WRITE", "role": "PRIMARY", "archivelog_mode": "ARCHIVELOG", "force_logging": "YES"}],
        "from v$instance": [{"status": "OPEN", "version": "19.20.0.0.0"}],
        "from dba_objects": [{"invalid_objects_count": 0}],
        "from dba_data_files": [{"tablespace_min_free_pct": 25.5}],
        "from v$recovery_file_dest": [{"space_limit": 0, "space_used": 0, "fra_used_pct": None}],
        **_oracle_configuration_markers(),
    }
    config = _real_config(tmp_path)

    output = CheckRunner(config, oracle_connector_factory=FakeOracleConnector).run_target("example_standalone")
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    fra_result = next(result for result in evidence["results"] if result["check_id"] == "fra_usage")

    assert fra_result["status"] == "SKIPPED"
    assert "FRA is not configured" in fra_result["message"]


def test_real_metrics_drive_tablespace_fra_and_invalid_object_results(tmp_path):
    FakeOracleConnector.queries = []
    FakeOracleConnector.rows_by_marker = {
        "from v$database": [{"open_mode": "READ WRITE", "role": "PRIMARY", "archivelog_mode": "ARCHIVELOG", "force_logging": "YES"}],
        "from v$instance": [{"status": "OPEN", "version": "19.20.0.0.0"}],
        "from dba_objects": [{"invalid_objects_count": 21}],
        "from dba_data_files": [{"tablespace_min_free_pct": 4.5}],
        "from v$recovery_file_dest": [{"space_limit": 100, "space_used": 96, "fra_used_pct": 96}],
        **_oracle_configuration_markers(),
    }
    config = _real_config(tmp_path)

    output = CheckRunner(config, oracle_connector_factory=FakeOracleConnector).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["tablespace_free_pct"]["status"] == "CRITICAL"
    assert results["fra_usage"]["status"] == "CRITICAL"
    assert results["invalid_objects"]["status"] == "FAIL"

    corrective_html = (output / "corrective_actions.html").read_text(encoding="utf-8")
    assert "🛑 CRITICAL" in corrective_html
    assert "🔴 FAIL" in corrective_html
    assert "Responsable: DBA" in corrective_html
    assert "Requiere ventana" in corrective_html
    assert "Riesgo de indisponibilidad" in corrective_html
    assert "Acciones recomendadas" in corrective_html


def test_missing_oracle_configuration_metric_is_controlled_error(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    target = config["targets"]["example_standalone"]
    target.database["mock_inventory"].get("parameters", {}).pop("open_cursors", None)

    output = CheckRunner(config).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["open_cursors"]["status"] == "ERROR"
    assert "No se encontró evidencia" in results["open_cursors"]["message"]
    assert results["open_cursors"]["error"] is None
