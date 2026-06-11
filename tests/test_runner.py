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


def test_reports_use_compact_professional_css(tmp_path):
    output = _run_example(tmp_path)

    for report_name in ["executive_report.html", "technical_report.html", "corrective_actions.html"]:
        html = (output / report_name).read_text(encoding="utf-8")
        assert 'font-family:"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif' in html
        assert "font-size:13px" in html
        assert "line-height:1.35" in html
        assert "max-width:1440px" in html
        assert "padding:4px 8px" in html
        assert "font-size:11px" in html

    technical_html = (output / "technical_report.html").read_text(encoding="utf-8")
    assert "max-height:190px" in technical_html


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


def test_technical_report_omits_remediation_column_and_text(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    mock_inventory = config["targets"]["example_standalone"].database["mock_inventory"]
    mock_inventory["archivelog_mode"] = "NOARCHIVELOG"
    mock_inventory["parameters"]["open_cursors"]["value"] = 100
    mock_inventory["parameters"]["open_cursors"]["display_value"] = 100

    output = CheckRunner(config).run_target("example_standalone")
    technical_html = (output / "technical_report.html").read_text(encoding="utf-8")
    corrective_html = (output / "corrective_actions.html").read_text(encoding="utf-8")

    assert "<th>Remediación</th>" not in technical_html
    assert "No requiere remediación." not in technical_html
    assert "Validación informativa." not in technical_html
    assert "Un valor bajo de open_cursors puede provocar errores ORA-01000" not in technical_html
    assert "Revisar alert log, trazas y monitoreo de aplicación" not in technical_html
    assert "La base de datos no está operando en modo ARCHIVELOG" not in technical_html
    assert "Confirmar con el negocio y el equipo DBA" not in technical_html
    assert "<pre" in technical_html
    assert "duration_ms" in technical_html
    assert "skipped_reason" in technical_html
    assert "error" in technical_html
    assert "Revisar alert log, trazas y monitoreo de aplicación" in corrective_html
    assert "Confirmar con el negocio y el equipo DBA" in corrective_html


def test_technical_report_keeps_skipped_reason_and_error_without_remediation(tmp_path):
    skipped_config = ConfigLoader("config").load_all()
    ConfigValidator().validate(skipped_config)
    skipped_config["settings"]["app"]["default_output_dir"] = str(tmp_path / "skipped")
    skipped_config["targets"]["example_standalone"].expected_architecture = "unsupported"

    skipped_output = CheckRunner(skipped_config).run_target("example_standalone")
    skipped_html = (skipped_output / "technical_report.html").read_text(encoding="utf-8")

    assert "Architecture unsupported is not applicable" in skipped_html
    assert "<th>Remediación</th>" not in skipped_html
    assert "La instancia de base de datos no reporta un estado operativo esperado" not in skipped_html

    error_config = ConfigLoader("config").load_all()
    ConfigValidator().validate(error_config)
    error_config["settings"]["app"]["default_output_dir"] = str(tmp_path / "error")
    error_config["checks"]["open_cursors"].collector["type"] = "unsupported"

    error_output = CheckRunner(error_config).run_target("example_standalone")
    error_html = (error_output / "technical_report.html").read_text(encoding="utf-8")

    assert "Unsupported collector type unsupported" in error_html
    assert "<th>Remediación</th>" not in error_html
    assert "Un valor bajo de open_cursors puede provocar errores ORA-01000" not in error_html


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
    assert len(evidence["results"]) == 32
    first_result = evidence["results"][0]
    assert {"check_id", "group_id", "status", "failure_severity", "evidence", "duration_ms"}.issubset(first_result)
    assert isinstance(first_result["duration_ms"], int)


def test_execution_log_contains_run_metadata(tmp_path):
    output = _run_example(tmp_path)
    log_text = (output / "execution.log").read_text(encoding="utf-8")

    assert "Target: example_standalone" in log_text
    assert "Profile: standalone_basic" in log_text
    assert "Enabled groups:" in log_text
    assert "Loaded checks (32):" in log_text
    assert "Executed checks (32):" in log_text
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
                if isinstance(rows, Exception):
                    raise rows
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




def _storage_markers(tablespace_free_pct=25.5, fra_used_pct=30, fra_space_limit=100, datafile_used_of_max_pct=10, datafile_status="AVAILABLE", datafile_online_status="ONLINE", temp_used_pct=12.5, temp_active_segments_count=1):
    return {
        "from ( select tablespace_name, sum(bytes) as bytes": [
            {
                "tablespace_name": "USERS",
                "total_mb": 1024,
                "used_mb": round(1024 * (100 - tablespace_free_pct) / 100, 2),
                "free_mb": round(1024 * tablespace_free_pct / 100, 2),
                "free_pct": tablespace_free_pct,
                "used_pct": 100 - tablespace_free_pct,
                "autoextensible": "YES",
            }
        ],
        "from dba_data_files order by": [
            {
                "file_name": "/u01/oradata/ORCL/users01.dbf",
                "tablespace_name": "USERS",
                "bytes_mb": 1024,
                "current_mb": 1024,
                "autoextensible": "YES",
                "maxbytes_mb": 10240,
                "max_mb": 10240,
                "used_of_max_pct": datafile_used_of_max_pct,
                "status": datafile_status,
                "online_status": datafile_online_status,
            }
        ],
        "from dba_temp_files order by": [
            {"tablespace_name": "TEMP", "file_name": "/u01/oradata/ORCL/temp01.dbf", "bytes_mb": 1024, "status": "AVAILABLE", "autoextensible": "YES"}
        ],
        "from v$tempseg_usage": [
            {"tablespace_name": "TEMP", "total_mb": 1024, "used_mb": round(1024 * temp_used_pct / 100, 2), "free_mb": round(1024 * (100 - temp_used_pct) / 100, 2), "used_pct": temp_used_pct, "active_temp_segments_count": temp_active_segments_count, "active_temp_sessions_count": temp_active_segments_count, "source": "dba_temp_files+v$tempseg_usage", "calculation_method": "active_temp_segments", "note": "Uso activo calculado desde segmentos temporales actualmente asignados a sesiones."}
        ],
        "from dba_tablespaces t": [
            {"tablespace_name": "UNDOTBS1", "status": "ONLINE", "total_mb": 2048, "used_mb": 256, "free_mb": 1792}
        ],
        "from v$recovery_file_dest": [
            {"recovery_file_dest": "/u01/fra", "space_limit": fra_space_limit, "space_used": fra_space_limit * fra_used_pct / 100 if fra_space_limit else 0, "space_reclaimable": 0, "space_limit_mb": fra_space_limit, "space_used_mb": fra_space_limit * fra_used_pct / 100 if fra_space_limit else 0, "space_reclaimable_mb": 0, "used_pct": fra_used_pct if fra_space_limit else None, "reclaimable_pct": 0}
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
        **_storage_markers(tablespace_free_pct=25.5, fra_used_pct=30),
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
        **_storage_markers(tablespace_free_pct=25.5, fra_used_pct=None, fra_space_limit=0),
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
        **_storage_markers(tablespace_free_pct=4.5, fra_used_pct=96),
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



def test_storage_checks_pass_for_healthy_mock_inventory(tmp_path):
    output = _run_example(tmp_path)
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    for check_id in ["tablespace_free_pct", "tablespace_used_pct", "datafiles_near_maxsize", "datafiles_status", "tempfiles_status", "temp_usage_pct", "undo_tablespace_status", "fra_configured", "fra_usage"]:
        assert results[check_id]["status"] == "PASS"


def test_storage_tablespace_datafile_warning_and_fail_paths(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    storage = config["targets"]["example_standalone"].database["mock_inventory"]["storage"]
    storage["tablespaces"][1]["free_pct"] = 8.5
    storage["tablespaces"][1]["used_pct"] = 91.5
    storage["datafiles"][1]["used_of_max_pct"] = 97
    storage["datafiles"][1]["online_status"] = "RECOVER"

    output = CheckRunner(config).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["tablespace_free_pct"]["status"] == "FAIL"
    assert results["tablespace_free_pct"]["evidence"]["worst_tablespace"] == "USERS"
    assert results["tablespace_used_pct"]["status"] == "FAIL"
    assert results["datafiles_near_maxsize"]["status"] == "FAIL"
    assert results["datafiles_status"]["status"] == "FAIL"
    technical_html = (output / "technical_report.html").read_text(encoding="utf-8")
    corrective_html = (output / "corrective_actions.html").read_text(encoding="utf-8")
    assert "Aumentar maxsize si hay capacidad" not in technical_html
    assert "Aumentar maxsize si hay capacidad" in corrective_html



def test_temp_usage_active_zero_passes_with_real_metric_source(tmp_path):
    FakeOracleConnector.queries = []
    FakeOracleConnector.rows_by_marker = {
        "from v$database": [{"open_mode": "READ WRITE", "role": "PRIMARY", "archivelog_mode": "ARCHIVELOG", "force_logging": "YES"}],
        "from v$instance": [{"status": "OPEN", "version": "19.20.0.0.0"}],
        "from dba_objects": [{"invalid_objects_count": 0}],
        **_storage_markers(temp_used_pct=0, temp_active_segments_count=0),
        **_oracle_configuration_markers(),
    }
    config = _real_config(tmp_path)

    output = CheckRunner(config, oracle_connector_factory=FakeOracleConnector).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["temp_usage_pct"]["status"] == "PASS"
    assert "active usage" in results["temp_usage_pct"]["message"]
    assert results["temp_usage_pct"]["evidence"]["active_temp_segments_count"] == 0
    assert results["temp_usage_pct"]["evidence"]["calculation_method"] == "active_temp_segments"


def test_temp_usage_high_active_usage_fails(tmp_path):
    FakeOracleConnector.queries = []
    FakeOracleConnector.rows_by_marker = {
        "from v$database": [{"open_mode": "READ WRITE", "role": "PRIMARY", "archivelog_mode": "ARCHIVELOG", "force_logging": "YES"}],
        "from v$instance": [{"status": "OPEN", "version": "19.20.0.0.0"}],
        "from dba_objects": [{"invalid_objects_count": 0}],
        **_storage_markers(temp_used_pct=98, temp_active_segments_count=5),
        **_oracle_configuration_markers(),
    }
    config = _real_config(tmp_path)

    output = CheckRunner(config, oracle_connector_factory=FakeOracleConnector).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["temp_usage_pct"]["status"] == "FAIL"
    assert results["temp_usage_pct"]["evidence"]["max_used_pct"] == 98
    assert results["temp_usage_pct"]["evidence"]["active_temp_segments_count"] == 5


def test_temp_usage_without_active_view_is_skipped_with_fallback_evidence(tmp_path):
    FakeOracleConnector.queries = []
    FakeOracleConnector.rows_by_marker = {
        "from v$database": [{"open_mode": "READ WRITE", "role": "PRIMARY", "archivelog_mode": "ARCHIVELOG", "force_logging": "YES"}],
        "from v$instance": [{"status": "OPEN", "version": "19.20.0.0.0"}],
        "from dba_objects": [{"invalid_objects_count": 0}],
        "from v$tempseg_usage": RuntimeError("ORA-00942: table or view does not exist"),
        "from v$temp_space_header": [
            {"tablespace_name": "TEMP", "total_mb": 130, "used_mb": 130, "free_mb": 0, "used_pct": 100, "source": "dba_temp_files+v$temp_space_header", "calculation_method": "fallback_temp_space_header"}
        ],
        **{key: value for key, value in _storage_markers().items() if key not in {"from v$tempseg_usage"}},
        **_oracle_configuration_markers(),
    }
    config = _real_config(tmp_path)

    output = CheckRunner(config, oracle_connector_factory=FakeOracleConnector).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["temp_usage_pct"]["status"] == "SKIPPED"
    assert "v$tempseg_usage" in results["temp_usage_pct"]["message"]
    assert results["temp_usage_pct"]["evidence"]["active_usage_available"] is False
    assert results["temp_usage_pct"]["evidence"]["calculation_method"] == "fallback_temp_space_header"

def test_fra_configured_check_can_skip_when_fra_missing(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    storage = config["targets"]["example_standalone"].database["mock_inventory"]["storage"]
    storage["fra"] = {"fra_configured": False, "recovery_file_dest": None, "recovery_file_dest_size": None, "message": "FRA is not configured or space_limit is 0"}
    config["targets"]["example_standalone"].database["mock_inventory"]["fra_configured"] = False

    output = CheckRunner(config).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["fra_configured"]["status"] == "SKIPPED"
    assert results["fra_usage"]["status"] == "SKIPPED"

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
