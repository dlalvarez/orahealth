import json
import logging
from pathlib import Path

from orahealthcheck.config_loader import ConfigLoader, ConfigValidator
from orahealthcheck.engine import CheckRunner
from orahealthcheck.models import Check, Inventory, Target


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
        "evidence_report.html",
        "inventory.json",
        "evidence.json",
        "execution.log",
    }
    assert expected.issubset({path.name for path in Path(output).iterdir()})


def test_inventory_includes_oracle_features(tmp_path):
    output = _run_example(tmp_path)
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))

    assert set(["oracle_rac", "multitenant", "standby_configuration", "fra_configured", "flashback_database"]).issubset(inventory["features"])
    assert inventory["features"]["oracle_rac"]["status"] in {"detected", "not_detected", "unknown", "skipped", "error"}


def test_runner_skips_check_when_required_feature_is_not_detected(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    profile = config["profiles"][config["targets"]["example_standalone"].profile]
    first_group_id = profile.enabled_groups[0]
    config["groups"][first_group_id].checks.insert(0, "applicability_requires_rac")
    config["checks"]["applicability_requires_rac"] = Check(
        check_id="applicability_requires_rac",
        group_id=first_group_id,
        title="Validación ficticia con aplicabilidad RAC",
        collector={"type": "inventory", "source": "database", "field": "status"},
        evaluator={"type": "expected_value", "expected": "OPEN"},
        applicability={"requires_feature": "oracle_rac"},
    )

    output = CheckRunner(config).run_target("example_standalone")
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    result = next(item for item in evidence["results"] if item["check_id"] == "applicability_requires_rac")

    assert result["status"] == "SKIPPED"
    assert "no está detectada" in result["skipped_reason"]
    assert result["evidence"]["required_feature"] == "oracle_rac"
    assert evidence["summary"]["score"] == 100


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



def test_reports_do_not_show_legacy_english_storage_text(tmp_path):
    output = _run_example(tmp_path)
    combined_html = "\n".join(
        (output / report_name).read_text(encoding="utf-8")
        for report_name in ["executive_report.html", "technical_report.html", "corrective_actions.html", "evidence_report.html"]
    )

    assert "Porcentaje de uso activo de tablespaces temporales" in combined_html
    assert "El uso activo de tablespace temporal" in combined_html
    assert "Remediación" not in (output / "technical_report.html").read_text(encoding="utf-8")
    for legacy_text in [
        "Datafiles with autoextend disabled",
        "Temporary tablespace active usage percentage",
        "Tablespace used percentage",
        "All datafiles are AVAILABLE/ONLINE",
        "Regex condition passed",
    ]:
        assert legacy_text not in combined_html

def test_reports_use_compact_professional_css(tmp_path):
    output = _run_example(tmp_path)

    for report_name in ["executive_report.html", "technical_report.html", "corrective_actions.html", "evidence_report.html"]:
        html = (output / report_name).read_text(encoding="utf-8")
        assert 'font-family:"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif' in html
        assert "font-size:13px" in html
        assert "line-height:1.35" in html
        assert "max-width:1440px" in html
        assert "padding:4px 8px" in html
        assert "font-size:11px" in html

    technical_html = (output / "technical_report.html").read_text(encoding="utf-8")
    assert "max-height:190px" in technical_html


def test_technical_report_contains_inventory_grouped_checks_without_evidence_column(tmp_path):
    output = _run_example(tmp_path)
    html = (output / "technical_report.html").read_text(encoding="utf-8")

    assert "Reporte Técnico" in html
    assert "Información del target" in html
    assert "Inventario de Base de Datos" in html
    assert "Inventario del Sistema Operativo" in html
    assert "Configuración general" in html
    assert "<th>Evidencia</th>" not in html
    assert ">Evidencia<" not in html
    assert "<pre" not in html
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
    assert "<th>Evidencia</th>" not in technical_html
    assert "<pre" not in technical_html
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

    assert "La arquitectura unsupported no aplica" in skipped_html
    assert "<th>Remediación</th>" not in skipped_html
    assert "La instancia de base de datos no reporta un estado operativo esperado" not in skipped_html

    error_config = ConfigLoader("config").load_all()
    ConfigValidator().validate(error_config)
    error_config["settings"]["app"]["default_output_dir"] = str(tmp_path / "error")
    error_config["checks"]["open_cursors"].collector["type"] = "unsupported"

    error_output = CheckRunner(error_config).run_target("example_standalone")
    error_html = (error_output / "technical_report.html").read_text(encoding="utf-8")

    assert "Tipo de colector no soportado: unsupported" in error_html
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

    for report_name in ["executive_report.html", "technical_report.html", "corrective_actions.html", "evidence_report.html"]:
        html = (output / report_name).read_text(encoding="utf-8")
        assert "ORA_EXAMPLE_PASSWORD" in html
        assert "super_secret_password" not in html



def test_evidence_report_contains_target_summary_groups_and_collapsed_details(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    config["checks"]["open_cursors"].collector["type"] = "unsupported"

    output = CheckRunner(config).run_target("example_standalone")
    html = (output / "evidence_report.html").read_text(encoding="utf-8")

    assert "Reporte de Evidencias Técnicas" in html
    assert "Información del target" in html
    assert "example_standalone" in html
    assert "Resumen Global" in html
    assert "Puntaje de Salud" in html
    assert "Inventario Técnico" in html
    assert "Evidencias por grupo funcional" in html
    assert "Configuración general" in html
    assert "<details" in html and "evidence-item" in html
    assert "database_status" in html
    assert "SKIPPED / Omitido" in html
    assert "ERROR / Error" in html
    assert "skipped_reason" in html
    assert "La versión Oracle" in html
    assert "error" in html
    assert "Tipo de colector no soportado: unsupported" in html
    assert "Evidencia completa" in html
    assert "No hay evidencia estructurada para esta validación." in html
    assert "Acciones recomendadas" not in html
    assert "Requiere ventana" not in html


def test_evidence_report_includes_pass_info_and_complete_json(tmp_path):
    output = _run_example(tmp_path)
    html = (output / "evidence_report.html").read_text(encoding="utf-8")

    assert "PASS / Correcto" in html
    assert "INFO / Informativo" in html
    assert "Evidencia completa" in html
    assert "<pre" in html


def test_evidence_json_has_minimum_structure(tmp_path):
    output = _run_example(tmp_path)
    evidence = json.loads((output / "evidence.json").read_text(encoding="utf-8"))

    assert set(evidence) == {"summary", "results"}
    assert evidence["summary"]["global_status"]
    assert isinstance(evidence["summary"]["score"], int)
    assert len(evidence["results"]) == 108
    first_result = evidence["results"][0]
    assert {"check_id", "group_id", "status", "failure_severity", "evidence", "duration_ms"}.issubset(first_result)
    assert isinstance(first_result["duration_ms"], int)


def test_execution_log_contains_run_metadata(tmp_path):
    output = _run_example(tmp_path)
    log_text = (output / "execution.log").read_text(encoding="utf-8")

    assert "Target: example_standalone" in log_text
    assert "Profile: standalone_basic" in log_text
    assert "Enabled groups:" in log_text
    assert "Loaded checks (108):" in log_text
    assert "Executed checks (94):" in log_text
    assert "Skipped checks (14):" in log_text
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
    assert "FRA no está configurada" in fra_result["message"]


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
    assert "uso activo" in results["temp_usage_pct"]["message"]
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
    storage["fra"] = {"fra_configured": False, "recovery_file_dest": None, "recovery_file_dest_size": None, "message": "FRA no está configurada o space_limit es 0"}
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


def test_security_checks_pass_for_healthy_mock_inventory(tmp_path):
    output = _run_example(tmp_path)
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    for check_id in [
        "locked_users",
        "expired_users",
        "default_open_users",
        "default_profile_users",
        "dba_role_users",
        "critical_privilege_users",
        "remote_login_passwordfile_security",
        "audit_trail_security",
        "permissive_failed_login_profiles",
        "unlimited_password_life_profiles",
        "missing_password_verify_profiles",
        "common_accounts_not_locked_or_expired",
    ]:
        assert results[check_id]["status"] == "PASS"
    assert results["sec_case_sensitive_logon"]["status"] == "SKIPPED"


def test_security_findings_generate_corrective_actions(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    security = config["targets"]["example_standalone"].database["mock_inventory"]["security"]
    security["default_open_users"] = [{"username": "SCOTT", "account_status": "OPEN"}]
    security["dba_role_users"] = [{"grantee": "APP_ADMIN", "granted_role": "DBA"}]

    output = CheckRunner(config).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["default_open_users"]["status"] == "FAIL"
    assert results["dba_role_users"]["status"] == "FAIL"
    assert "Se detectaron 1 hallazgo" in results["default_open_users"]["message"]
    corrective_html = (output / "corrective_actions.html").read_text(encoding="utf-8")
    assert "Cuentas default abiertas" in corrective_html
    assert "Bloquear y expirar cuentas default no utilizadas" in corrective_html


def test_security_account_status_predicates_are_precise():
    class CaptureConnector:
        queries = []

        def query(self, sql: str):
            normalized = " ".join(sql.lower().split())
            type(self).queries.append(normalized)
            return []

    CaptureConnector.queries = []
    CheckRunner({})._discover_security_inventory(CaptureConnector())
    joined = "\n".join(CaptureConnector.queries)
    common_query = next(query for query in CaptureConnector.queries if "where username in" in query and "account_status not like '%locked%'" in query)

    assert "where account_status like '%locked%'" in joined
    assert "where account_status like 'expired%' and account_status not like '%locked%'" in joined
    assert "account_status not like '%expired%'" not in common_query


def test_locked_users_are_informational_inventory(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    security = config["targets"]["example_standalone"].database["mock_inventory"]["security"]
    security["locked_users"] = [{"username": "MDSYS", "account_status": "EXPIRED & LOCKED"}]

    output = CheckRunner(config).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["locked_users"]["status"] == "INFO"
    assert results["locked_users"]["failure_severity"] == "INFO"
    assert "Usuarios bloqueados registrados" in results["locked_users"]["message"]


def test_expired_common_accounts_are_findings_until_locked(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    security = config["targets"]["example_standalone"].database["mock_inventory"]["security"]
    security["common_accounts_not_locked_or_expired"] = [{"username": "XDB", "account_status": "EXPIRED(GRACE)"}]

    output = CheckRunner(config).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["common_accounts_not_locked_or_expired"]["status"] == "FAIL"
    assert "Cuentas comunes/default que no están bloqueadas" in results["common_accounts_not_locked_or_expired"]["message"]


def test_dba_role_users_does_not_fail_for_sys_and_system_only(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    security = config["targets"]["example_standalone"].database["mock_inventory"]["security"]
    security["dba_role_users"] = [
        {"grantee": "SYS", "granted_role": "DBA", "grantee_type": "USER", "oracle_maintained": "Y"},
        {"grantee": "SYSTEM", "granted_role": "DBA", "grantee_type": "USER", "oracle_maintained": "Y"},
    ]

    output = CheckRunner(config).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["dba_role_users"]["status"] == "PASS"
    assert results["dba_role_users"]["evidence"]["affected_count"] == 0
    assert results["dba_role_users"]["evidence"]["excluded_count"] == 2


def test_dba_role_users_fails_for_application_user_with_dba(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    security = config["targets"]["example_standalone"].database["mock_inventory"]["security"]
    security["dba_role_users"] = [
        {"grantee": "APP_ADMIN", "granted_role": "DBA", "grantee_type": "USER", "oracle_maintained": "N", "account_status": "OPEN"},
    ]

    output = CheckRunner(config).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["dba_role_users"]["status"] == "FAIL"
    assert results["dba_role_users"]["evidence"]["rows"][0]["grantee"] == "APP_ADMIN"
    assert "no esperados con rol DBA" in results["dba_role_users"]["message"]


def test_critical_privilege_users_does_not_penalize_oracle_maintained_users(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    security = config["targets"]["example_standalone"].database["mock_inventory"]["security"]
    security["critical_privilege_users"] = [
        {
            "grantee": "GGSYS",
            "privilege": "SELECT ANY DICTIONARY",
            "admin_option": "NO",
            "grantee_type": "USER",
            "account_status": "LOCKED",
            "oracle_maintained": "Y",
            "role_oracle_maintained": None,
            "common": "NO",
            "profile": "DEFAULT",
        },
        {
            "grantee": "AUDSYS",
            "privilege": "ALTER SYSTEM",
            "admin_option": "NO",
            "grantee_type": "USER",
            "account_status": "LOCKED",
            "oracle_maintained": "Y",
            "role_oracle_maintained": None,
            "common": "NO",
            "profile": "DEFAULT",
        },
    ]

    output = CheckRunner(config).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["critical_privilege_users"]["status"] == "PASS"
    assert results["critical_privilege_users"]["evidence"]["affected_count"] == 0
    assert results["critical_privilege_users"]["evidence"]["excluded_count"] == 2
    assert "allowlist" not in results["critical_privilege_users"]["evidence"]["classification_note"].lower()


def test_critical_privilege_users_does_not_penalize_oracle_maintained_roles(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    security = config["targets"]["example_standalone"].database["mock_inventory"]["security"]
    security["critical_privilege_users"] = [
        {
            "grantee": "DV_REALM_OWNER",
            "privilege": "ALTER SYSTEM",
            "admin_option": "NO",
            "grantee_type": "ROLE",
            "account_status": None,
            "oracle_maintained": None,
            "role_oracle_maintained": "Y",
            "common": None,
            "profile": None,
        },
        {
            "grantee": "EM_EXPRESS_ALL",
            "privilege": "SELECT ANY DICTIONARY",
            "admin_option": "NO",
            "grantee_type": "ROLE",
            "account_status": None,
            "oracle_maintained": None,
            "role_oracle_maintained": "Y",
            "common": None,
            "profile": None,
        },
    ]

    output = CheckRunner(config).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["critical_privilege_users"]["status"] == "PASS"
    assert results["critical_privilege_users"]["evidence"]["affected_count"] == 0
    assert results["critical_privilege_users"]["evidence"]["excluded_count"] == 2


def test_critical_privilege_users_fails_for_non_oracle_maintained_user(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    security = config["targets"]["example_standalone"].database["mock_inventory"]["security"]
    security["critical_privilege_users"] = [
        {"grantee": "PROMETHEUS", "privilege": "SELECT ANY DICTIONARY", "admin_option": "NO", "grantee_type": "USER", "account_status": "OPEN", "oracle_maintained": "N", "role_oracle_maintained": None, "common": "NO", "profile": "DEFAULT"},
    ]

    output = CheckRunner(config).run_target("example_standalone")
    results = {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}

    assert results["critical_privilege_users"]["status"] == "FAIL"
    assert results["critical_privilege_users"]["evidence"]["rows"][0]["grantee"] == "PROMETHEUS"
    assert "no esperados con privilegios críticos" in results["critical_privilege_users"]["message"]



def _run_with_schema_objects(tmp_path, schema_objects):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    config["targets"]["example_standalone"].database["mock_inventory"]["schema_objects"] = schema_objects
    output = CheckRunner(config).run_target("example_standalone")
    return {result["check_id"]: result for result in json.loads((output / "evidence.json").read_text(encoding="utf-8"))["results"]}


def test_schema_objects_advanced_checks_pass_with_clean_inventory(tmp_path):
    results = _run_with_schema_objects(tmp_path, {})

    for check_id in [
        "invalid_objects_detail",
        "unusable_indexes",
        "unusable_index_partitions",
        "disabled_constraints",
        "disabled_triggers",
        "stale_table_statistics",
        "missing_table_statistics",
        "locked_table_statistics",
        "recyclebin_objects",
        "invalid_synonyms",
    ]:
        assert results[check_id]["status"] == "PASS"
        assert results[check_id]["evidence"]["affected_count"] == 0


def test_invalid_objects_detail_detects_application_object_and_excludes_oracle_maintained(tmp_path):
    results = _run_with_schema_objects(tmp_path, {
        "invalid_objects_detail": [
            {"owner": "SYS", "object_name": "DBMS_INTERNAL", "object_type": "PACKAGE", "status": "INVALID", "oracle_maintained": "Y"},
            {"owner": "APP", "object_name": "PKG_ORDERS", "object_type": "PACKAGE", "status": "INVALID", "created": "2026-01-01", "last_ddl_time": "2026-06-01", "oracle_maintained": "N"},
        ]
    })

    result = results["invalid_objects_detail"]
    assert result["status"] == "FAIL"
    assert result["evidence"]["affected_count"] == 1
    assert result["evidence"]["excluded_count"] == 1
    assert result["evidence"]["rows"][0]["owner"] == "APP"
    assert result["evidence"]["rows"][0]["object_name"] == "PKG_ORDERS"


def test_unusable_indexes_detects_application_index(tmp_path):
    results = _run_with_schema_objects(tmp_path, {
        "unusable_indexes": [
            {"owner": "APP", "index_name": "IX_ORDERS_01", "table_owner": "APP", "table_name": "ORDERS", "status": "UNUSABLE", "partitioned": "NO", "index_type": "NORMAL", "tablespace_name": "USERS", "oracle_maintained": "N"}
        ]
    })

    assert results["unusable_indexes"]["status"] == "FAIL"
    assert results["unusable_indexes"]["evidence"]["rows"][0]["index_name"] == "IX_ORDERS_01"


def test_unusable_index_partitions_detects_partition_or_subpartition(tmp_path):
    results = _run_with_schema_objects(tmp_path, {
        "unusable_index_partitions": [
            {"owner": "APP", "index_name": "IX_SALES_P", "partition_name": "P2026", "subpartition_name": None, "table_owner": "APP", "table_name": "SALES", "status": "UNUSABLE", "level": "PARTITION", "oracle_maintained": "N"},
            {"owner": "APP", "index_name": "IX_SALES_SP", "partition_name": "P2026", "subpartition_name": "SP01", "table_owner": "APP", "table_name": "SALES", "status": "UNUSABLE", "level": "SUBPARTITION", "oracle_maintained": "N"},
        ]
    })

    assert results["unusable_index_partitions"]["status"] == "FAIL"
    assert {row["level"] for row in results["unusable_index_partitions"]["evidence"]["rows"]} == {"PARTITION", "SUBPARTITION"}


def test_disabled_constraints_evidence_includes_type_and_table(tmp_path):
    results = _run_with_schema_objects(tmp_path, {
        "disabled_constraints": [
            {"owner": "APP", "constraint_name": "PK_ORDERS", "constraint_type": "P", "table_name": "ORDERS", "status": "DISABLED", "validated": "NOT VALIDATED", "deferrable": "NOT DEFERRABLE", "deferred": "IMMEDIATE", "generated": "USER NAME", "oracle_maintained": "N"}
        ]
    })

    result = results["disabled_constraints"]
    assert result["status"] == "FAIL"
    assert result["evidence"]["rows"][0]["constraint_type"] == "P"
    assert result["evidence"]["rows"][0]["table_name"] == "ORDERS"


def test_disabled_triggers_detects_application_trigger(tmp_path):
    results = _run_with_schema_objects(tmp_path, {
        "disabled_triggers": [
            {"owner": "APP", "trigger_name": "TRG_AUD_ORDERS", "table_owner": "APP", "table_name": "ORDERS", "trigger_type": "BEFORE EACH ROW", "triggering_event": "INSERT OR UPDATE", "status": "DISABLED", "oracle_maintained": "N"}
        ]
    })

    assert results["disabled_triggers"]["status"] == "WARNING"
    assert results["disabled_triggers"]["evidence"]["rows"][0]["trigger_name"] == "TRG_AUD_ORDERS"


def test_stale_and_missing_table_statistics_are_reported(tmp_path):
    results = _run_with_schema_objects(tmp_path, {
        "stale_table_statistics": [
            {"owner": "APP", "table_name": "ORDERS", "object_type": "TABLE", "stale_stats": "YES", "last_analyzed": "2026-01-01", "num_rows": 1000, "oracle_maintained": "N"}
        ],
        "missing_table_statistics": [
            {"owner": "APP", "table_name": "NEW_TABLE", "num_rows": None, "blocks": None, "last_analyzed": None, "stale_stats": None, "oracle_maintained": "N"}
        ],
    })

    assert results["stale_table_statistics"]["status"] == "WARNING"
    assert results["stale_table_statistics"]["evidence"]["rows"][0]["stale_stats"] == "YES"
    assert results["missing_table_statistics"]["status"] == "WARNING"
    assert results["missing_table_statistics"]["evidence"]["rows"][0]["last_analyzed"] is None


def test_optional_schema_object_checks_are_reported_when_present(tmp_path):
    results = _run_with_schema_objects(tmp_path, {
        "locked_table_statistics": [
            {"owner": "APP", "table_name": "CONFIG", "stattype_locked": "ALL", "last_analyzed": "2026-01-01", "stale_stats": "NO", "oracle_maintained": "N"}
        ],
        "recyclebin_objects": [
            {"owner": "APP", "object_name": "BIN$ABC", "original_name": "OLD_TABLE", "type": "TABLE", "ts_name": "USERS", "can_undrop": "YES", "can_purge": "YES", "space_mb": 12.5, "oracle_maintained": "N"}
        ],
        "invalid_synonyms": [
            {"owner": "PUBLIC", "synonym_name": "V$XS_SESSION_ROLE", "table_owner": "SYS", "table_name": "V$XS_SESSION_ROLES", "db_link": None, "oracle_maintained": None, "table_owner_oracle_maintained": "Y"},
            {"owner": "APP", "synonym_name": "S_MISSING", "table_owner": "APP", "table_name": "MISSING_TABLE", "db_link": None, "oracle_maintained": "N", "table_owner_oracle_maintained": "N"},
        ],
    })

    assert results["locked_table_statistics"]["status"] == "INFO"
    assert results["recyclebin_objects"]["status"] == "INFO"
    assert results["recyclebin_objects"]["evidence"]["total_mb"] == 12.5
    assert results["invalid_synonyms"]["status"] == "WARNING"
    assert results["invalid_synonyms"]["evidence"]["affected_count"] == 1
    assert results["invalid_synonyms"]["evidence"]["rows"][0]["synonym_name"] == "S_MISSING"



def test_schema_object_real_inventory_queries_use_oracle_19c_safe_sql():
    class CaptureConnector:
        queries: list[str] = []

        def query(self, sql: str):
            normalized = " ".join(sql.lower().split())
            type(self).queries.append(normalized)
            return []

    CaptureConnector.queries = []
    CheckRunner({})._discover_schema_objects_inventory(CaptureConnector())
    joined = "\n".join(CaptureConnector.queries)
    partition_query = next(query for query in CaptureConnector.queries if "from dba_ind_partitions" in query and "from dba_ind_subpartitions" in query)
    stats_queries = [query for query in CaptureConnector.queries if "from dba_tab_statistics" in query]
    synonym_query = next(query for query in CaptureConnector.queries if "from dba_synonyms" in query)

    assert "dba_ind_partitions" in partition_query
    assert "dba_ind_subpartitions" in partition_query
    assert 'as "level"' in partition_query
    assert "'partition'" in partition_query
    assert "'subpartition'" in partition_query
    assert "s.temporary" not in joined
    assert len(stats_queries) == 3
    for query in stats_queries:
        assert "join dba_tables t on t.owner = s.owner and t.table_name = s.table_name" in query
        assert "nvl(t.temporary, 'n') = 'n'" in query
    assert "s.owner <> 'public'" in synonym_query
    assert "left join dba_users tu on tu.username = s.table_owner" in synonym_query
    assert "nvl(tu.oracle_maintained, 'n') = 'n'" in synonym_query



def test_schema_object_fallback_does_not_log_warning_for_optional_oracle_maintained(caplog):
    class FallbackConnector:
        def query(self, sql: str):
            normalized = " ".join(sql.lower().split())
            if "u.oracle_maintained" in normalized:
                raise Exception('ORA-00904: "U"."ORACLE_MAINTAINED": invalid identifier')
            return [{"owner": "APP", "object_name": "PKG_APP", "oracle_maintained": None}]

    with caplog.at_level(logging.WARNING):
        rows = CheckRunner({})._query_schema_rows(
            FallbackConnector(),
            "objetos inválidos no mantenidos por Oracle",
            "select o.owner, o.object_name, u.oracle_maintained from dba_objects o left join dba_users u on u.username = o.owner",
            "select o.owner, o.object_name, null as oracle_maintained from dba_objects o where o.owner not in ({internal_schemas})",
        )

    assert rows == [{"owner": "APP", "object_name": "PKG_APP", "oracle_maintained": None}]
    assert "Oracle inventory query failed" not in caplog.text


def test_schema_objects_queries_do_not_use_licensed_views_or_packs():
    forbidden = ["DBA_" + "HIST", "V$ACTIVE_SESSION_" + "HISTORY", "DBMS_WORKLOAD_" + "REPOSITORY", "DBA_" + "ADVISOR", "DBA_" + "SQLTUNE"]
    text = "\n".join(Path(path).read_text(encoding="utf-8") for path in [
        "src/orahealthcheck/engine/runner.py",
        *Path("config/checks/schema_objects").glob("*.yaml"),
    ])

    for token in forbidden:
        assert token not in text


def test_new_schema_objects_visible_text_is_spanish():
    config = ConfigLoader("config").load_all()
    for check_id in [
        "invalid_objects_detail",
        "unusable_indexes",
        "unusable_index_partitions",
        "disabled_constraints",
        "disabled_triggers",
        "stale_table_statistics",
        "missing_table_statistics",
        "locked_table_statistics",
        "recyclebin_objects",
        "invalid_synonyms",
    ]:
        check = config["checks"][check_id]
        assert any(word in check.title.lower() for word in ["objet", "índice", "restric", "disparador", "tabla", "sinónimo", "papelera"])
        assert check.remediation["summary"]
        assert len(check.remediation["actions"]) >= 5
        assert check.remediation["owner"] == "DBA"

def test_oracle_features_are_rendered_in_all_html_reports(tmp_path):
    output = _run_example(tmp_path)
    for report_name in ["executive_report.html", "technical_report.html", "corrective_actions.html", "evidence_report.html"]:
        html = (output / report_name).read_text(encoding="utf-8")
        assert "Características Oracle detectadas" in html
        assert "ESTADO DE DETECCIÓN" in html
        assert "<th>Detectado</th>" not in html
        assert "<th>DETECTADO</th>" not in html
        assert "Estas características corresponden a capacidades o configuraciones detectadas durante el inventario" in html
        for expected in ["Oracle RAC", "Multitenant / CDB", "Configuración con bases standby", "FRA configurada", "Flashback Database"]:
            assert expected in html
        assert "No representan hallazgos ni afectan el puntaje de salud" in html


def test_oracle_features_are_inventory_context_not_corrective_actions(tmp_path):
    output = _run_example(tmp_path)
    corrective_html = (output / "corrective_actions.html").read_text(encoding="utf-8")
    features_position = corrective_html.index("Características Oracle detectadas")
    actions_position = corrective_html.index("Acciones correctivas")

    assert features_position < actions_position
    assert "Oracle RAC" in corrective_html[:actions_position]
    assert "No se requieren acciones correctivas" in corrective_html


def test_oracle_feature_labels_status_booleans_and_missing_fields_do_not_break_reports(tmp_path):
    config = ConfigLoader("config").load_all()
    ConfigValidator().validate(config)
    config["settings"]["app"]["default_output_dir"] = str(tmp_path)
    mock_inventory = config["targets"]["example_standalone"].database["mock_inventory"]
    mock_inventory["parameters"]["cluster_database"] = {"value": "TRUE", "display_value": "TRUE"}
    mock_inventory["cdb"] = "NO"
    mock_inventory["database_role"] = "PRIMARY"
    mock_inventory["fra_configured"] = True
    mock_inventory["fra_space_limit"] = 1024
    mock_inventory["flashback_on"] = "UNKNOWN"
    config["targets"]["example_standalone"].features["future_unknown"] = {"status": "unknown"}
    config["targets"]["example_standalone"].features["sysdba"] = True
    output = CheckRunner(config).run_target("example_standalone")
    for report_name in ["executive_report.html", "technical_report.html", "corrective_actions.html", "evidence_report.html"]:
        html = (output / report_name).read_text(encoding="utf-8")
        assert "Características Oracle detectadas" in html
        assert "ESTADO DE DETECCIÓN" in html
        assert "<th>Detectado</th>" not in html
        assert "<th>DETECTADO</th>" not in html
        assert "Diagnostic Pack" in html
        assert "AWR" in html
        assert "Conexión SYSDBA" in html
        assert "Detectado" in html
        assert "No detectado" in html
        assert "Desconocido" in html
        assert ">Sí<" in html
        assert ">No<" in html
        assert "Configuración con bases standby" in html


def test_all_reports_generate_when_oracle_features_are_absent(tmp_path):
    reporter = __import__("orahealthcheck.reports.html_reporter", fromlist=["HTMLReporter"]).HTMLReporter(Path("templates/html"))
    target = Target("no_features", "No Features", "test", "standalone", "standalone_basic")
    inventory = Inventory("no_features", "standalone", "test", database={"status": "OPEN"}, operating_system={"platform": "linux"}, features={})

    reporter.generate(tmp_path, target, inventory, [], {"score": 100, "global_status": "PASS"})

    for report_name in ["executive_report.html", "technical_report.html", "corrective_actions.html", "evidence_report.html"]:
        html = (tmp_path / report_name).read_text(encoding="utf-8")
        assert "OraHealthCheck" in html
        assert "Características Oracle detectadas" not in html


def test_oracle_feature_renderer_handles_absent_and_incomplete_features():
    reporter = __import__("orahealthcheck.reports.html_reporter", fromlist=["HTMLReporter"]).HTMLReporter(Path("templates/html"))
    assert reporter._oracle_feature_items({}) == []

    items = reporter._oracle_feature_items({"features": {"future_feature": {"status": "unknown"}, "flag_only": True}})
    by_id = {item["feature_id"]: item for item in items}
    assert by_id["future_feature"]["name"] == "Future Feature"
    assert by_id["future_feature"]["status"] == "Desconocido"
    assert by_id["future_feature"]["detected"] == "No disponible"
    assert by_id["future_feature"]["source"] == "-"
    assert by_id["future_feature"]["value"] == "unknown"
    assert by_id["future_feature"]["reason"] == "-"
    assert by_id["flag_only"]["status"] == "Detectado"
    assert by_id["flag_only"]["value"] == "Sí"
    assert by_id["flag_only"]["detected"] == "Sí"

    false_item = reporter._oracle_feature_items({"features": {"diagnostic_pack": False}})[0]
    assert false_item["name"] == "Diagnostic Pack"
    assert false_item["status"] == "No detectado"
    assert false_item["value"] == "No"
