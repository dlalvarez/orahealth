from orahealthcheck.engine.runner import CheckRunner
from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.models import Check, Inventory, ResultStatus


def _runner():
    return CheckRunner({"targets": {}, "profiles": {}, "settings": {}})


def test_alert_log_internal_errors_generan_evidencia_truncada():
    check = Check(
        check_id="alert_log_internal_errors",
        group_id="alert_log",
        title="Errores internos Oracle en alert log",
        collector={"type": "alert_log_family", "field": "alert_log_excerpt", "patterns": ["ORA-00600", "ORA-07445"], "max_samples": 1},
    )
    inventory = Inventory("t", "standalone", "test", {"alert_log_excerpt": "2026 ORA-00600 error\n2026 ORA-07445 error"}, {})

    evidence = _runner()._collect(check, inventory)

    assert evidence["occurrences"] == 2
    assert evidence["truncated"] is True
    assert evidence["sample_lines"] == [{"linea": 1, "patron": "ORA-00600", "texto": "2026 ORA-00600 error"}]


def test_alert_log_family_falla_si_hay_coincidencias():
    status, message = EVALUATORS["alert_log_family"].evaluate(
        {"available": True, "occurrences": 1, "message": "Se detectó ORA-04031"},
        {"mode": "fail_on_match", "failure_status": "FAIL"},
    )

    assert status == ResultStatus.FAIL
    assert "ORA-04031" in message


def test_alert_log_summary_es_informativo_y_no_penaliza():
    status, message = EVALUATORS["alert_log_family"].evaluate(
        {"available": True, "occurrences": 3, "message": "Resumen informativo"},
        {"mode": "info"},
    )

    assert status == ResultStatus.INFO
    assert message == "Resumen informativo"


def test_alert_log_sin_muestra_retorna_error_controlado():
    check = Check(
        check_id="alert_log_memory_errors",
        group_id="alert_log",
        title="Errores de memoria en alert log",
        collector={"type": "alert_log_family", "field": "alert_log_excerpt", "patterns": ["ORA-04031"]},
    )
    inventory = Inventory("t", "standalone", "test", {}, {})

    evidence = _runner()._collect(check, inventory)
    status, message = EVALUATORS["alert_log_family"].evaluate(evidence, {"failure_status": "FAIL"})

    assert status == ResultStatus.ERROR
    assert "No se encontró muestra" in message


def test_alert_log_resumen_no_evalua_salud_data_guard():
    check = Check(
        check_id="alert_log_recent_summary",
        group_id="alert_log",
        title="Resumen reciente del alert log",
        collector={"type": "alert_log_family", "field": "alert_log_excerpt", "patterns": ["standby", "\\bMRP[0-9A-Z]*\\b"], "summary": True},
    )
    inventory = Inventory("t", "standalone", "test", {"alert_log_excerpt": "MRP0 stopped for standby apply"}, {})

    evidence = _runner()._collect(check, inventory)

    assert evidence["counts_by_family"]["texto_standby"] == 1
    assert "no evalúa la salud de Data Guard" in evidence["standby_note"]
