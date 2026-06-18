from orahealthcheck.engine.runner import CheckRunner
from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.models import Check, Inventory, ResultStatus, Target
from orahealthcheck.engine.scoring import summarize
from orahealthcheck.models import Result


def _runner():
    return CheckRunner({"targets": {}, "profiles": {}, "settings": {}, "connections": {"os_connections": {}}})


def _check(check_id, patterns, severity="FAIL", summary=False):
    return Check(
        check_id=check_id,
        group_id="alert_log",
        title="Check de alert log",
        severity=severity,
        collector={"type": "alert_log_family", "field": "alert_log", "patterns": patterns, "max_samples": 1, "summary": summary},
        evaluator={"type": "alert_log_family", "mode": "info" if summary else "fail_on_match", "failure_status": severity},
    )


class FakeConnector:
    def __init__(self, responses):
        self.responses = responses

    def query(self, sql):
        for marker, response in self.responses:
            if marker in sql:
                if isinstance(response, Exception):
                    raise response
                return response
        return []


def test_alert_log_diag_alert_ext_accesible_sin_patrones_pasa_y_resumen_info():
    runner = _runner()
    alert_log = {"available": True, "source": "v$diag_alert_ext", "events": [{"message_text": "Inicio normal", "source": "v$diag_alert_ext"}]}
    inventory = Inventory("t", "standalone", "test", {"alert_log": alert_log}, {})

    status_error, message_error = EVALUATORS["alert_log_family"].evaluate(runner._collect(_check("alert_log_internal_errors", ["ORA-00600"], "CRITICAL"), inventory), {"failure_status": "CRITICAL"})
    status_summary, _ = EVALUATORS["alert_log_family"].evaluate(runner._collect(_check("alert_log_recent_summary", ["ORA-00600"], "INFO", summary=True), inventory), {"mode": "info"})

    assert status_error == ResultStatus.PASS
    assert "No se encontraron patrones" in message_error
    assert status_summary == ResultStatus.INFO


def test_alert_log_internal_errors_diag_alert_ext_generan_critical():
    runner = _runner()
    alert_log = {"available": True, "source": "v$diag_alert_ext", "events": [{"timestamp": "2026-06-18T10:00:00", "message_text": "ORA-00600 internal error", "source": "v$diag_alert_ext"}]}
    evidence = runner._collect(_check("alert_log_internal_errors", ["ORA-00600", "ORA-07445"], "CRITICAL"), Inventory("t", "standalone", "test", {"alert_log": alert_log}, {}))
    status, _ = EVALUATORS["alert_log_family"].evaluate(evidence, {"failure_status": "CRITICAL"})

    assert status == ResultStatus.CRITICAL
    assert evidence["sample_lines"][0]["timestamp"] == "2026-06-18T10:00:00"


def test_alert_log_memory_errors_diag_alert_ext_generan_fail():
    runner = _runner()
    alert_log = {"available": True, "source": "v$diag_alert_ext", "events": [{"message_text": "ORA-04031 unable to allocate", "source": "v$diag_alert_ext"}]}
    evidence = runner._collect(_check("alert_log_memory_errors", ["ORA-04031", "ORA-04030"], "FAIL"), Inventory("t", "standalone", "test", {"alert_log": alert_log}, {}))

    status, _ = EVALUATORS["alert_log_family"].evaluate(evidence, {"failure_status": "FAIL"})

    assert status == ResultStatus.FAIL


def test_alert_log_space_errors_diag_alert_ext_generan_fail():
    runner = _runner()
    alert_log = {"available": True, "source": "v$diag_alert_ext", "events": [{"message_text": "ORA-00257 archiver error", "source": "v$diag_alert_ext"}]}
    evidence = runner._collect(_check("alert_log_space_errors", ["ORA-00257", "ORA-01652", "ORA-01653", "ORA-01654"], "FAIL"), Inventory("t", "standalone", "test", {"alert_log": alert_log}, {}))

    status, _ = EVALUATORS["alert_log_family"].evaluate(evidence, {"failure_status": "FAIL"})

    assert status == ResultStatus.FAIL


def test_alert_log_sin_privilegios_y_sin_os_queda_skipped_para_todos_los_checks():
    runner = _runner()
    alert_log = {"available": False, "status": "skipped", "source": "sin_acceso", "events": [], "message": "No fue posible acceder al alert log. La instancia Oracle genera alert log, pero este target no tiene privilegios SQL suficientes sobre V$DIAG_ALERT_EXT ni conexión OS/SSH/local configurada para leer el archivo alert_<INSTANCE_NAME>.log."}
    inventory = Inventory("t", "standalone", "test", {"alert_log": alert_log}, {})

    for check_id in ["alert_log_ora_errors_basic", "alert_log_internal_errors", "alert_log_memory_errors", "alert_log_space_errors", "alert_log_snapshot_undo_errors", "alert_log_corruption_errors", "alert_log_redo_archive_errors", "alert_log_recent_summary"]:
        evidence = runner._collect(_check(check_id, ["ORA-00600"], "CRITICAL", summary=check_id == "alert_log_recent_summary"), inventory)
        status, message = EVALUATORS["alert_log_family"].evaluate(evidence, {"failure_status": "CRITICAL", "mode": "info" if check_id == "alert_log_recent_summary" else "fail_on_match"})
        assert status == ResultStatus.SKIPPED
        assert "La instancia Oracle genera alert log" in message


def test_alert_log_ora_errors_basic_sin_muestra_accesible_queda_skipped():
    runner = _runner()
    evidence = runner._collect(_check("alert_log_ora_errors_basic", ["ORA-(00600|07445)"], "CRITICAL"), Inventory("t", "standalone", "test", {}, {}))
    status, message = EVALUATORS["alert_log_family"].evaluate(evidence, {"failure_status": "CRITICAL"})

    assert status == ResultStatus.SKIPPED
    assert "No fue posible acceder al alert log" in message


def test_alert_log_lectura_os_fallida_queda_error_con_detalle():
    runner = _runner()
    evidence = runner._collect(_check("alert_log_internal_errors", ["ORA-00600"], "CRITICAL"), Inventory("t", "standalone", "test", {"alert_log": {"available": False, "status": "error", "source": "alert_log_file", "path": "/tmp/alert_orcl.log", "read_error": "Permiso denegado", "message": "Se intentó leer el alert log en /tmp/alert_orcl.log, pero ocurrió un error técnico: Permiso denegado."}}, {}))
    status, message = EVALUATORS["alert_log_family"].evaluate(evidence, {"failure_status": "CRITICAL"})

    assert status == ResultStatus.ERROR
    assert "Permiso denegado" in message


def test_alert_log_recent_summary_sin_acceso_queda_skipped():
    runner = _runner()
    evidence = runner._collect(_check("alert_log_recent_summary", ["ORA-00600"], "INFO", summary=True), Inventory("t", "standalone", "test", {}, {}))
    status, _ = EVALUATORS["alert_log_family"].evaluate(evidence, {"mode": "info"})

    assert status == ResultStatus.SKIPPED


def test_alert_log_skipped_no_penaliza_score():
    summary = summarize([Result("alert_log_ora_errors_basic", "alert_log", ResultStatus.SKIPPED, "Alert log")])

    assert summary["score"] == 100


def test_alert_log_ora_errors_basic_sigue_registrado_en_grupo():
    checks = _runner().config.get("checks", {})
    assert checks == {}
    from orahealthcheck.config_loader.loader import ConfigLoader
    groups = ConfigLoader("config").load_check_groups()

    assert "alert_log_ora_errors_basic" in groups["alert_log"].checks


def test_discover_alert_log_usa_v_diag_alert_ext_como_fuente_preferida():
    runner = _runner()
    connector = FakeConnector([("v$diag_alert_ext", [{"message_text": "ORA-07445 exception", "originating_timestamp": "2026-06-18T12:00:00"}])])
    target = Target("t", "T", "test", "standalone", "standalone_basic", {}, {})

    alert_log = runner._discover_alert_log_inventory(connector, target, {"instance_name": "orcl"})

    assert alert_log["available"] is True
    assert alert_log["source"] == "v$diag_alert_ext"
    assert alert_log["events"][0]["message_text"] == "ORA-07445 exception"


def test_discover_alert_log_sin_privilegios_y_sin_os_retorna_skipped():
    runner = _runner()
    connector = FakeConnector([("v$diag_alert_ext", RuntimeError("ORA-01031: privilegios insuficientes")), ("v$diag_info", [])])
    target = Target("t", "T", "test", "standalone", "standalone_basic", {}, {})

    alert_log = runner._discover_alert_log_inventory(connector, target, {"instance_name": "orcl"})

    assert alert_log["available"] is False
    assert alert_log["status"] == "skipped"
    assert "ORA-01031" in alert_log["diag_alert_error"]


def _config_check(check_id):
    from orahealthcheck.config_loader.loader import ConfigLoader
    return ConfigLoader("config").load_checks()[check_id]


def _evaluate_configured_check(check, text):
    runner = _runner()
    alert_log = {"available": True, "source": "v$diag_alert_ext", "events": [{"message_text": line, "source": "v$diag_alert_ext"} for line in text.splitlines()]}
    evidence = runner._collect(check, Inventory("t", "standalone", "test", {"alert_log": alert_log}, {}))
    status, message = EVALUATORS[check.evaluator["type"]].evaluate(evidence, check.evaluator)
    return status, message, evidence


def test_redo_archive_switch_normal_no_es_hallazgo():
    check = _config_check("alert_log_redo_archive_errors")
    status, message, evidence = _evaluate_configured_check(check, "Thread 1 advanced to log sequence 202 (LGWR switch)")

    assert status == ResultStatus.PASS
    assert message == "No se encontraron errores de redo/archive en el alert log dentro de la muestra evaluada."
    assert evidence["occurrences"] == 0


def test_redo_archive_cannot_allocate_aislado_es_warning():
    check = _config_check("alert_log_redo_archive_errors")
    status, _, evidence = _evaluate_configured_check(check, "Thread 1 cannot allocate new log, sequence 202")

    assert status == ResultStatus.WARNING
    assert evidence["counts_by_pattern"]["cannot allocate new log"] == 1
    assert evidence["occurrences"] == 1


def test_redo_archive_cannot_allocate_con_checkpoint_es_fail():
    check = _config_check("alert_log_redo_archive_errors")
    text = "Thread 1 cannot allocate new log, sequence 202\nCheckpoint not complete"
    status, _, evidence = _evaluate_configured_check(check, text)

    assert status == ResultStatus.FAIL
    assert evidence["counts_by_pattern"]["cannot allocate new log"] == 1
    assert evidence["counts_by_pattern"]["checkpoint not complete"] == 1


def test_redo_archive_ora_00257_es_critical():
    check = _config_check("alert_log_redo_archive_errors")
    status, _, evidence = _evaluate_configured_check(check, "ORA-00257: archiver error. Connect internal only, until freed.")

    assert status == ResultStatus.CRITICAL
    assert evidence["counts_by_pattern"]["ORA-00257"] == 1


def test_alert_log_recent_summary_cuenta_switch_normal_como_informativo():
    check = _config_check("alert_log_recent_summary")
    status, _, evidence = _evaluate_configured_check(check, "Thread 1 advanced to log sequence 202 (LGWR switch)")

    assert status == ResultStatus.INFO
    assert evidence["occurrences"] >= 1
