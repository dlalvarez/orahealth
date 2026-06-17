from orahealthcheck.engine.runner import CheckRunner
from orahealthcheck.evaluators import EVALUATORS
from orahealthcheck.models import ResultStatus


def evaluate(metric, evidence, **config):
    data = {"metric": metric, **evidence}
    cfg = {"type": "io_redo_archive", **config}
    return EVALUATORS["io_redo_archive"].evaluate(data, cfg)[0]


def test_archivelog_generation_recent_handles_noarchivelog_and_thresholds():
    assert evaluate("archivelog_generation_recent", {"archivelog_mode": "NOARCHIVELOG"}) == ResultStatus.SKIPPED
    assert evaluate("archivelog_generation_recent", {"archivelog_mode": "ARCHIVELOG", "total_mb": 10}) == ResultStatus.INFO
    assert evaluate("archivelog_generation_recent", {"archivelog_mode": "ARCHIVELOG", "total_mb": 150}, warning_archivelog_mb_24h=100, fail_archivelog_mb_24h=200) == ResultStatus.WARNING


def test_archive_dest_status_and_errors_ignore_unconfigured_destinations():
    rows = [
        {"archive_dest_status": "INACTIVE", "archive_destination": None, "archive_dest_error": None},
        {"archive_dest_status": "VALID", "archive_destination": "USE_DB_RECOVERY_FILE_DEST", "valid_now": "YES"},
    ]
    assert evaluate("archive_dest_status", {"archivelog_mode": "ARCHIVELOG", "rows": rows}) == ResultStatus.PASS
    assert evaluate("archive_dest_errors", {"rows": rows}) == ResultStatus.PASS
    rows[1]["archive_dest_error"] = "ORA-16038"
    assert evaluate("archive_dest_errors", {"rows": rows}) == ResultStatus.FAIL


def test_archive_dest_status_allows_null_valid_now_and_noarchivelog_without_false_fail():
    rows = [{"archive_dest_status": "VALID", "archive_destination": "USE_DB_RECOVERY_FILE_DEST", "valid_now": None}]
    assert evaluate("archive_dest_status", {"archivelog_mode": "ARCHIVELOG", "rows": rows}) == ResultStatus.PASS
    assert evaluate("archive_dest_status", {"archivelog_mode": "NOARCHIVELOG", "rows": rows}) == ResultStatus.INFO


def test_archive_dest_errors_detects_status_error_and_ignores_empty_inactive():
    rows = [
        {"archive_dest_status": "INACTIVE", "archive_destination": None, "archive_dest_error": None, "archive_dest_status_error": None},
        {"archive_dest_status": "VALID", "archive_destination": "SERVICE=DG", "archive_dest_status_error": "ORA-12514"},
    ]
    assert evaluate("archive_dest_errors", {"rows": rows}) == ResultStatus.FAIL
    assert evaluate("archive_dest_status", {"archivelog_mode": "ARCHIVELOG", "rows": [rows[0]]}) == ResultStatus.PASS


def test_archive_dest_query_uses_valid_now_from_archive_dest():
    class CaptureConnector:
        queries = []

        def query(self, sql):
            self.queries.append(sql)
            return []

    CaptureConnector.queries = []
    CheckRunner({})._discover_io_redo_archive_inventory(CaptureConnector(), {}, {"archivelog_mode": "ARCHIVELOG"})
    archive_query = next(query for query in CaptureConnector.queries if "from v$archive_dest d" in query)
    assert "d.valid_now" in archive_query
    assert "s.valid_now" not in archive_query
    assert "d.error as archive_dest_error" in archive_query
    assert "s.error as archive_dest_status_error" in archive_query


def test_fra_usage_advanced_thresholds_and_reclaimable_warning():
    assert evaluate("fra_usage_advanced", {"fra_configured": False}) == ResultStatus.SKIPPED
    assert evaluate("fra_usage_advanced", {"fra_configured": True, "used_pct": 50}, warning=70, fail=85, critical=95) == ResultStatus.PASS
    assert evaluate("fra_usage_advanced", {"fra_configured": True, "used_pct": 90}, warning=70, fail=85, critical=95) == ResultStatus.FAIL
    assert evaluate("fra_usage_advanced", {"fra_configured": True, "used_pct": 96}, warning=70, fail=85, critical=95) == ResultStatus.CRITICAL
    assert evaluate("fra_reclaimable_space", {"fra_configured": True, "reclaimable_pct": 60}, warning_reclaimable_pct=50) == ResultStatus.WARNING


def test_flashback_status_and_log_usage():
    assert evaluate("flashback_status", {"flashback_on": "NO"}, required=False) == ResultStatus.INFO
    assert evaluate("flashback_status", {"flashback_on": "YES"}, required=True) == ResultStatus.PASS
    assert evaluate("flashback_status", {"flashback_on": "NO"}, required=True) == ResultStatus.WARNING
    assert evaluate("flashback_log_usage", {"flashback_on": "NO"}) == ResultStatus.SKIPPED
    assert evaluate("flashback_log_usage", {"flashback_on": "YES"}) == ResultStatus.INFO


def test_redo_checks_thresholds_and_statuses():
    assert evaluate("redo_log_switch_frequency", {"switches_per_hour": 2}, warning_switches_per_hour=6, fail_switches_per_hour=20) == ResultStatus.INFO
    assert evaluate("redo_log_switch_frequency", {"switches_per_hour": 7}, warning_switches_per_hour=6, fail_switches_per_hour=20) == ResultStatus.WARNING
    assert evaluate("redo_log_switch_frequency", {"switches_per_hour": 21}, warning_switches_per_hour=6, fail_switches_per_hour=20) == ResultStatus.FAIL
    assert evaluate("redo_log_size_assessment", {"min_redo_mb": 128}, warning_min_redo_mb=256) == ResultStatus.WARNING
    assert evaluate("redo_log_status", {"affected_count": 0}) == ResultStatus.PASS
    assert evaluate("redo_log_status", {"affected_count": 1}) == ResultStatus.WARNING
    assert evaluate("redo_logfile_status", {"affected_count": 0}) == ResultStatus.PASS
    assert evaluate("redo_logfile_status", {"affected_count": 1}) == ResultStatus.WARNING


def test_io_and_recoverability_checks():
    assert evaluate("sysstat_io_basic", {"values": {"redo size": 1}}) == ResultStatus.INFO
    assert evaluate("filestat_io_basic", {"rows": [{"file_number": 1}]}) == ResultStatus.INFO
    assert evaluate("nologging_objects_basic", {"affected_count": 0, "force_logging": "NO"}) == ResultStatus.PASS
    assert evaluate("nologging_objects_basic", {"affected_count": 2, "force_logging": "NO"}) == ResultStatus.WARNING
    assert evaluate("nologging_objects_basic", {"affected_count": 2, "force_logging": "YES"}) == ResultStatus.INFO
    assert evaluate("unrecoverable_datafiles", {"rows": []}) == ResultStatus.PASS
    assert evaluate("unrecoverable_datafiles", {"rows": [{"recent": False}]}) == ResultStatus.WARNING
    assert evaluate("unrecoverable_datafiles", {"rows": [{"recent": True}]}) == ResultStatus.FAIL
