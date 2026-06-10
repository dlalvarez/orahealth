from typing import Any

from orahealthcheck.models import ResultStatus


class StorageEvaluator:
    """Evaluate Oracle storage evidence assembled from reusable inventory data."""

    def evaluate(self, evidence: dict[str, Any], config: dict[str, Any]) -> tuple[ResultStatus, str]:
        metric = evidence.get("metric")
        if metric == "tablespace_free_pct":
            return self._low_threshold(evidence.get("worst_free_pct"), config, "Tablespace free percentage")
        if metric == "tablespace_used_pct":
            return self._high_threshold(evidence.get("max_used_pct"), config, "Tablespace used percentage")
        if metric == "datafiles_autoextend_disabled":
            if evidence.get("datafiles") is None:
                return ResultStatus.ERROR, "Datafile information was not found in evidence"
            count = int(evidence.get("affected_count") or 0)
            if count:
                return self._configured_status(config.get("status_when_found", "WARNING")), f"{count} datafile(s) have AUTOEXTENSIBLE disabled"
            return ResultStatus.PASS, "All datafiles are autoextensible or no fixed datafiles were detected"
        if metric == "datafiles_near_maxsize":
            return self._high_threshold(evidence.get("max_used_of_max_pct"), config, "Datafile maxsize usage")
        if metric == "datafiles_status":
            if evidence.get("datafile_count") == 0:
                return ResultStatus.ERROR, "Datafile information was not found in evidence"
            count = int(evidence.get("affected_count") or 0)
            if count:
                return ResultStatus.FAIL, f"{count} datafile(s) have anomalous status"
            return ResultStatus.PASS, "All datafiles are AVAILABLE/ONLINE"
        if metric == "tempfiles_status":
            if int(evidence.get("tempfile_count") or 0) == 0:
                return self._configured_status(config.get("missing_status", "WARNING")), "No tempfiles were found"
            count = int(evidence.get("affected_count") or 0)
            if count:
                return self._configured_status(config.get("anomaly_status", "FAIL")), f"{count} tempfile(s) have anomalous status"
            return ResultStatus.PASS, "Tempfiles exist and have acceptable status"
        if metric == "temp_usage_pct":
            if not evidence.get("tablespaces"):
                return ResultStatus.ERROR, "Temporary tablespace usage information was not found in evidence"
            return self._high_threshold(evidence.get("max_used_pct"), config, "Temporary tablespace usage")
        if metric == "undo_tablespace_status":
            if not evidence.get("undo_tablespace") or evidence.get("status") is None:
                return ResultStatus.WARNING, "UNDO tablespace information could not be fully determined"
            if str(evidence.get("status")).upper() != "ONLINE":
                return ResultStatus.WARNING, f"UNDO tablespace status is {evidence.get('status')}"
            return ResultStatus.PASS, "UNDO tablespace and retention information were collected"
        if metric == "fra_configured":
            configured = bool(evidence.get("fra_configured"))
            if configured:
                return ResultStatus.PASS, "FRA is configured"
            status = self._configured_status(config.get("missing_status", "SKIPPED"))
            return status, evidence.get("message") or "FRA is not configured"
        if metric in ("fra_usage", "fra_usage_pct"):
            if not evidence.get("fra_configured"):
                return ResultStatus.SKIPPED, evidence.get("message") or "FRA is not configured"
            return self._high_threshold(evidence.get("used_pct", evidence.get("fra_used_pct")), config, "FRA usage")
        return ResultStatus.ERROR, f"Unsupported storage metric {metric}"

    def _high_threshold(self, raw_value: Any, config: dict[str, Any], label: str) -> tuple[ResultStatus, str]:
        value = self._numeric(raw_value, label)
        if value is None:
            return ResultStatus.ERROR, f"{label} was not found in evidence"
        if config.get("critical") is not None and value >= float(config["critical"]):
            return ResultStatus.CRITICAL, f"{label} {value} reached critical threshold {config['critical']}"
        if config.get("fail") is not None and value >= float(config["fail"]):
            return ResultStatus.FAIL, f"{label} {value} reached fail threshold {config['fail']}"
        if config.get("warning") is not None and value >= float(config["warning"]):
            return ResultStatus.WARNING, f"{label} {value} reached warning threshold {config['warning']}"
        return ResultStatus.PASS, f"{label} {value} is within threshold"

    def _low_threshold(self, raw_value: Any, config: dict[str, Any], label: str) -> tuple[ResultStatus, str]:
        value = self._numeric(raw_value, label)
        if value is None:
            return ResultStatus.ERROR, f"{label} was not found in evidence"
        if config.get("critical") is not None and value <= float(config["critical"]):
            return ResultStatus.CRITICAL, f"{label} {value} reached critical threshold {config['critical']}"
        if config.get("fail") is not None and value <= float(config["fail"]):
            return ResultStatus.FAIL, f"{label} {value} reached fail threshold {config['fail']}"
        if config.get("warning") is not None and value <= float(config["warning"]):
            return ResultStatus.WARNING, f"{label} {value} reached warning threshold {config['warning']}"
        return ResultStatus.PASS, f"{label} {value} is within threshold"

    def _numeric(self, raw_value: Any, label: str) -> float | None:
        try:
            return float(raw_value)
        except (TypeError, ValueError):
            return None

    def _configured_status(self, value: Any) -> ResultStatus:
        try:
            return ResultStatus(str(value).upper())
        except ValueError:
            return ResultStatus.WARNING
