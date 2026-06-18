from typing import Any

from orahealthcheck.models import ResultStatus


class AlertLogEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia del alert log no tiene el formato esperado"
        if evidence.get("available") is False:
            if evidence.get("status") == "error":
                return ResultStatus.ERROR, evidence.get("message", "Error técnico al acceder al alert log")
            return ResultStatus.SKIPPED, evidence.get("message", "No fue posible acceder al alert log con las fuentes configuradas")

        count = int(evidence.get("occurrences", 0) or 0)
        mode = config.get("mode", "fail_on_match")
        if mode == "info":
            return ResultStatus.INFO, evidence.get("message", "Resumen informativo del alert log generado")
        if mode == "fail_on_match" and count > 0:
            status = self._status_from_severity_rules(evidence, config)
            return status, evidence.get("message", f"Se detectaron {count} ocurrencias relevantes en el alert log")
        return ResultStatus.PASS, evidence.get("message", "No se detectaron eventos de esta familia en la muestra del alert log")


    def _status_from_severity_rules(self, evidence: dict[str, Any], config: dict[str, Any]) -> ResultStatus:
        rules = config.get("severity_rules") or {}
        counts = evidence.get("counts_by_pattern") or {}
        if not isinstance(counts, dict) or not isinstance(rules, dict):
            return ResultStatus(config.get("failure_status", "FAIL"))

        def total_for(patterns: list[str]) -> int:
            return sum(int(counts.get(pattern, 0) or 0) for pattern in patterns)

        critical_patterns = [str(pattern) for pattern in rules.get("critical_patterns", [])]
        fail_patterns = [str(pattern) for pattern in rules.get("fail_patterns", [])]
        warning_patterns = [str(pattern) for pattern in rules.get("warning_patterns", [])]
        if total_for(critical_patterns) > 0:
            return ResultStatus.CRITICAL
        if total_for(fail_patterns) > 0:
            return ResultStatus.FAIL
        cannot_allocate_pattern = rules.get("cannot_allocate_pattern")
        if cannot_allocate_pattern:
            cannot_allocate_count = int(counts.get(str(cannot_allocate_pattern), 0) or 0)
            fail_threshold = int(rules.get("cannot_allocate_fail_threshold", 2) or 2)
            if cannot_allocate_count >= fail_threshold:
                return ResultStatus.FAIL
            if cannot_allocate_count > 0:
                return ResultStatus.WARNING
        if total_for(warning_patterns) > 0:
            return ResultStatus.WARNING
        return ResultStatus(config.get("failure_status", "FAIL"))
