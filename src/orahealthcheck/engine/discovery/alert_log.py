"""Descubrimiento y evidencia del grupo alert_log.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

import logging
import re
import shlex
from typing import Any

from orahealthcheck.models import Check, Target
from orahealthcheck.engine.discovery.common import CommonMixin


class AlertLogMixin(CommonMixin):
    def _default_alert_log_inventory(self, database: dict[str, Any]) -> dict[str, Any]:
        excerpt = database.get("alert_log_excerpt")
        if excerpt is not None:
            return {
                "available": True,
                "source": "mock_inventory",
                "events": self._alert_log_events_from_text(str(excerpt), "mock_inventory"),
                "message": "Muestra de alert log proporcionada por el inventario mock.",
            }
        return {
            "available": False,
            "status": "skipped",
            "source": "no_configurado",
            "events": [],
            "message": "No fue posible acceder al alert log. La instancia Oracle genera alert log, pero este target no tiene privilegios SQL suficientes sobre V$DIAG_ALERT_EXT ni conexión OS/SSH/local configurada para leer el archivo alert_<INSTANCE_NAME>.log.",
        }

    def _discover_alert_log_inventory(self, connector: Any, target: Target, inventory: dict[str, Any]) -> dict[str, Any]:
        lookback_hours = int(self.config.get("settings", {}).get("alert_log", {}).get("lookback_hours", 72) or 72)
        rows, diag_alert_error = self._query_rows_with_error(connector, "alert log desde V$DIAG_ALERT_EXT", f"""
            select
              originating_timestamp,
              message_level,
              message_type,
              message_group,
              problem_key,
              message_text,
              filename,
              log_name,
              con_id,
              container_name
            from v$diag_alert_ext
            where originating_timestamp >= systimestamp - numtodsinterval({lookback_hours}, 'HOUR')
            order by originating_timestamp desc
        """, log_warning=False)
        if diag_alert_error is None:
            return {
                "available": True,
                "source": "v$diag_alert_ext",
                "lookback_hours": lookback_hours,
                "events": [self._normalize_alert_log_sql_event(row) for row in rows],
                "message": "Alert log consultado desde V$DIAG_ALERT_EXT.",
            }

        diag_info = self._query_rows(connector, "ubicación de alert log desde V$DIAG_INFO", """
            select name, value
            from v$diag_info
            where name in ('Diag Trace', 'Diag Alert', 'ADR Home', 'ADR Base')
        """)
        diag_info_by_name = {str(row.get("name")): row.get("value") for row in diag_info}
        instance_name = str(inventory.get("instance_name") or "").strip()
        candidate_path = None
        source = "alert_log_file"
        if diag_info_by_name.get("Diag Trace") and instance_name:
            candidate_path = f"{str(diag_info_by_name['Diag Trace']).rstrip('/')}/alert_{instance_name}.log"
        else:
            diagnostic_dest = self._parameter_value(inventory.get("parameters", {}), "diagnostic_dest")
            db_identity = inventory.get("db_unique_name") or inventory.get("db_name")
            if diagnostic_dest and db_identity and instance_name:
                candidate_path = f"{str(diagnostic_dest).rstrip('/')}/diag/rdbms/{str(db_identity).lower()}/{instance_name}/trace/alert_{instance_name}.log"
                source = "diagnostic_dest_fallback"

        os_connector = self._build_alert_log_os_connector(target)
        if candidate_path and os_connector is not None:
            command = f"tail -n 5000 {shlex.quote(candidate_path)}"
            try:
                output = os_connector.run_command(command, timeout=60)
            except Exception as exc:
                return self._alert_log_read_error(candidate_path, source, str(exc), diag_alert_error)
            if output.get("exit_code") != 0:
                detail = output.get("stderr") or output.get("stdout") or f"exit_code={output.get('exit_code')}"
                return self._alert_log_read_error(candidate_path, source, str(detail).strip(), diag_alert_error)
            return {
                "available": True,
                "source": source,
                "path": candidate_path,
                "events": self._alert_log_events_from_text(output.get("stdout", ""), source, filename=candidate_path),
                "diag_alert_error": diag_alert_error,
                "message": f"Alert log leído desde {candidate_path}.",
            }

        return {
            "available": False,
            "status": "skipped",
            "source": "sin_acceso",
            "events": [],
            "candidate_path": candidate_path,
            "diag_alert_error": diag_alert_error,
            "message": "No fue posible acceder al alert log. La instancia Oracle genera alert log, pero este target no tiene privilegios SQL suficientes sobre V$DIAG_ALERT_EXT ni conexión OS/SSH/local configurada para leer el archivo alert_<INSTANCE_NAME>.log.",
        }

    def _build_alert_log_os_connector(self, target: Target) -> Any | None:
        try:
            return self._os_connector(target)
        except Exception as exc:
            logging.warning("No fue posible construir la conexión OS para el alert log: %s", exc)
            return None

    def _alert_log_read_error(self, path: str, source: str, detail: str, diag_alert_error: str | None) -> dict[str, Any]:
        return {
            "available": False,
            "status": "error",
            "source": source,
            "path": path,
            "events": [],
            "diag_alert_error": diag_alert_error,
            "read_error": detail,
            "message": f"Se intentó leer el alert log en {path}, pero ocurrió un error técnico: {detail}.",
        }

    def _normalize_alert_log_sql_event(self, row: dict[str, Any]) -> dict[str, Any]:
        return {
            "timestamp": row.get("originating_timestamp"),
            "message_text": row.get("message_text"),
            "message_level": row.get("message_level"),
            "message_type": row.get("message_type"),
            "message_group": row.get("message_group"),
            "problem_key": row.get("problem_key"),
            "filename": row.get("filename"),
            "log_name": row.get("log_name"),
            "con_id": row.get("con_id"),
            "container_name": row.get("container_name"),
            "source": "v$diag_alert_ext",
        }

    def _alert_log_events_from_text(self, text: str, source: str, filename: str | None = None) -> list[dict[str, Any]]:
        return [
            {"timestamp": None, "message_text": line, "filename": filename, "source": source}
            for line in text.splitlines()
        ]

    def _build_alert_log_evidence(self, check: Check, database: dict[str, Any]) -> dict[str, Any]:
        collector = check.collector
        alert_log = database.get("alert_log") if isinstance(database.get("alert_log"), dict) else self._default_alert_log_inventory(database)
        if alert_log.get("available") is False:
            return {
                "available": False,
                "status": alert_log.get("status", "skipped"),
                "source": alert_log.get("source", "sin_acceso"),
                "path": alert_log.get("path"),
                "candidate_path": alert_log.get("candidate_path"),
                "diag_alert_error": alert_log.get("diag_alert_error"),
                "read_error": alert_log.get("read_error"),
                "message": alert_log.get("message"),
            }

        events = alert_log.get("events") or []
        patterns = collector.get("patterns", [])
        max_samples = int(collector.get("max_samples", 5) or 5)
        matches: list[dict[str, Any]] = []
        counts_by_pattern: dict[str, int] = {str(pattern): 0 for pattern in patterns}
        counts_by_family = {
            "internos": 0,
            "memoria": 0,
            "espacio": 0,
            "undo_snapshot": 0,
            "corrupcion_recovery": 0,
            "redo_archive": 0,
            "texto_standby": 0,
            "asm_storage": 0,
        }

        family_patterns = {
            "internos": [r"ORA-00600", r"ORA-07445"],
            "memoria": [r"ORA-04031", r"ORA-04030"],
            "espacio": [r"ORA-00257", r"ORA-01652", r"ORA-01653", r"ORA-01654"],
            "undo_snapshot": [r"ORA-01555"],
            "corrupcion_recovery": [r"ORA-01578", r"ORA-01110", r"block corruption", r"media corruption", r"corrupt block", r"DBVERIFY"],
            "redo_archive": [r"archive error", r"archiver error", r"\bARC[0-9A-Z]*\b", r"\bLGWR\b", r"checkpoint not complete", r"redo log error", r"log file switch", r"cannot allocate new log"],
            "texto_standby": [r"standby", r"\bMRP[0-9A-Z]*\b", r"\bRFS[0-9A-Z]*\b", r"\bFAL\b"],
            "asm_storage": [r"ASM", r"diskgroup", r"I/O error"],
        }

        for index, event in enumerate(events, start=1):
            text = str(event.get("message_text") or "") if isinstance(event, dict) else str(event)
            for pattern in patterns:
                pattern_text = str(pattern)
                if re.search(pattern_text, text, re.IGNORECASE):
                    counts_by_pattern[pattern_text] = counts_by_pattern.get(pattern_text, 0) + 1
                    if len(matches) < max_samples:
                        matches.append({
                            "linea": index,
                            "timestamp": event.get("timestamp") if isinstance(event, dict) else None,
                            "patron": pattern_text,
                            "texto": text.strip(),
                            "filename": event.get("filename") if isinstance(event, dict) else None,
                            "source": event.get("source", alert_log.get("source")) if isinstance(event, dict) else alert_log.get("source"),
                        })
            if collector.get("summary"):
                for family, family_regexes in family_patterns.items():
                    if any(re.search(family_pattern, text, re.IGNORECASE) for family_pattern in family_regexes):
                        counts_by_family[family] += 1

        occurrences = sum(counts_by_pattern.values())
        truncated = occurrences > len(matches)
        message = (
            f"Se detectaron {occurrences} ocurrencias en el alert log dentro de la muestra evaluada"
            if occurrences else
            collector.get("no_match_message", "No se encontraron patrones de esta familia en el alert log dentro de la muestra evaluada.")
        )
        evidence: dict[str, Any] = {
            "available": True,
            "source": alert_log.get("source"),
            "path": alert_log.get("path"),
            "lookback_hours": alert_log.get("lookback_hours"),
            "family": collector.get("family", check.check_id),
            "occurrences": occurrences,
            "patterns": patterns,
            "counts_by_pattern": counts_by_pattern,
            "sample_lines": matches,
            "sample_limit": max_samples,
            "truncated": truncated,
            "message": message,
            "scope_note": "Se analiza la muestra de alert log disponible mediante V$DIAG_ALERT_EXT o archivo físico; una correlación avanzada de ADR queda fuera de esta fase.",
        }
        if collector.get("summary"):
            evidence["counts_by_family"] = counts_by_family
            evidence["standby_note"] = "Se reportan solo coincidencias textuales con procesos o términos de standby; este check no evalúa la salud de Data Guard."
        return evidence
