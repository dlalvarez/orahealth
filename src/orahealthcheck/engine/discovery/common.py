"""Utilidades compartidas de consulta, normalización y evidencia.

Extraído de ``engine/runner.py`` sin cambios de comportamiento (Fase C2).
"""

from __future__ import annotations

import logging
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from orahealthcheck.models import Check
from orahealthcheck.engine.requirements import CORE_VIEWS, required_views
from orahealthcheck.evaluators.oracle_resources import OracleResourcesEvaluator


class CommonMixin:
    def _views_to_probe(self, checks: list[Check] | None) -> list[str]:
        views: dict[str, None] = dict.fromkeys(CORE_VIEWS)
        for check in checks or []:
            for view in required_views(check):
                views[view] = None
        return list(views)

    def _probe_view_access(self, connector: Any, views: list[str]) -> dict[str, dict[str, Any]]:
        """Verifica acceso de lectura a cada vista sin traer filas (``where 1 = 0``)."""
        access: dict[str, dict[str, Any]] = {}
        for view in views:
            if not all(ch.isalnum() or ch in "_$" for ch in view):
                access[view] = {"accessible": False, "error": "Nombre de vista inválido en la configuración"}
                continue
            try:
                connector.query(f"select 1 from {view} where 1 = 0")
                access[view] = {"accessible": True, "error": None}
            except Exception as exc:
                logging.warning("Sin acceso a %s: %s", view, exc)
                access[view] = {"accessible": False, "error": str(exc)}
        return access

    def _safe_number(self, value: Any) -> float:
        try:
            return float(value or 0)
        except (TypeError, ValueError):
            return 0

    def _is_recent_datetime(self, value: Any, days: int) -> bool:
        if value is None:
            return False
        try:
            from datetime import datetime, timedelta
            if isinstance(value, datetime):
                return value >= datetime.now(value.tzinfo) - timedelta(days=days)
            text = str(value).strip()
            candidates = (text[:19].replace("T", " "), text[:10])
            for candidate, fmt in ((candidates[0], "%Y-%m-%d %H:%M:%S"), (candidates[1], "%Y-%m-%d")):
                try:
                    parsed = datetime.strptime(candidate, fmt)
                    return parsed >= datetime.now() - timedelta(days=days)
                except ValueError:
                    continue
        except Exception:
            return False
        return False

    def _parameter_value(self, parameters: dict[str, Any], name: str) -> Any:
        data = parameters.get(name.lower(), {}) if isinstance(parameters, dict) else {}
        if not isinstance(data, dict):
            return None
        return data.get("display_value", data.get("value"))

    def _record_query_failure(self, label: str, exc: Any) -> None:
        failures = getattr(self, "_query_failures", None)
        if failures is None:
            failures = self._query_failures = []
        failures.append({"query": label, "error": str(exc)})

    def _query_one(self, connector: Any, label: str, sql: str) -> dict[str, Any]:
        rows = self._query_rows(connector, label, sql)
        return rows[0] if rows else {}

    def _query_rows(self, connector: Any, label: str, sql: str) -> list[dict[str, Any]]:
        rows, _ = self._query_rows_with_error(connector, label, sql)
        return rows

    def _query_rows_with_error(self, connector: Any, label: str, sql: str, log_warning: bool = True) -> tuple[list[dict[str, Any]], str | None]:
        try:
            rows = connector.query(sql)
        except Exception as exc:
            if log_warning:
                # log_warning=False se usa en consultas de sondeo con fallback; solo se
                # registran como fallo las consultas definitivas.
                logging.warning("Oracle inventory query failed for %s: %s", label, exc)
                self._record_query_failure(label, exc)
            return [], str(exc)
        return [
            {key: self._normalize_inventory_value(value) for key, value in dict(row).items()}
            for row in rows
        ], None

    def _normalize_inventory_value(self, value: Any) -> Any:
        if isinstance(value, Decimal):
            return int(value) if value == value.to_integral_value() else float(value)
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        return value

    def _bytes_to_mb(self, value: Any) -> float | None:
        num = self._safe_float(value)
        return round(num / 1024 / 1024, 2) if num else None

    def _parse_memory_value_bytes(self, value: Any) -> float | None:
        parsed = OracleResourcesEvaluator()._memory_value_bytes(value)
        return parsed if parsed is not None else self._safe_float(value)

    def _safe_float(self, value: Any) -> float | None:
        try:
            if value is None:
                return None
            if isinstance(value, str):
                cleaned = value.strip().replace(",", "")
                if not cleaned or cleaned.upper() == "UNLIMITED":
                    return None
                return float(cleaned)
            return float(value)
        except (TypeError, ValueError):
            return None

    def _sql_in_list(self, values: set[str]) -> str:
        return ",".join(f"'{value}'" for value in sorted(values))

    def _build_oracle_config_evidence(
        self,
        check: Check,
        name: str,
        actual: Any,
        source: str,
        exists: bool = True,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        evidence = {
            "metric": name,
            "parameter": name if check.collector.get("type") == "oracle_parameter" else None,
            "actual_value": actual,
            "source": source,
            "exists": exists and actual is not None,
        }
        if check.evaluator.get("expected") is not None:
            evidence["expected_value"] = check.evaluator.get("expected")
        if check.evaluator.get("minimum") is not None:
            evidence["minimum"] = check.evaluator.get("minimum")
        if check.evaluator.get("disallowed_values") is not None:
            evidence["disallowed_values"] = check.evaluator.get("disallowed_values")
        if extra:
            evidence.update({key: value for key, value in extra.items() if value is not None})
        return evidence
