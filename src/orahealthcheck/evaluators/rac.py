from __future__ import annotations

from typing import Any

from orahealthcheck.models import ResultStatus


class RacEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia RAC no tiene una estructura válida"
        if evidence.get("collection_error"):
            return ResultStatus.SKIPPED, f"No se pudo recolectar evidencia RAC: {evidence.get('collection_error')}"
        metric = evidence.get("metric") or config.get("metric")
        handler = getattr(self, f"_{metric}", None)
        if handler is None:
            return ResultStatus.ERROR, f"Métrica RAC no soportada: {metric}"
        return handler(evidence, config)

    def _rac_cluster_database_parameter(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        value = str(e.get("cluster_database", "")).upper()
        if value == "TRUE":
            return ResultStatus.PASS, "El parámetro cluster_database está habilitado para Oracle RAC."
        return ResultStatus.FAIL, "La característica Oracle RAC fue detectada, pero cluster_database no está en TRUE."

    def _rac_instances_status(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = e.get("rows") or []
        bad = [r for r in rows if str(r.get("status", "")).upper() != "OPEN" or str(r.get("active_state", "")).upper() not in {"NORMAL", "ACTIVE", ""}]
        if not rows:
            return ResultStatus.WARNING, "No se detectaron instancias RAC visibles para validar."
        if bad:
            return ResultStatus.WARNING, f"Se detectaron {len(bad)} instancia(s) RAC visibles con estado anómalo."
        return ResultStatus.PASS, "Las instancias RAC visibles se encuentran en estado operativo."

    def _rac_instance_count(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        count = int(e.get("instance_count") or 0)
        minimum = int(e.get("min_instances") or c.get("min_instances", 2))
        if count >= minimum:
            return ResultStatus.PASS, "La cantidad de instancias RAC visibles cumple el mínimo configurado."
        return ResultStatus.WARNING, f"La cantidad de instancias RAC visibles ({count}) es menor al mínimo configurado ({minimum})."

    def _rac_threads_status(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = e.get("rows") or []
        bad = [r for r in rows if str(r.get("enabled", "")).upper() not in {"PUBLIC", "PRIVATE", "YES"} or str(r.get("status", "")).upper() not in {"OPEN", "CLOSED", "ACTIVE"}]
        if not rows:
            return ResultStatus.WARNING, "No se detectaron threads redo RAC visibles para validar."
        if bad:
            return ResultStatus.WARNING, f"Se detectaron {len(bad)} thread(s) redo RAC deshabilitados o inconsistentes."
        return ResultStatus.PASS, "Los threads redo RAC visibles se encuentran habilitados y consistentes."

    def _rac_undo_configuration_basic(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = e.get("rows") or []
        missing = [r for r in rows if not str(r.get("value") or "").strip()]
        if not rows:
            return ResultStatus.WARNING, "No se detectó configuración UNDO por instancia RAC visible."
        if missing:
            return ResultStatus.WARNING, f"Se detectaron {len(missing)} instancia(s) RAC sin tablespace UNDO configurado."
        return ResultStatus.PASS, "Cada instancia RAC visible tiene tablespace UNDO configurado."

    def _rac_services_basic(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        return ResultStatus.INFO, "Servicios RAC recolectados para inventario operativo."

    def _rac_interconnect_info(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        return ResultStatus.INFO, "Información de interconnect RAC recolectada para inventario."
