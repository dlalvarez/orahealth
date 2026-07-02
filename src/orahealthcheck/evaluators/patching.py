from typing import Any

from orahealthcheck.models import ResultStatus


class PatchingEvaluator:
    PROBLEM_STATUSES = {"WITH ERRORS", "FAILED", "ERROR", "FAILURE"}
    OK_STATUSES = {"SUCCESS", "SUCCESSFUL", "COMPLETED"}
    WARNING_STATUSES = {"", "IN PROGRESS", "UNKNOWN", "PENDING"}

    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia de patching no tiene una estructura válida"
        metric = evidence.get("metric") or config.get("metric")
        if evidence.get("collection_error"):
            return ResultStatus.SKIPPED, f"No fue posible consultar la vista requerida para patching: {evidence.get('collection_error')}"
        if metric == "patching_database_version":
            if not (evidence.get("instance_version") or evidence.get("database_version")):
                return ResultStatus.WARNING, "No fue posible determinar la versión observable de la base o instancia"
            return ResultStatus.INFO, "Versión observable de base de datos e instancia reportada para readiness de patching"
        if metric == "patching_registry_sqlpatch_status":
            rows = self._rows(evidence, "rows")
            if not rows:
                empty_status = str(config.get("empty_inventory_status", "INFO")).upper()
                status = ResultStatus.WARNING if empty_status == "WARNING" else ResultStatus.INFO
                return status, "DBA_REGISTRY_SQLPATCH no muestra entradas; inventario SQL patch limitado, sin asumir falla automática"
            return ResultStatus.INFO, f"Se reportan {len(rows)} entradas del inventario SQL patch"
        if metric == "patching_registry_sqlpatch_errors":
            rows = self._rows(evidence, "rows")
            problems = [r for r in rows if self._status(r) in self.PROBLEM_STATUSES]
            unexpected = [r for r in rows if self._status(r) not in self.PROBLEM_STATUSES | self.OK_STATUSES and self._status(r) in self.WARNING_STATUSES]
            if problems:
                return ResultStatus.FAIL, f"Se detectaron {len(problems)} entradas SQL patch con estado problemático"
            if unexpected:
                return ResultStatus.WARNING, f"Se detectaron {len(unexpected)} entradas SQL patch con estado incompleto o inesperado"
            return ResultStatus.PASS, "No se detectaron errores en DBA_REGISTRY_SQLPATCH"
        if metric == "patching_registry_components_status":
            rows = self._rows(evidence, "components") or self._rows(evidence, "rows")
            invalid = [r for r in rows if str(r.get("status") or "").upper() == "INVALID"]
            nonvalid = [r for r in rows if str(r.get("status") or "").upper() not in {"VALID", "INVALID"}]
            if invalid:
                return ResultStatus.FAIL, f"Se detectaron {len(invalid)} componentes de registry en estado INVALID"
            if nonvalid:
                return ResultStatus.WARNING, f"Se detectaron {len(nonvalid)} componentes de registry en estados que requieren revisión"
            return ResultStatus.PASS, "Todos los componentes de registry observados están VALID"
        if metric == "patching_invalid_objects_prepatch":
            invalid = int(evidence.get("application_invalid_count") or evidence.get("invalid_count") or 0)
            fail = int(config.get("invalid_objects_fail", 20) or 20)
            warn = int(config.get("invalid_objects_warning", 1) or 1)
            critical_types = evidence.get("critical_invalid_count") or 0
            if invalid >= fail or critical_types:
                return ResultStatus.FAIL, f"Se detectaron {invalid} objetos inválidos de aplicación antes de la ventana de patching"
            if invalid >= warn:
                return ResultStatus.WARNING, f"Se detectaron {invalid} objetos inválidos de aplicación preexistentes"
            return ResultStatus.PASS, "No se detectaron objetos inválidos de aplicación preexistentes relevantes"
        if metric == "patching_datapatch_inventory_consistency":
            rows = self._rows(evidence, "rows")
            if not rows:
                return ResultStatus.WARNING, "Inventario SQL patch vacío o insuficiente para evaluar consistencia observable"
            latest = self._latest_by_patch(rows)
            problems = [r for r in latest if self._status(r) in self.PROBLEM_STATUSES]
            unclear = [r for r in latest if not r.get("action") or not r.get("action_time")]
            if problems:
                return ResultStatus.FAIL, f"La última acción de {len(problems)} patch(es) quedó con estado problemático"
            if unclear:
                return ResultStatus.WARNING, f"No se pudo determinar claramente la última acción de {len(unclear)} patch(es)"
            return ResultStatus.PASS, "El inventario SQL patch observable es consistente"
        if metric == "patching_database_open_mode_readiness":
            role = str(evidence.get("database_role") or evidence.get("role") or "").upper()
            open_mode = str(evidence.get("open_mode") or "").upper()
            db_status = str(evidence.get("status") or "").upper()
            if not (role or open_mode or db_status):
                return ResultStatus.SKIPPED, "Sin información suficiente de V$DATABASE/V$INSTANCE para evaluar modo de apertura"
            if role == "PRIMARY" and open_mode == "READ WRITE" and db_status in {"OPEN", ""}:
                return ResultStatus.PASS, "La base PRIMARY está en READ WRITE para evaluación SQL normal de patching"
            if "READ ONLY" in open_mode or "STANDBY" in role:
                return ResultStatus.INFO, "La base está en modo read only o standby; la evaluación SQL de patching tiene limitaciones operativas"
            return ResultStatus.WARNING, "El modo de apertura observado puede limitar la evaluación SQL de patching"
        if metric == "patching_pdb_sqlpatch_status":
            if not evidence.get("is_cdb"):
                return ResultStatus.SKIPPED, "La base no es CDB; no aplica evaluación de SQL patch por PDB"
            problem_pdbs = self._rows(evidence, "problem_pdbs")
            closed = [p for p in self._rows(evidence, "pdbs") if str(p.get("open_mode") or "").upper() != "READ WRITE"]
            if problem_pdbs:
                return ResultStatus.FAIL, f"Se detectaron {len(problem_pdbs)} PDB(s) con SQL patch en error"
            if closed or not self._rows(evidence, "pdb_patch_rows"):
                return ResultStatus.WARNING, "Hay PDBs no abiertas o evidencia SQL patch por PDB insuficiente"
            return ResultStatus.PASS, "Las PDBs observadas no muestran errores de SQL patch"
        return ResultStatus.ERROR, f"Métrica de patching no soportada: {metric}"

    def _rows(self, evidence: dict[str, Any], key: str) -> list[dict[str, Any]]:
        return evidence.get(key) if isinstance(evidence.get(key), list) else []

    def _status(self, row: dict[str, Any]) -> str:
        return str(row.get("status") or "").strip().upper()

    def _latest_by_patch(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for idx, row in enumerate(rows):
            key = str(row.get("patch_uid") or row.get("patch_id") or idx)
            current = grouped.get(key)
            if current is None or str(row.get("action_time") or "") >= str(current.get("action_time") or ""):
                grouped[key] = row
        return list(grouped.values())
