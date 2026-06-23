from typing import Any

from orahealthcheck.models import ResultStatus


class AsmEvaluator:
    def evaluate(self, evidence: Any, config: dict[str, Any]) -> tuple[ResultStatus, str]:
        if not isinstance(evidence, dict):
            return ResultStatus.ERROR, "La evidencia ASM no tiene una estructura válida"
        metric = evidence.get("metric") or config.get("metric")
        if evidence.get("collection_error"):
            return ResultStatus.INFO, f"No se pudo consultar evidencia ASM completa para {metric}: {evidence.get('collection_error')}"
        if metric == "asm_database_uses_asm":
            return (ResultStatus.INFO, f"La base usa ASM en diskgroups: {', '.join(evidence.get('diskgroups_detectados') or [])}") if evidence.get("usa_asm") else (ResultStatus.SKIPPED, "No se encontraron archivos de base de datos sobre ASM desde la conexión actual")
        if metric == "asm_database_files_on_asm":
            rows = evidence.get("rows") if isinstance(evidence.get("rows"), list) else []
            return ResultStatus.INFO, f"Se inventariaron {len(rows)} archivos ASM usados por la base evaluada"
        if metric == "asm_diskgroup_inventory_db_view":
            rows = self._rows(evidence)
            return ResultStatus.INFO, f"Se inventariaron {len(rows)} diskgroups ASM visibles desde la conexión de base"
        if metric == "asm_diskgroup_usage_db_view":
            return self._diskgroup_usage(evidence, config)
        if metric == "asm_diskgroup_state_db_view":
            return self._diskgroup_state(evidence, config)
        if metric == "asm_diskgroup_free_headroom_db_view":
            return self._headroom(evidence, config)
        if metric == "asm_disk_status_db_view":
            return self._disk_status(evidence, config)
        if metric == "asm_rebalance_operations_db_view":
            rows = self._rows(evidence)
            if not rows:
                return ResultStatus.PASS, "No se observaron operaciones ASM de rebalance en curso"
            return ResultStatus.INFO, f"Se observaron {len(rows)} operaciones ASM de rebalance visibles desde la base"
        return ResultStatus.ERROR, f"Métrica ASM no soportada: {metric}"

    def _diskgroup_usage(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        values = [self._num(r.get("free_pct")) for r in self._rows(e) if self._num(r.get("free_pct")) is not None]
        if not values:
            return ResultStatus.INFO, "No hay porcentajes comparables de espacio libre ASM"
        worst = min(values)
        status = self._status_for_low_pct(worst, c, "diskgroup_free_critical_pct", "diskgroup_free_fail_pct", "diskgroup_free_warning_pct")
        if status == ResultStatus.PASS:
            return status, f"Espacio libre mínimo ASM {worst}% dentro de umbrales"
        return status, f"Espacio libre mínimo ASM {worst}% bajo umbrales configurados"

    def _headroom(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        rows = self._rows(e)
        values = [self._num(r.get("usable_pct")) for r in rows if self._num(r.get("usable_pct")) is not None]
        keyprefix = "diskgroup_usable_file"
        if not values:
            values = [self._num(r.get("free_pct")) for r in rows if self._num(r.get("free_pct")) is not None]
            keyprefix = "diskgroup_free"
        if not values:
            return ResultStatus.INFO, "No hay margen ASM comparable; se conserva evidencia sin fallo automático"
        worst = min(values)
        status = self._status_for_low_pct(worst, c, f"{keyprefix}_critical_pct", f"{keyprefix}_fail_pct", f"{keyprefix}_warning_pct")
        return (status, f"Margen efectivo ASM mínimo {worst}% {'dentro de umbrales' if status == ResultStatus.PASS else 'bajo umbrales configurados'}")

    def _diskgroup_state(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        acceptable = {str(x).upper() for x in c.get("acceptable_diskgroup_states", ["CONNECTED", "MOUNTED"])}
        used = {str(x).upper().lstrip('+') for x in e.get("used_diskgroups", [])}
        bad = []
        for r in self._rows(e):
            name = str(r.get("name") or r.get("diskgroup") or "").upper().lstrip('+')
            state = str(r.get("state") or "").upper()
            offline = self._num(r.get("offline_disks")) or 0
            if (not used or name in used) and ((state and state not in acceptable) or offline > 0):
                bad.append({"name": name, "state": state, "offline_disks": offline})
        if not bad:
            return ResultStatus.PASS, "Los diskgroups ASM relevantes tienen estado aceptable desde la base"
        return ResultStatus.FAIL, f"Se detectaron {len(bad)} diskgroups ASM relevantes con estado u offline_disks anómalos"

    def _disk_status(self, e: dict[str, Any], c: dict[str, Any]) -> tuple[ResultStatus, str]:
        problem = {str(x).upper() for x in c.get("disk_problem_statuses", [])}
        bad=[]
        for r in self._rows(e):
            vals = {str(r.get(k) or "").upper() for k in ("header_status", "mode_status", "state", "mount_status")}
            if vals & problem:
                bad.append(r)
        if not bad:
            return ResultStatus.PASS, "No se detectaron discos ASM visibles con estados problemáticos claros"
        return ResultStatus.FAIL, f"Se detectaron {len(bad)} discos ASM visibles con estado problemático"

    def _rows(self, e: dict[str, Any]) -> list[dict[str, Any]]:
        return e.get("rows") if isinstance(e.get("rows"), list) else []

    def _status_for_low_pct(self, value: float, c: dict[str, Any], crit_key: str, fail_key: str, warn_key: str) -> ResultStatus:
        crit = self._num(c.get(crit_key)); fail = self._num(c.get(fail_key)); warn = self._num(c.get(warn_key))
        if crit is not None and value <= crit: return ResultStatus.CRITICAL
        if fail is not None and value <= fail: return ResultStatus.FAIL
        if warn is not None and value <= warn: return ResultStatus.WARNING
        return ResultStatus.PASS

    def _num(self, v: Any) -> float | None:
        try:
            if v is None: return None
            if isinstance(v, str):
                v = v.strip().replace(',', '')
                if not v: return None
            return float(v)
        except (TypeError, ValueError):
            return None
