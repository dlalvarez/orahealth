from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import html
import json
import re

from orahealthcheck.models import ConnectionProfile, Inventory, Result, Target
from orahealthcheck.utils.masking import mask_secrets


STATUS_ORDER = {"CRITICAL": 0, "ERROR": 1, "FAIL": 2, "WARNING": 3, "INFO": 4, "PASS": 5, "SKIPPED": 6}
ACTION_STATUSES = {"FAIL", "CRITICAL", "WARNING", "ERROR"}
ALL_STATUSES = ("PASS", "INFO", "WARNING", "FAIL", "CRITICAL", "ERROR", "SKIPPED")
OWNER_ORDER = ("DBA", "OS", "Seguridad", "Aplicación", "Otro")

STATUS_LABELS = {
    "PASS": "Correcto",
    "INFO": "Informativo",
    "WARNING": "Advertencia",
    "FAIL": "Fallo",
    "CRITICAL": "Crítico",
    "ERROR": "Error",
    "SKIPPED": "Omitido",
}

GROUP_LABELS = {
    "configuration_general": "Configuración general",
    "storage": "Almacenamiento",
    "schema_objects": "Esquemas y objetos",
    "os": "Sistema operativo",
    "alert_log": "Alert log",
    "security": "Seguridad Oracle",
    "performance": "Rendimiento",
    "rac": "RAC",
    "dataguard": "Data Guard",
    "asm": "ASM",
    "capacity": "Capacidad",
    "patching": "Parches",
}

CHECK_TITLE_TRANSLATIONS = {
    "Estado de base de datos OPEN": "Estado de base de datos OPEN",
    "Modo de apertura de base de datos READ WRITE": "Modo de apertura de base de datos READ WRITE",
    "Base de datos en modo ARCHIVELOG": "Base de datos en modo ARCHIVELOG",
    "Porcentaje mínimo libre en tablespaces": "Porcentaje mínimo libre en tablespaces",
    "Porcentaje de uso de FRA": "Porcentaje de uso de FRA",
    "Cantidad de objetos inválidos dentro del umbral": "Cantidad de objetos inválidos dentro del umbral",
    "Uso de filesystems del sistema operativo bajo umbrales críticos": "Uso de filesystems del sistema operativo bajo umbrales críticos",
    "Información de memoria del sistema operativo recolectada correctamente": "Información de memoria del sistema operativo recolectada correctamente",
    "Información de CPU del sistema operativo recolectada correctamente": "Información de CPU del sistema operativo recolectada correctamente",
    "Alert log sin errores ORA críticos en la muestra": "Alert log sin errores ORA críticos en la muestra",
}

DB_INVENTORY_FIELDS = (
    ("status", "Estado de la base de datos"),
    ("open_mode", "Estado de apertura"),
    ("role", "Rol de base de datos"),
    ("archivelog_mode", "Modo ARCHIVELOG"),
    ("version", "Versión"),
    ("invalid_objects_count", "Objetos inválidos"),
    ("tablespace_min_free_pct", "Mínimo porcentaje libre en tablespaces"),
    ("fra_configured", "FRA configurada"),
    ("fra_used_pct", "Uso de FRA"),
)


class HTMLReporter:
    def __init__(self, template_dir: Path) -> None:
        self.template_dir = template_dir
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape  # type: ignore
        except ImportError:  # pragma: no cover - fallback for minimal environments
            self.env = None
        else:
            self.env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=select_autoescape(["html", "xml"]))
            self.env.filters["pretty_json"] = self._pretty_json
            self.env.filters["status_label"] = self._status_label
            self.env.filters["group_label"] = self._group_label
            self.env.filters["check_title"] = self._check_title
            self.env.filters["friendly_message"] = self._friendly_message

    def generate(self, output_dir: Path, target: Target, inventory: Inventory, results: list[Result], summary: dict[str, Any], config: dict[str, Any] | None = None) -> None:
        findings = self._sort_results([r for r in results if r.status.value in ACTION_STATUSES])
        grouped_results = self._group_results(results)
        corrective_actions = self._group_corrective_actions(findings)
        inventory_dict = mask_secrets(inventory.to_dict())
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        context = {
            "target": target,
            "inventory": inventory_dict,
            "target_info": self._target_info(target, inventory_dict, generated_at, config),
            "database_inventory_items": self._database_inventory_items(inventory_dict),
            "os_inventory_enriched": self._os_inventory_enriched(inventory_dict, results),
            "results": self._sort_results(results),
            "grouped_results": grouped_results,
            "summary": self._summary_with_defaults(summary, results),
            "findings": findings,
            "corrective_actions": corrective_actions,
            "generated_at": generated_at,
        }
        mapping = {
            "executive_report.html.j2": "executive_report.html",
            "technical_report.html.j2": "technical_report.html",
            "corrective_actions.html.j2": "corrective_actions.html",
            "evidence_report.html.j2": "evidence_report.html",
        }
        for template_name, output_name in mapping.items():
            if self.env:
                rendered = self.env.get_template(template_name).render(**context)
            else:
                rendered = self._fallback_render(output_name, **context)
            (output_dir / output_name).write_text(rendered, encoding="utf-8")

    def _target_info(self, target: Target, inventory: dict[str, Any], generated_at: str, config: dict[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
        general = [
            {"label": "target_id", "value": target.target_id},
            {"label": "nombre", "value": target.name},
            {"label": "ambiente", "value": target.environment},
            {"label": "arquitectura esperada", "value": target.expected_architecture},
            {"label": "perfil", "value": target.profile},
            {"label": "fecha/hora de ejecución", "value": generated_at},
        ]
        database = self._database_connection_info(target, config)
        operating_system = self._os_connection_info(target, inventory, config)
        return {"general": general, "database": database, "operating_system": operating_system}

    def _database_connection_info(self, target: Target, config: dict[str, Any] | None) -> list[dict[str, Any]]:
        connection_id = target.database.get("primary_connection")
        items: list[dict[str, Any]] = []
        if connection_id:
            items.append({"label": "connection profile usado", "value": connection_id})
            profile = self._connection_profile(config, "db_connections", connection_id)
            items.extend(self._connection_items(profile, ("host", "port", "service_name", "sid", "tns_alias", "username", "mode", "auth_method", "password_env", "sysdba")))
        if "sysdba" in target.features and not any(item["label"] == "sysdba" for item in items):
            items.append({"label": "sysdba", "value": target.features.get("sysdba")})
        return items

    def _os_connection_info(self, target: Target, inventory: dict[str, Any], config: dict[str, Any] | None) -> list[dict[str, Any]]:
        connection_ids = target.operating_system.get("connections") or []
        connection_id = connection_ids[0] if connection_ids else None
        items: list[dict[str, Any]] = []
        if connection_id:
            items.append({"label": "connection profile usado", "value": connection_id})
            profile = self._connection_profile(config, "os_connections", connection_id)
            items.extend(self._connection_items(profile, ("host", "port", "username", "auth_method", "password_env", "sudo")))
        os_data = inventory.get("operating_system", {})
        for key in ("platform", "distribution", "sudo"):
            value = target.operating_system.get(key, os_data.get(key))
            if value not in (None, "") and not any(item["label"] == key for item in items):
                items.append({"label": key, "value": value})
        return items

    def _connection_profile(self, config: dict[str, Any] | None, section: str, connection_id: str) -> ConnectionProfile | None:
        if not config:
            return None
        profile = config.get("connections", {}).get(section, {}).get(connection_id)
        return profile if isinstance(profile, ConnectionProfile) else None

    def _connection_items(self, profile: ConnectionProfile | None, fields: tuple[str, ...]) -> list[dict[str, Any]]:
        if not profile:
            return []
        raw = {"auth_method": profile.auth_method, **profile.settings}
        items: list[dict[str, Any]] = []
        for field in fields:
            if field == "password" or "password" in field.lower() and field != "password_env":
                continue
            value = raw.get(field)
            if value not in (None, ""):
                items.append({"label": field, "value": value})
        if raw.get("password") and not any(item["label"] == "password_env" for item in items):
            items.append({"label": "password", "value": "********"})
        return items

    def _database_inventory_items(self, inventory: dict[str, Any]) -> list[dict[str, Any]]:
        database = inventory.get("database", {})
        return [{"label": label, "technical_name": key, "value": database.get(key, "N/D")} for key, label in DB_INVENTORY_FIELDS]

    def _os_inventory_enriched(self, inventory: dict[str, Any], results: list[Result]) -> dict[str, Any]:
        os_data = dict(inventory.get("operating_system", {}))
        evidence_by_check = {result.check_id: result.evidence for result in results}
        cpu_evidence = evidence_by_check.get("os_cpu")
        memory_evidence = evidence_by_check.get("os_memory")
        filesystem_evidence = evidence_by_check.get("os_filesystem_usage")
        cpu_count = cpu_evidence.get("cpu_count") if isinstance(cpu_evidence, dict) else os_data.get("cpu_count")
        total_mb = memory_evidence.get("total_mb") if isinstance(memory_evidence, dict) else os_data.get("total_mb")
        available_mb = memory_evidence.get("available_mb") if isinstance(memory_evidence, dict) else os_data.get("available_mb")
        filesystems = filesystem_evidence if isinstance(filesystem_evidence, list) else os_data.get("filesystems") or []
        max_fs = max(filesystems, key=lambda item: item.get("used_pct", -1)) if filesystems else None
        return {
            "platform": os_data.get("platform", "N/D"),
            "distribution": os_data.get("distribution"),
            "cpu_summary": f"{cpu_count} CPU(s)" if cpu_count is not None else "N/D",
            "memory_summary": f"{total_mb} MB total / {available_mb} MB disponible" if total_mb is not None and available_mb is not None else "N/D",
            "filesystems_summary": f"{len(filesystems)} filesystems evaluados, mayor uso: {max_fs.get('mount')} {max_fs.get('used_pct')}%" if max_fs else "N/D",
            "filesystems": filesystems,
        }

    def _status_label(self, status: str) -> str:
        return STATUS_LABELS.get(status, status.title())

    def _group_label(self, group_id: str) -> str:
        return GROUP_LABELS.get(group_id, group_id.replace("_", " ").title())

    def _check_title(self, title: str) -> str:
        return CHECK_TITLE_TRANSLATIONS.get(title, title)

    def _friendly_message(self, message: str | None) -> str:
        if not message:
            return ""
        patterns = (
            (r"^Actual value matches expected value (.+)$", r"Valor actual coincide con el valor esperado \1."),
            (r"^Actual value '(.+)' differs from expected '(.+)'$", r"Valor actual '\1' difiere del valor esperado '\2'."),
            (r"^Value (.+) is within threshold$", r"El valor \1 está dentro del umbral configurado."),
            (r"^Regex condition passed$", "La condición de expresión regular fue satisfactoria."),
            (r"^FRA is not configured or space_limit is 0$", "FRA no está configurada o space_limit es 0."),
            (r"^FRA is not configured$", "FRA no está configurada."),
        )
        for pattern, replacement in patterns:
            if re.match(pattern, message):
                return re.sub(pattern, replacement, message)
        return message

    def _summary_with_defaults(self, summary: dict[str, Any], results: list[Result]) -> dict[str, Any]:
        enriched = {status: int(summary.get(status, 0)) for status in ALL_STATUSES}
        enriched.update(summary)
        enriched["total_checks"] = len(results)
        return enriched

    def _sort_results(self, results: list[Result]) -> list[Result]:
        return sorted(results, key=lambda result: (STATUS_ORDER.get(result.status.value, 99), result.group_id, result.check_id))

    def _group_results(self, results: list[Result]) -> dict[str, list[Result]]:
        grouped: dict[str, list[Result]] = defaultdict(list)
        for result in self._sort_results(results):
            grouped[result.group_id].append(result)
        return dict(sorted(grouped.items()))

    def _group_corrective_actions(self, findings: list[Result]) -> dict[str, list[Result]]:
        grouped: dict[str, list[Result]] = {owner: [] for owner in OWNER_ORDER}
        for result in findings:
            owner = str(result.remediation.get("owner") or "Otro")
            if owner == "Security":
                owner = "Seguridad"
            if owner == "Application":
                owner = "Aplicación"
            if owner not in grouped:
                owner = "Otro"
            grouped[owner].append(result)
        return {owner: grouped[owner] for owner in OWNER_ORDER if grouped[owner]}

    def _pretty_json(self, value: Any) -> str:
        return json.dumps(mask_secrets(value), indent=2, ensure_ascii=False, sort_keys=True)

    def _fallback_render(
        self,
        output_name: str,
        target: Target,
        inventory: dict[str, Any],
        results: list[Result],
        summary: dict[str, Any],
        findings: list[Result],
        target_info: dict[str, list[dict[str, Any]]],
        database_inventory_items: list[dict[str, Any]],
        os_inventory_enriched: dict[str, Any],
        grouped_results: dict[str, list[Result]],
        corrective_actions: dict[str, list[Result]],
        generated_at: str,
        **_: Any,
    ) -> str:
        def esc(value: Any) -> str:
            return html.escape(str(value))

        def badge(status: str) -> str:
            icon = {"PASS": "🟢", "INFO": "🔵", "WARNING": "🟡", "FAIL": "🔴", "CRITICAL": "🛑", "ERROR": "🟣", "SKIPPED": "⚪"}.get(status, "⚪")
            return f'<span class="badge {esc(status)}">{icon} {esc(status)} / {esc(self._status_label(status))}</span>'

        def info_section() -> str:
            parts = ["<section><h2>Información del target</h2>"]
            labels = (("general", "Datos generales"), ("database", "Datos de base de datos"), ("operating_system", "Datos del servidor / sistema operativo"))
            for key, title in labels:
                items = target_info.get(key, [])
                if not items:
                    continue
                parts.append(f"<h3>{title}</h3><div class='grid'>")
                for item in items:
                    parts.append(f"<div class='card'><span>{esc(item['label'])}</span><strong>{esc(item['value'])}</strong></div>")
                parts.append("</div>")
            parts.append("</section>")
            return "".join(parts)

        style = """
        <style>body{margin:0;background:#f4f7fb;color:#172033;font-family:"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-size:13px;line-height:1.35}.page{max-width:1440px;margin:auto;padding:20px 16px}.hero,section{background:#fff;border:1px solid #dfe7f1;border-radius:16px;box-shadow:0 8px 22px rgba(23,32,51,.07);padding:16px 18px;margin:16px 0}.hero{background:linear-gradient(135deg,#13213a,#234876);color:#fff;padding:20px 24px}.hero h1{font-size:1.55rem;margin:.2rem 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:9px}.card{background:#fff;border:1px solid #dfe7f1;border-radius:12px;padding:10px 12px;color:#172033}.card span{color:#637083;font-size:.74rem}.card strong{display:block;font-size:1.35rem;word-break:break-word}.badge{display:inline-flex;gap:5px;border-radius:999px;padding:4px 8px;font-weight:700;font-size:11px;white-space:nowrap}.PASS{color:#15803d;background:#dcfce7}.INFO{color:#1d4ed8;background:#dbeafe}.WARNING{color:#b45309;background:#fef3c7}.FAIL{color:#dc2626;background:#fee2e2}.CRITICAL{color:#7f1d1d;background:#fecaca}.ERROR{color:#581c87;background:#f3e8ff}.SKIPPED{color:#64748b;background:#f1f5f9}.table-wrap{overflow-x:auto;border:1px solid #dfe7f1;border-radius:12px;margin-top:10px}table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:7px 9px;border-bottom:1px solid #dfe7f1;text-align:left;vertical-align:top}th{background:#f8fafc;color:#475569;text-transform:uppercase;font-size:11px;letter-spacing:.05em}pre{background:#0f172a;color:#e2e8f0;border-radius:10px;padding:10px;max-height:190px;overflow:auto;white-space:pre-wrap;font-size:11px;line-height:1.3}.positive{border-left:5px solid #15803d;background:#f0fdf4;padding:12px;border-radius:12px}article{padding:13px;border-top:1px solid #dfe7f1}li{margin:3px 0}.evidence-item{border:1px solid #dfe7f1;border-radius:12px;margin:10px 0;background:#fff;overflow:hidden}.evidence-item summary{cursor:pointer;display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:12px 14px;background:#f8fafc}.evidence-item summary small{color:#637083;flex-basis:100%}.evidence-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:9px;padding:12px}.json-block{max-height:none}.no-evidence{border-left:5px solid #64748b;background:#f1f5f9;padding:10px;border-radius:10px;color:#64748b}@media(max-width:700px){.page{padding:14px 10px}.hero{padding:16px}th,td{padding:7px}}</style>
        """
        title_by_output = {"executive_report.html": "Reporte Ejecutivo", "technical_report.html": "Reporte Técnico", "corrective_actions.html": "Acciones Correctivas", "evidence_report.html": "Reporte de Evidencias Técnicas"}
        body = ["<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>", f"<title>OraHealthCheck {title_by_output.get(output_name, 'Reporte')} - {esc(target.target_id)}</title>", style, "</head><body><div class='page'>"]
        
        if output_name == "evidence_report.html":
            body.append("<header class='hero'><div>OraHealthCheck</div><h1>Reporte de Evidencias Técnicas</h1><p>Evidencia completa generada por cada validación ejecutada. Este reporte complementa el reporte técnico y conserva el detalle JSON sin sobrecargar la vista principal.</p></header>")
        else:
            body.append(f"<header class='hero'><div>OraHealthCheck</div><h1>{title_by_output.get(output_name, 'Reporte')}</h1><p>{esc(target.name)} · {esc(target.environment)} · {esc(generated_at)}</p></header>")
        body.append(info_section())

        if output_name == "executive_report.html":
            body.append("<section><h2>Resumen Ejecutivo</h2><p>El puntaje inicia en 100 y disminuye ante hallazgos de riesgo.</p><div class='grid'>")
            for label, value in (("Puntaje de Salud", summary.get("score")), ("Estado Global", badge(str(summary.get("global_status")))), ("Total de validaciones", summary.get("total_checks")), ("PASS", summary.get("PASS")), ("WARNING", summary.get("WARNING")), ("FAIL", summary.get("FAIL")), ("ERROR", summary.get("ERROR")), ("SKIPPED", summary.get("SKIPPED"))):
                body.append(f"<div class='card'><span>{label}</span><strong>{value}</strong></div>")
            body.append("</div></section><section><h2>Hallazgos Principales</h2>")
            if findings:
                body.append("<div class='table-wrap'><table><tr><th>Estado</th><th>Grupo</th><th>Validación</th><th>Mensaje</th><th>Severidad</th><th>Acción recomendada</th></tr>")
                for result in findings:
                    msg = self._friendly_message(result.message or result.error or result.skipped_reason)
                    body.append(f"<tr><td>{badge(result.status.value)}</td><td>{esc(self._group_label(result.group_id))}<br><small>{esc(result.group_id)}</small></td><td>{esc(self._check_title(result.title))}<br><small>{esc(result.check_id)}</small></td><td>{esc(msg)}</td><td>{esc(self._status_label(result.failure_severity))}</td><td>{esc(result.remediation.get('summary') or 'Revisar evidencia.')}</td></tr>")
                body.append("</table></div>")
            else:
                body.append("<div class='positive'>Todas las validaciones evaluadas están saludables. No hay hallazgos principales para reportar.</div>")
            body.append("</section>")
        elif output_name == "technical_report.html":
            body.append("<section><h2>Resumen Global</h2><div class='grid'>")
            for label, value in (("Puntaje de Salud", summary.get("score")), ("Estado Global", badge(str(summary.get("global_status")))), ("Total de validaciones", summary.get("total_checks"))):
                body.append(f"<div class='card'><span>{label}</span><strong>{value}</strong></div>")
            body.append("</div></section><section><h2>Inventario Técnico</h2><h3>Inventario de Base de Datos</h3><div class='grid'>")
            for item in database_inventory_items:
                body.append(f"<div class='card'><span>{esc(item['label'])}</span><strong>{esc(item['value'])}</strong><small>{esc(item['technical_name'])}</small></div>")
            body.append("</div><h3>Inventario del Sistema Operativo</h3><div class='grid'>")
            for label, value in (("Plataforma", os_inventory_enriched.get("platform")), ("CPU", os_inventory_enriched.get("cpu_summary")), ("Memoria", os_inventory_enriched.get("memory_summary")), ("Filesystems", os_inventory_enriched.get("filesystems_summary"))):
                body.append(f"<div class='card'><span>{label}</span><strong>{esc(value)}</strong></div>")
            body.append("</div>")
            if os_inventory_enriched.get("filesystems"):
                body.append("<div class='table-wrap'><table><tr><th>Filesystem</th><th>Mount</th><th>Uso (%)</th></tr>")
                for fs in os_inventory_enriched["filesystems"]:
                    body.append(f"<tr><td>{esc(fs.get('filesystem'))}</td><td>{esc(fs.get('mount'))}</td><td>{esc(fs.get('used_pct'))}</td></tr>")
                body.append("</table></div>")
            body.append("</section><section><h2>Detalle de validaciones</h2>")
            for group_id, group_results in grouped_results.items():
                body.append(f"<h3>{esc(self._group_label(group_id))} <small>{esc(group_id)}</small></h3><div class='table-wrap'><table><tr><th>check_id</th><th>Título</th><th>Grupo</th><th>Estado</th><th>Severidad</th><th>Mensaje</th><th>skipped_reason</th><th>error</th><th>duration_ms</th></tr>")
                for result in group_results:
                    body.append(f"<tr><td>{esc(result.check_id)}</td><td>{esc(self._check_title(result.title))}</td><td>{esc(self._group_label(result.group_id))}</td><td>{badge(result.status.value)}</td><td>{esc(self._status_label(result.failure_severity))}</td><td>{esc(self._friendly_message(result.message))}</td><td>{esc(self._friendly_message(result.skipped_reason))}</td><td>{esc(result.error or '')}</td><td>{esc(result.duration_ms)}</td></tr>")
                body.append("</table></div>")
            body.append("</section>")
        elif output_name == "evidence_report.html":
            body.append("<section><h2>Resumen Global</h2><div class='grid'>")
            for label, value in (("Puntaje de Salud", summary.get("score")), ("Estado Global", badge(str(summary.get("global_status")))), ("Total de validaciones", summary.get("total_checks")), ("PASS", summary.get("PASS")), ("INFO", summary.get("INFO")), ("WARNING", summary.get("WARNING")), ("FAIL", summary.get("FAIL")), ("CRITICAL", summary.get("CRITICAL")), ("ERROR", summary.get("ERROR")), ("SKIPPED", summary.get("SKIPPED"))):
                body.append(f"<div class='card'><span>{label}</span><strong>{value}</strong></div>")
            body.append("</div></section><section><h2>Inventario Técnico</h2><h3>Inventario de Base de Datos</h3><div class='grid'>")
            for item in database_inventory_items:
                body.append(f"<div class='card'><span>{esc(item['label'])}</span><strong>{esc(item['value'])}</strong><small>{esc(item['technical_name'])}</small></div>")
            body.append("</div></section><section><h2>Evidencias por grupo funcional</h2><p>Las evidencias se muestran colapsadas por defecto para facilitar la navegación. Despliegue cada validación para ver el JSON completo de evidencia asociado al resultado.</p>")
            for group_id, group_results in grouped_results.items():
                body.append(f"<h3>{esc(self._group_label(group_id))} <small>{esc(group_id)}</small> ({len(group_results)} validación(es))</h3>")
                for result in group_results:
                    msg = self._friendly_message(result.message or result.skipped_reason or result.error)
                    body.append(f"<details class='evidence-item'><summary>{badge(result.status.value)} <strong>{esc(result.check_id)}</strong> <span>{esc(self._check_title(result.title))}</span> <small>{esc(msg)}</small></summary><div class='evidence-meta'><div><span>Grupo</span><strong>{esc(self._group_label(result.group_id))}</strong></div><div><span>group_id</span><strong>{esc(result.group_id)}</strong></div><div><span>Severidad</span><strong>{esc(self._status_label(result.failure_severity))}</strong></div><div><span>Duración</span><strong>{esc(result.duration_ms)} ms</strong></div></div>")
                    if result.skipped_reason:
                        body.append(f"<p><strong>skipped_reason:</strong> {esc(self._friendly_message(result.skipped_reason))}</p>")
                    if result.error:
                        body.append(f"<p><strong>error:</strong> {esc(result.error)}</p>")
                    body.append("<h4>Evidencia completa</h4>")
                    if result.evidence is None:
                        body.append("<div class='no-evidence'>No hay evidencia estructurada para esta validación.</div>")
                    else:
                        body.append(f"<pre class='json-block'>{esc(self._pretty_json(result.evidence))}</pre>")
                    body.append("</details>")
            body.append("</section>")
        else:
            body.append("<section><h2>Resumen de Estados</h2><div class='grid'>")
            for label, value in (("Puntaje de Salud", summary.get("score")), ("Estado Global", badge(str(summary.get("global_status")))), ("WARNING", summary.get("WARNING")), ("FAIL", summary.get("FAIL")), ("CRITICAL", summary.get("CRITICAL")), ("ERROR", summary.get("ERROR"))):
                body.append(f"<div class='card'><span>{label}</span><strong>{value}</strong></div>")
            body.append("</div></section><section><h2>Acciones correctivas</h2>")
            if corrective_actions:
                for owner, owner_results in corrective_actions.items():
                    body.append(f"<h3>Responsable: {esc(owner)}</h3>")
                    for result in owner_results:
                        body.append(f"<article><p>{badge(result.status.value)} <strong>Severidad:</strong> {esc(self._status_label(result.failure_severity))} <strong>Validación afectada:</strong> {esc(result.check_id)} <strong>Requiere ventana:</strong> {esc(result.remediation.get('requires_window', False))} <strong>Riesgo de indisponibilidad:</strong> {esc(result.remediation.get('outage_risk', 'desconocido'))}</p><h4>{esc(self._check_title(result.title))}</h4><p><strong>Resumen del problema:</strong> {esc(result.remediation.get('summary') or result.message or result.error)}</p><strong>Acciones recomendadas:</strong><ul>")
                        actions = result.remediation.get("actions") or ["Revisar la evidencia y definir un plan de remediación con el responsable."]
                        for action in actions:
                            body.append(f"<li>{esc(action)}</li>")
                        body.append(f"</ul><p><strong>Evidencia resumida:</strong> {esc(self._friendly_message(result.message or result.error or result.skipped_reason))}</p></article>")
            else:
                body.append("<div class='positive'><strong>No se requieren acciones correctivas.</strong> No se detectaron validaciones FAIL, CRITICAL, WARNING o ERROR.</div>")
            body.append("</section>")
        body.append("</div></body></html>")
        return "".join(body)
