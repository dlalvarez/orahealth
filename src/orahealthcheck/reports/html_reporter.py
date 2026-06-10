from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import html
import json

from orahealthcheck.models import Inventory, Result, Target
from orahealthcheck.utils.masking import mask_secrets


STATUS_ORDER = {"CRITICAL": 0, "ERROR": 1, "FAIL": 2, "WARNING": 3, "INFO": 4, "PASS": 5, "SKIPPED": 6}
ACTION_STATUSES = {"FAIL", "CRITICAL", "WARNING", "ERROR"}
ALL_STATUSES = ("PASS", "INFO", "WARNING", "FAIL", "CRITICAL", "ERROR", "SKIPPED")
OWNER_ORDER = ("DBA", "OS", "Security", "Application", "Other")


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

    def generate(self, output_dir: Path, target: Target, inventory: Inventory, results: list[Result], summary: dict[str, Any]) -> None:
        findings = self._sort_results([r for r in results if r.status.value in ACTION_STATUSES])
        grouped_results = self._group_results(results)
        corrective_actions = self._group_corrective_actions(findings)
        context = {
            "target": target,
            "inventory": mask_secrets(inventory.to_dict()),
            "results": self._sort_results(results),
            "grouped_results": grouped_results,
            "summary": self._summary_with_defaults(summary, results),
            "findings": findings,
            "corrective_actions": corrective_actions,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
        mapping = {
            "executive_report.html.j2": "executive_report.html",
            "technical_report.html.j2": "technical_report.html",
            "corrective_actions.html.j2": "corrective_actions.html",
        }
        for template_name, output_name in mapping.items():
            if self.env:
                rendered = self.env.get_template(template_name).render(**context)
            else:
                rendered = self._fallback_render(output_name, **context)
            (output_dir / output_name).write_text(rendered, encoding="utf-8")

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
            owner = str(result.remediation.get("owner") or "Other")
            if owner not in grouped:
                owner = "Other"
            grouped[owner].append(result)
        return {owner: grouped[owner] for owner in OWNER_ORDER if grouped[owner]}

    def _pretty_json(self, value: Any) -> str:
        return json.dumps(mask_secrets(value), indent=2, ensure_ascii=False, sort_keys=True)

    def _fallback_render(self, output_name: str, target: Target, inventory: dict[str, Any], results: list[Result], summary: dict[str, Any], findings: list[Result], **_: Any) -> str:
        title = output_name.replace("_", " ").replace(".html", "").title()
        body = [f"<h1>{html.escape(title)}</h1>", f"<h2>{html.escape(target.name)} ({html.escape(target.target_id)})</h2>"]
        body.append(f"<pre>{html.escape(json.dumps(summary, indent=2))}</pre>")
        if output_name == "technical_report.html":
            body.append(f"<h2>Inventory</h2><pre>{html.escape(json.dumps(inventory, indent=2))}</pre>")
            items = results
        else:
            items = findings
        for result in items:
            body.append(f"<section><h3>{html.escape(result.check_id)} - {result.status.value}</h3><p>{html.escape(result.message or result.error or result.skipped_reason or '')}</p></section>")
        return "<!doctype html><html><head><meta charset='utf-8'></head><body>" + "\n".join(body) + "</body></html>"
