from pathlib import Path
from typing import Any
import html
import json

from orahealthcheck.models import Inventory, Result, Target
from orahealthcheck.utils.masking import mask_secrets


class HTMLReporter:
    def __init__(self, template_dir: Path) -> None:
        self.template_dir = template_dir
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape  # type: ignore
        except ImportError:  # pragma: no cover - fallback for minimal environments
            self.env = None
        else:
            self.env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=select_autoescape(["html", "xml"]))

    def generate(self, output_dir: Path, target: Target, inventory: Inventory, results: list[Result], summary: dict[str, Any]) -> None:
        context = {
            "target": target,
            "inventory": mask_secrets(inventory.to_dict()),
            "results": results,
            "summary": summary,
            "findings": [r for r in results if r.status.value in {"WARNING", "FAIL", "CRITICAL", "ERROR"}],
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

    def _fallback_render(self, output_name: str, target: Target, inventory: dict[str, Any], results: list[Result], summary: dict[str, Any], findings: list[Result]) -> str:
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
