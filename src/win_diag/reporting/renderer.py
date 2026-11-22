from __future__ import annotations

import json
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from win_diag.agent.schemas import AuditRunResult
from win_diag.privacy.vault import PrivacyVault

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _format_json_pretty(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def render_html_report(
    result: AuditRunResult,
    *,
    vault: PrivacyVault,
    reports_dir: Path,
    keep_anonymized: bool = False,
    open_in_browser: bool = True,
) -> Path:
    """Renderuje samowystarczalny raport HTML i zapisuje go lokalnie w katalogu reports/."""
    reports_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    def _fmt(text: Any) -> str:
        raw = "" if text is None else str(text)
        return raw if keep_anonymized else vault.deanonymize(raw)

    env.filters["fmt"] = _fmt
    env.filters["to_pretty_json"] = _format_json_pretty

    template = env.get_template("report.html.j2")

    total_prompt = sum(u.prompt_tokens for u in result.usage_by_tier.values())
    total_completion = sum(u.completion_tokens for u in result.usage_by_tier.values())
    total_tokens = sum(u.total_tokens for u in result.usage_by_tier.values())

    html_content = template.render(
        result=result,
        diag=result.final_diagnosis,
        tier1=result.tier1_diagnosis,
        keep_anonymized=keep_anonymized,
        vault_stats=vault.stats(),
        generated_local=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_usage={
            "prompt": total_prompt,
            "completion": total_completion,
            "total": total_tokens,
        },
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = "_anon" if keep_anonymized else ""
    report_path = (reports_dir / f"diag_{timestamp}{suffix}.html").resolve()
    report_path.write_text(html_content, encoding="utf-8")

    if open_in_browser:
        webbrowser.open(report_path.as_uri())

    return report_path