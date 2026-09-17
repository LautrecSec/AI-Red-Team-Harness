from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

from .orchestrator import CampaignOutcome
from .security import redact_data, redact_text, safe_output_path


def _result_dicts(outcome: CampaignOutcome) -> list[dict[str, object]]:
    return [redact_data(result.to_dict()) for result in outcome.results]


def write_json(outcome: CampaignOutcome, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = safe_output_path(output_dir, "results.json")
    payload = {
        "campaign": redact_text(outcome.name),
        "attack_success_rate": outcome.attack_success_rate,
        "results": _result_dicts(outcome),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_sarif(outcome: CampaignOutcome, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = safe_output_path(output_dir, "results.sarif")
    sarif_results = []
    for result in outcome.results:
        if result.success:
            sarif_results.append(
                {
                    "ruleId": f"AIREDTEAM/{result.plugin}/{result.phase.value}",
                    "level": "warning" if result.severity in {"medium", "high"} else "note",
                    "message": {"text": redact_text(result.summary or "Attack condition observed")},
                    "properties": {
                        "target": redact_text(result.target),
                        "attack_id": redact_text(result.attack_id),
                    },
                }
            )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "AI Red Team Harness", "version": "1.0.0"}},
                "results": sarif_results,
            }
        ],
    }
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return path


def write_html(outcome: CampaignOutcome, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = safe_output_path(output_dir, "report.html")

    total = len(outcome.results)
    findings = sum(result.success for result in outcome.results)
    controls = total - findings
    phases = Counter(result.phase.value for result in outcome.results)
    phase_findings = Counter(result.phase.value for result in outcome.results if result.success)
    plugins = Counter(result.plugin for result in outcome.results)

    phase_rows = "".join(
        f"<div class='phase-row'><div class='phase-name'>{html.escape(phase.replace('_', ' ').title())}</div>"
        f"<div class='bar'><span style='width:{(phase_findings[phase] / count * 100) if count else 0:.1f}%'></span></div>"
        f"<div class='phase-count'>{phase_findings[phase]}/{count}</div></div>"
        for phase, count in phases.items()
    )

    plugin_pills = "".join(
        f"<span class='pill'>{html.escape(plugin)} <strong>{count}</strong></span>"
        for plugin, count in plugins.items()
    )

    rows = "\n".join(
        f"<tr><td><code>{html.escape(redact_text(r.attack_id))}</code></td>"
        f"<td>{html.escape(redact_text(r.plugin))}</td>"
        f"<td>{html.escape(r.phase.value.replace('_', ' ').title())}</td>"
        f"<td>{html.escape(redact_text(r.target))}</td>"
        f"<td><span class='status {'finding' if r.success else 'pass'}'>{'FINDING' if r.success else 'PASS'}</span></td>"
        f"<td><span class='severity {html.escape(r.severity.lower())}'>{html.escape(r.severity.upper())}</span></td>"
        f"<td>{html.escape(redact_text(r.summary))}</td></tr>"
        for r in outcome.results
    )

    campaign_name = html.escape(redact_text(outcome.name))
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{campaign_name} - AI Red Team Report</title>
<style>
:root{{--bg:#080b11;--panel:#0f141d;--panel2:#131a25;--line:#263142;--text:#eef3f8;--muted:#8d9aad;--accent:#ff4d5a;--good:#45d483;--warn:#ffb454;--blue:#62a8ff}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 20% 0%,#131c2b 0,#080b11 42%);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
.wrap{{max-width:1420px;margin:0 auto;padding:42px 46px 56px}}header{{display:flex;justify-content:space-between;gap:24px;align-items:flex-end;margin-bottom:28px}}.eyebrow{{color:var(--accent);font-size:11px;font-weight:800;letter-spacing:.18em;text-transform:uppercase}}h1{{font-size:34px;line-height:1.05;margin:7px 0 8px;letter-spacing:-.03em}}.subtitle{{color:var(--muted);font-size:14px}}.badge{{border:1px solid #334156;background:#101722;padding:8px 12px;border-radius:999px;color:#aab6c7;font-size:12px}}.grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:14px}}.card{{background:linear-gradient(180deg,rgba(19,26,37,.95),rgba(13,18,27,.96));border:1px solid var(--line);border-radius:14px;padding:20px}}.label{{color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.09em;text-transform:uppercase}}.value{{font-size:30px;font-weight:800;letter-spacing:-.04em;margin-top:4px}}.value.danger{{color:var(--accent)}}.value.good{{color:var(--good)}}.subgrid{{display:grid;grid-template-columns:1.25fr .75fr;gap:14px;margin-bottom:14px}}h2{{font-size:15px;margin:0 0 16px}}.phase-row{{display:grid;grid-template-columns:170px 1fr 46px;align-items:center;gap:14px;margin:12px 0}}.phase-name{{color:#c5cfdd;font-size:12px}}.bar{{height:8px;background:#202a38;border-radius:99px;overflow:hidden}}.bar span{{display:block;height:100%;background:linear-gradient(90deg,#ff4d5a,#ff8c63);border-radius:99px}}.phase-count{{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}}.pills{{display:flex;flex-wrap:wrap;gap:9px}}.pill{{padding:8px 11px;border:1px solid #2c394b;border-radius:9px;background:#0b1018;color:#aab7c8}}.pill strong{{color:#fff;margin-left:5px}}.table-card{{padding:0;overflow:hidden}}.table-head{{display:flex;justify-content:space-between;align-items:center;padding:18px 20px;border-bottom:1px solid var(--line)}}.table-wrap{{overflow:auto}}table{{border-collapse:collapse;width:100%;min-width:980px}}th,td{{padding:13px 16px;text-align:left;border-bottom:1px solid #1e2734;vertical-align:top}}th{{color:#7f8ca0;background:#0d121a;font-size:10px;text-transform:uppercase;letter-spacing:.08em}}td{{color:#cbd5e2;font-size:12px}}tr:last-child td{{border-bottom:0}}code{{color:#9fc8ff;font-family:"SFMono-Regular",Consolas,monospace;font-size:11px}}.status,.severity{{display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;font-size:9px;font-weight:800;letter-spacing:.08em}}.status.finding{{color:#ff8b94;background:rgba(255,77,90,.11);border:1px solid rgba(255,77,90,.3)}}.status.pass{{color:#79e5a8;background:rgba(69,212,131,.09);border:1px solid rgba(69,212,131,.27)}}.severity.medium,.severity.high,.severity.critical{{color:#ffc472;background:rgba(255,180,84,.1);border:1px solid rgba(255,180,84,.25)}}.severity.informational,.severity.low{{color:#9cc7ff;background:rgba(98,168,255,.1);border:1px solid rgba(98,168,255,.25)}}footer{{color:#59677a;font-size:11px;margin-top:18px;text-align:right}}@media(max-width:900px){{.wrap{{padding:24px}}.grid{{grid-template-columns:1fr 1fr}}.subgrid{{grid-template-columns:1fr}}header{{align-items:flex-start;flex-direction:column}}}}
</style>
</head>
<body>
<div class="wrap">
<header><div><div class="eyebrow">Normalized Security Evaluation</div><h1>AI Red Team Harness</h1><div class="subtitle">Campaign: {campaign_name}</div></div><div class="badge">Defensive testing / lab-safe reference</div></header>
<div class="grid">
  <div class="card"><div class="label">Attack Success Rate</div><div class="value danger">{outcome.attack_success_rate:.1f}%</div></div>
  <div class="card"><div class="label">Executed Tests</div><div class="value">{total}</div></div>
  <div class="card"><div class="label">Findings</div><div class="value danger">{findings}</div></div>
  <div class="card"><div class="label">Controls Held</div><div class="value good">{controls}</div></div>
</div>
<div class="subgrid">
  <section class="card"><h2>Findings by attack phase</h2>{phase_rows or '<div class="subtitle">No phase data</div>'}</section>
  <section class="card"><h2>Scanner coverage</h2><div class="pills">{plugin_pills or '<span class="subtitle">No plugin data</span>'}</div></section>
</div>
<section class="card table-card">
  <div class="table-head"><h2 style="margin:0">Normalized findings</h2><div class="subtitle">JSON + SARIF + HTML</div></div>
  <div class="table-wrap"><table><thead><tr><th>Attack</th><th>Plugin</th><th>Phase</th><th>Target</th><th>Status</th><th>Severity</th><th>Summary</th></tr></thead><tbody>{rows}</tbody></table></div>
</section>
<footer>AI Red Team Harness · generated report · secrets redacted before persistence</footer>
</div>
</body></html>"""
    path.write_text(document, encoding="utf-8")
    return path
