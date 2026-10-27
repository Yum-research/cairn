from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from typing import Any

from . import __version__
from .config import APP_NAME
from .db import Database

_BASE_CSS = """
:root{color-scheme:light;--ink:#17201d;--muted:#5c6b65;--line:#dbe3de;--paper:#fff;--wash:#f4f7f5;--amber:#a96512;--teal:#176b5b;--red:#a12d2d;}
*{box-sizing:border-box}body{margin:0;background:var(--wash);color:var(--ink);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
.page{max-width:1080px;margin:0 auto;padding:48px 28px 80px}.brand{display:flex;align-items:center;gap:12px;margin-bottom:30px}
.mark{width:34px;height:34px}.brand b{font-size:18px;letter-spacing:.08em}.brand span{color:var(--muted);font-size:12px;letter-spacing:.12em;text-transform:uppercase}
h1{font-size:34px;line-height:1.15;margin:0 0 8px;letter-spacing:-.02em}h2{font-size:20px;margin:34px 0 12px}h3{font-size:16px;margin:18px 0 8px}
.sub{color:var(--muted);font-size:14px}.card{background:var(--paper);border:1px solid var(--line);border-radius:14px;padding:20px;margin:14px 0}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}.meta div{background:var(--wash);padding:12px;border-radius:10px}
.meta dt{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}.meta dd{margin:4px 0 0;font-weight:600}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px}.stat{background:var(--wash);border-radius:10px;padding:14px}
.stat b{display:block;font-size:25px;letter-spacing:-.02em}.stat span{color:var(--muted);font-size:12px}
table{width:100%;border-collapse:collapse;font-size:13.5px}th{text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid var(--line);padding:9px 8px}
td{padding:11px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.pill{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700;letter-spacing:.03em}
.sev-critical{background:#fbe9e9;color:#8d1f1f}.sev-high{background:#fdf0e5;color:#9b4a12}.sev-medium{background:#fbf6df;color:#7b630f}.sev-low{background:#eaf1ee;color:#40544c}.sev-info{background:#eef1f5;color:#4c596b}
.conf{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-weight:700}
.finding{border-left:3px solid var(--line);padding:4px 0 4px 16px;margin:18px 0}.finding.high{border-color:#c56b20}.finding.critical{border-color:#a12d2d}.finding.medium{border-color:#b59a2e}.finding.low{border-color:#50796c}
pre{background:#1b2421;color:#e8efeb;padding:14px;border-radius:10px;overflow:auto;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word}
details{margin:8px 0}summary{cursor:pointer;color:var(--teal);font-weight:600;font-size:13px}
.bar{height:5px;background:#e7ece9;border-radius:99px;overflow:hidden;margin-top:5px}.bar i{display:block;height:100%;background:var(--teal)}
.note{border-left:3px solid var(--amber);background:#fdf8ef;padding:12px 16px;border-radius:0 8px 8px 0;color:#5f4a25;font-size:13px}
ul.why{margin:6px 0 0;padding-left:18px;color:var(--muted);font-size:12.5px}
.footer{margin-top:50px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:11.5px}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.92em}
@media print{body{background:#fff}.page{padding:0}.card{break-inside:avoid}details{display:block}details>summary{display:none}}
"""


def _scope_lines(engagement: dict[str, Any]) -> list[str]:
    return [
        f"{rule['mode']} {rule['kind']} {rule['value']}"
        + (" (subdomains)" if rule.get("include_subdomains") else "")
        for rule in engagement.get("scope", [])
    ]


def _explain_lines(explain: list[dict[str, Any]]) -> list[str]:
    return [
        f"{item.get('label', item.get('feature'))}: {item.get('direction')} "
        f"({item.get('contribution'):+.2f} from value {item.get('value')})"
        for item in explain[:5]
    ]


def build_report(db: Database, run_id: str) -> dict[str, Any]:
    run = db.get_run(run_id)
    if not run:
        raise KeyError(f"Unknown run: {run_id}")
    engagement = run["engagement"]
    findings = db.findings_for_run(run_id)
    for finding in findings:
        finding["evidence_records"] = db.get_evidence_many(finding.get("evidence_ids", [])[:8])
    audit_ok, audit_count, audit_bad = db.verify_audit(engagement["id"])
    evidence_ok, evidence_count, evidence_bad = db.verify_evidence(engagement["id"])
    previous = db.latest_previous_run(engagement["id"], run["id"])
    delta = None
    if previous:
        current = db.fingerprints_for_run(run_id)
        before = db.fingerprints_for_run(previous["id"])
        delta = {
            "new": len(current - before),
            "resolved": len(before - current),
            "persistent": len(current & before),
            "previous_run_id": previous["id"],
        }
    severity = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        if finding.get("status") in ("false_positive", "duplicate"):
            continue
        severity[finding["severity"]] += 1
    return {
        "generator": f"{APP_NAME} {__version__}",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "run": {
            "id": run["id"],
            "mode": run["mode"],
            "status": run["status"],
            "started_at": run.get("started_at"),
            "finished_at": run.get("finished_at"),
            "coverage": run.get("coverage", 0),
            "stats": run.get("stats", {}),
            "error": run.get("error"),
        },
        "engagement": {
            "id": engagement["id"],
            "name": engagement["name"],
            "client": engagement.get("client"),
            "authorized_by": engagement["authorized_by"],
            "authorization_ref": engagement["authorization_ref"],
            "starts_at": engagement["starts_at"],
            "expires_at": engagement["expires_at"],
            "manifest_hash": engagement["manifest_hash"],
            "scope": _scope_lines(engagement),
        },
        "severity": severity,
        "findings": findings,
        "delta": delta,
        "integrity": {
            "audit_chain_valid": audit_ok,
            "audit_events": audit_count,
            "audit_failure_id": audit_bad,
            "evidence_chain_valid": evidence_ok,
            "evidence_records": evidence_count,
            "evidence_failure_id": evidence_bad,
        },
        "method": {
            "principles": [
                "Scope is explicit, expiring, and enforced per connection.",
                "Findings require redacted evidence; secret values are never persisted.",
                "Confidence is a calibrated probability that the finding is valid, separate from severity.",
                "Coverage states what was attempted; it is not a proof of safety.",
                "No authentication attempts, exploitation, or destructive actions are performed.",
            ],
            "limitations": [
                "TCP connect scanning can misclassify filtered ports as closed depending on the network stack.",
                "Technology and service identification are heuristic and may be incomplete.",
                "The confidence model is only as good as the analyst feedback in this local database.",
                "Passive DNS/certificate transparency results depend on third-party coverage and availability.",
            ],
        },
    }


def render_json(db: Database, run_id: str) -> str:
    return json.dumps(build_report(db, run_id), indent=2, default=str)


def render_markdown(db: Database, run_id: str) -> str:
    report = build_report(db, run_id)
    engagement = report["engagement"]
    lines = [
        f"# Cairn assessment report — {engagement['name']}",
        "",
        f"**Run:** `{report['run']['id']}` · **Mode:** {report['run']['mode']} · "
        f"**Status:** {report['run']['status']} · **Coverage:** {report['run']['coverage'] * 100:.1f}%",
        "",
        "## Authorization",
        "",
        f"- Authorized by: **{engagement['authorized_by']}**",
        f"- Reference: `{engagement['authorization_ref']}`",
        f"- Window: {engagement['starts_at']} → {engagement['expires_at']}",
        f"- Manifest hash: `{engagement['manifest_hash']}`",
        "",
        "Scope:",
        *(f"- {rule}" for rule in engagement["scope"]),
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
        *(f"| {sev.title()} | {count} |" for sev, count in report["severity"].items()),
        "",
        "Confidence model: see the evidence and feature contributions for each finding.",
        "",
    ]
    delta = report.get("delta")
    if delta:
        lines += [
            "## Exposure delta",
            "",
            f"- New since previous run: **{delta['new']}**",
            f"- No longer observed: **{delta['resolved']}**",
            f"- Persistent: **{delta['persistent']}**",
            "",
        ]
    lines += ["## Findings", ""]
    if not report["findings"]:
        lines.append("No findings were recorded in this run. This does not prove the surface is secure; see coverage.")
    for finding in report["findings"]:
        lines += [
            f"### [{finding['severity'].upper()}] {finding['title']}",
            "",
            f"- Asset: `{finding.get('asset_value') or 'unknown'}`",
            f"- Detector: `{finding['detector']}`",
            f"- Confidence: **{finding['run_confidence']:.3f}** ({finding['confidence_band']})",
            f"- Status: {finding['status']}",
            f"- Occurrences: {finding['occurrences']} · First seen {finding['first_seen']}",
            "",
            finding["description"],
            "",
            f"**Remediation:** {finding['remediation']}",
            "",
        ]
        why = _explain_lines(finding.get("explain", []))
        if why:
            lines += ["**Why this confidence:**", *(f"- {item}" for item in why), ""]
        for evidence in finding.get("evidence_records", []):
            lines += [
                f"<details><summary>Evidence {evidence['id']} · {evidence['kind']} · `{evidence['locator']}`</summary>",
                "",
                "```",
                evidence["excerpt"],
                "```",
                "",
                "</details>",
                "",
            ]
    lines += [
        "## Coverage and limitations",
        "",
        f"Coverage score: **{report['run']['coverage'] * 100:.1f}%**. "
        "This measures completed planned probes, not the absence of weaknesses.",
        "",
        *(f"- {item}" for item in report["method"]["limitations"]),
        "",
        "## Integrity",
        "",
        f"- Audit hash chain: {'verified' if report['integrity']['audit_chain_valid'] else 'FAILED'} "
        f"({report['integrity']['audit_events']} events)",
        f"- Evidence hash chain: {'verified' if report['integrity']['evidence_chain_valid'] else 'FAILED'} "
        f"({report['integrity']['evidence_records']} records)",
        "",
        f"Generated by {report['generator']} at {report['generated_at']}.",
        "",
    ]
    return "\n".join(lines)


def render_html(db: Database, run_id: str) -> str:
    report = build_report(db, run_id)
    engagement = report["engagement"]
    severity = report["severity"]
    delta = report.get("delta")
    esc = html.escape
    findings_html: list[str] = []
    for finding in report["findings"]:
        sev = finding["severity"]
        evidence_html = ""
        for evidence in finding.get("evidence_records", []):
            evidence_html += (
                "<details><summary>Evidence "
                f"{esc(evidence['id'])} · {esc(evidence['kind'])} · {esc(evidence['locator'])}</summary>"
                f"<pre>{esc(evidence['excerpt'])}</pre></details>"
            )
        why = "".join(f"<li>{esc(item)}</li>" for item in _explain_lines(finding.get("explain", [])))
        findings_html.append(
            f'<section class="finding {esc(sev)}">'
            f'<div><span class="pill sev-{esc(sev)}">{esc(sev.upper())}</span> '
            f'<span class="conf">{finding["run_confidence"]:.3f}</span> '
            f'<span class="sub">{esc(finding["confidence_band"])} confidence</span></div>'
            f"<h3>{esc(finding['title'])}</h3>"
            f'<p class="sub"><code>{esc(finding.get("asset_value") or "unknown")}</code> · '
            f'detector <code>{esc(finding["detector"])}</code> · status {esc(finding["status"])}</p>'
            f"<p>{esc(finding['description'])}</p>"
            f"<p><b>Remediation.</b> {esc(finding['remediation'])}</p>"
            f'<details><summary>Why {finding["run_confidence"]:.2f}?</summary><ul class="why">{why}</ul></details>'
            f"{evidence_html}</section>"
        )
    if not findings_html:
        findings_html.append("<p>No findings were recorded in this run. This does not prove the surface is secure.</p>")
    scope_items = "".join(f"<li>{esc(rule)}</li>" for rule in engagement["scope"])
    delta_html = ""
    if delta:
        delta_html = (
            '<div class="card"><h2>Exposure delta</h2><div class="stats">'
            f'<div class="stat"><b>{delta["new"]}</b><span>new since previous run</span></div>'
            f'<div class="stat"><b>{delta["resolved"]}</b><span>no longer observed</span></div>'
            f'<div class="stat"><b>{delta["persistent"]}</b><span>persistent</span></div>'
            "</div></div>"
        )
    limitations = "".join(f"<li>{esc(item)}</li>" for item in report["method"]["limitations"])
    principles = "".join(f"<li>{esc(item)}</li>" for item in report["method"]["principles"])
    integrity = report["integrity"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cairn report — {esc(engagement['name'])}</title><style>{_BASE_CSS}</style></head>
<body><div class="page">
<div class="brand"><svg class="mark" viewBox="0 0 48 48" aria-hidden="true"><path d="M24 4 38 18 24 32 10 18Z" fill="#176b5b"/><path d="M24 18 36 30 24 42 12 30Z" fill="#a96512" opacity=".9"/></svg>
<div><b>CAIRN</b><br><span>Evidence-first surface intelligence</span></div></div>
<h1>{esc(engagement['name'])}</h1>
<p class="sub">Authorized assessment report · Run <code>{esc(report['run']['id'])}</code> · {esc(report['run']['mode'])} mode · Generated {esc(report['generated_at'])}</p>
<div class="card"><div class="stats">
<div class="stat"><b>{severity['critical']}</b><span>critical</span></div>
<div class="stat"><b>{severity['high']}</b><span>high</span></div>
<div class="stat"><b>{severity['medium']}</b><span>medium</span></div>
<div class="stat"><b>{severity['low']}</b><span>low</span></div>
<div class="stat"><b>{severity['info']}</b><span>info</span></div>
<div class="stat"><b>{report['run']['coverage'] * 100:.0f}%</b><span>probe coverage</span></div>
</div></div>
<div class="card"><h2>Authorization</h2><div class="meta">
<div><dt>Authorized by</dt><dd>{esc(engagement['authorized_by'])}</dd></div>
<div><dt>Reference</dt><dd>{esc(engagement['authorization_ref'])}</dd></div>
<div><dt>Window</dt><dd>{esc(engagement['starts_at'])}<br>{esc(engagement['expires_at'])}</dd></div>
<div><dt>Manifest SHA-256</dt><dd style="word-break:break-all;font-size:11px">{esc(engagement['manifest_hash'])}</dd></div>
</div><h3>Scope</h3><ul>{scope_items}</ul></div>
{delta_html}
<h2>Findings</h2>
{''.join(findings_html)}
<div class="card"><h2>Method and limitations</h2><ul>{principles}</ul><ul>{limitations}</ul>
<div class="note">Confidence is the calibrated probability that a finding is valid, not its business severity. Coverage is the weighted success of planned probes. A clean run is not a proof of security.</div></div>
<div class="card"><h2>Integrity</h2><div class="stats">
<div class="stat"><b>{'Verified' if integrity['audit_chain_valid'] else 'FAILED'}</b><span>audit chain ({integrity['audit_events']} events)</span></div>
<div class="stat"><b>{'Verified' if integrity['evidence_chain_valid'] else 'FAILED'}</b><span>evidence chain ({integrity['evidence_records']} records)</span></div>
</div></div>
<div class="footer">Generated by {esc(report['generator'])}. Evidence excerpts are redacted; secret values are not stored. This report is confidential to the engagement owner.</div>
</div></body></html>"""
