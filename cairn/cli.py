from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import sys
import webbrowser
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import __version__
from .config import Limits, default_db_path, parse_ports
from .db import Database
from .demo import DemoLab
from .intel.learning import learning_overview, maybe_retrain, train_confidence_model
from .models import SEVERITY_RANK, ScopeError, ScopeSpec
from .net.dns import DNSResolver
from .reporting import render_html, render_json, render_markdown
from .scope import ScopeGuard, validate_manifest, validate_scope

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
AMBER = "\033[38;5;214m"
SEV_COLORS = {
    "critical": "\033[38;5;197m",
    "high": "\033[38;5;208m",
    "medium": "\033[38;5;221m",
    "low": "\033[38;5;109m",
    "info": "\033[38;5;110m",
}


def _color(text: str, code: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"{code}{text}{RESET}"


def _db(args: argparse.Namespace) -> Database:
    path = Path(args.db).expanduser() if getattr(args, "db", None) else default_db_path()
    return Database(path)


def _duration(value: str) -> timedelta:
    value = value.strip().lower()
    try:
        if value.endswith("d"):
            return timedelta(days=float(value[:-1]))
        if value.endswith("h"):
            return timedelta(hours=float(value[:-1]))
        if value.endswith("m"):
            return timedelta(minutes=float(value[:-1]))
        return timedelta(hours=float(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Duration must look like 24h, 7d, or 90m") from exc


def _resolve_engagement(db: Database, value: str) -> dict[str, Any]:
    exact = db.get_engagement(value)
    if exact:
        return exact
    rows = db.query("SELECT id FROM engagements WHERE id LIKE ?", (value + "%",))
    if len(rows) == 1:
        found = db.get_engagement(rows[0]["id"])
        if found:
            return found
    if not rows:
        raise KeyError(f"No engagement matches {value!r}")
    raise KeyError(f"Ambiguous engagement prefix {value!r}; use more characters")


def _resolve_finding(db: Database, value: str) -> dict[str, Any]:
    exact = db.get_finding(value)
    if exact:
        return exact
    rows = db.query("SELECT id FROM findings WHERE id LIKE ?", (value + "%",))
    if len(rows) == 1:
        found = db.get_finding(rows[0]["id"])
        if found:
            return found
    if not rows:
        raise KeyError(f"No finding matches {value!r}")
    raise KeyError(f"Ambiguous finding prefix {value!r}; use more characters")


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _visible_len(value: str) -> int:
    return len(_ANSI.sub("", value))


def _fit(value: str, width: int) -> str:
    """Pad or truncate to a visible width without breaking ANSI sequences."""

    out: list[str] = []
    used = 0
    index = 0
    while index < len(value):
        if value[index] == "\x1b":
            match = _ANSI.match(value, index)
            if match:
                out.append(match.group())
                index = match.end()
                continue
        if used < width:
            out.append(value[index])
            used += 1
        index += 1
    if used < width:
        out.append(" " * (width - used))
    return "".join(out)


def _table(headers: list[str], rows: list[list[str]], widths: list[int] | None = None) -> str:
    if widths is None:
        widths = [
            max(_visible_len(headers[i]), *(_visible_len(str(row[i])) for row in rows))
            if rows
            else _visible_len(headers[i])
            for i in range(len(headers))
        ]
    lines = ["  ".join(_fit(_color(headers[i].upper(), DIM), widths[i]) for i in range(len(headers)))]
    lines.append("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        lines.append("  ".join(_fit(str(row[i]), widths[i]) for i in range(len(headers))))
    return "\n".join(lines)


def _scope_specs(args: argparse.Namespace) -> list[ScopeSpec]:
    specs: list[ScopeSpec] = []
    for value in getattr(args, "domain", []) or []:
        specs.append(ScopeSpec("domain", value, include_subdomains=bool(getattr(args, "wildcard", False))))
    for value in getattr(args, "ip", []) or []:
        specs.append(ScopeSpec("ip", value))
    for value in getattr(args, "cidr", []) or []:
        specs.append(ScopeSpec("cidr", value))
    for value in getattr(args, "url", []) or []:
        specs.append(ScopeSpec("url", value))
    for value in getattr(args, "exclude_domain", []) or []:
        specs.append(ScopeSpec("domain", value, include_subdomains=True, mode="exclude"))
    for value in getattr(args, "exclude_cidr", []) or []:
        specs.append(ScopeSpec("cidr", value, mode="exclude"))
    for value in getattr(args, "exclude_url", []) or []:
        specs.append(ScopeSpec("url", value, mode="exclude"))
    return specs


# --------------------------------------------------------------------------- commands
def cmd_init(args: argparse.Namespace) -> int:
    db = _db(args)
    print(_color("Cairn initialized", GREEN), f"at {db.path}")
    print("Next: cairn engagement create --help")
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"Cairn {__version__}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    db = _db(args)
    print(_color("CAIRN / doctor", BOLD))
    print(f"Version:        {__version__}")
    print(f"Python:         {sys.version.split()[0]}")
    print(f"Database:       {db.path}")
    print(f"SQLite:         {db.one('SELECT sqlite_version() AS v')['v']}")  # type: ignore[index]
    print(f"Engagements:    {db.one('SELECT COUNT(*) AS n FROM engagements')['n']}")  # type: ignore[index]
    print(f"Findings:       {db.one('SELECT COUNT(*) AS n FROM findings')['n']}")  # type: ignore[index]
    tools = ["nmap", "nuclei", "httpx", "subfinder", "masscan", "naabu"]
    print("\nOptional adapters discovered on PATH:")
    found = False
    for tool in tools:
        path = shutil.which(tool)
        if path:
            found = True
            print(f"  {tool:12} {path}")
    if not found:
        print("  none (Cairn's native engine does not require them)")
    print("\nSafety posture:")
    print("  - local-only UI, token-authenticated API")
    print("  - explicit, expiring, hashed scope manifests")
    print("  - no authentication attempts, exploitation, or destructive actions")
    return 0


def cmd_engagement_create(args: argparse.Namespace) -> int:
    db = _db(args)
    try:
        scope = validate_scope(_scope_specs(args))
        ports = parse_ports(args.ports or None, all_ports=args.all_ports)
    except (ScopeError, ValueError) as exc:
        print(_color(f"error: {exc}", RED), file=sys.stderr)
        return 2
    now = datetime.now(UTC)
    try:
        expires = now + _duration(args.expires)
    except argparse.ArgumentTypeError as exc:
        print(_color(f"error: {exc}", RED), file=sys.stderr)
        return 2
    limits = Limits(
        http_rate=args.http_rate,
        port_rate=args.port_rate,
        timeout=args.timeout,
        max_hosts=args.max_hosts,
        allowed_ports=ports,
        full_ports=args.all_ports,
    )
    try:
        validate_manifest(
            authorized_by=args.authorized_by,
            authorization_ref=args.auth_ref,
            starts_at=now.isoformat(timespec="seconds"),
            expires_at=expires.isoformat(timespec="seconds"),
            scope=scope,
        )
    except ScopeError as exc:
        print(_color(f"error: {exc}", RED), file=sys.stderr)
        return 2
    engagement_id = db.create_engagement(
        name=args.name,
        client=args.client,
        authorized_by=args.authorized_by,
        authorization_ref=args.auth_ref,
        starts_at=now.isoformat(timespec="seconds"),
        expires_at=expires.isoformat(timespec="seconds"),
        scope=scope,
        limits=limits.to_dict(),
        notes=args.notes,
        actor=args.authorized_by,
    )
    engagement = db.get_engagement(engagement_id)
    assert engagement is not None
    print(_color("Engagement created", GREEN))
    print(f"  id:             {engagement_id}")
    print(f"  manifest hash:  {engagement['manifest_hash']}")
    print(f"  authorized by:  {engagement['authorized_by']} ({engagement['authorization_ref']})")
    print(f"  expires:        {engagement['expires_at']}")
    print("  scope:")
    for rule in engagement["scope"]:
        suffix = " (subdomains)" if rule.get("include_subdomains") else ""
        print(f"    {rule['mode']:7} {rule['kind']:6} {rule['value']}{suffix}")
    port_text = "all 65,535" if args.all_ports else f"{len(ports)} allowed"
    print(f"  ports:          {port_text}")
    print("\nScope is a contract, not a suggestion. Every target connection is checked against this manifest.")
    print(f"Next: {_color('cairn scan --engagement ' + engagement_id + ' --mode standard', CYAN)}")
    return 0


def cmd_engagement_list(args: argparse.Namespace) -> int:
    db = _db(args)
    rows = db.list_engagements()
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return 0
    if not rows:
        print("No engagements yet. Create one with: cairn engagement create --help")
        return 0
    table_rows = []
    for row in rows:
        state = row["status"]
        if state == "active":
            state = _color(state, GREEN)
        table_rows.append(
            [
                row["id"][:14],
                row["name"][:34],
                state,
                row["expires_at"][:19],
                str(row["run_count"]),
                str(row["open_findings"]),
            ]
        )
    print(_table(["id", "name", "status", "expires", "runs", "open findings"], table_rows))
    return 0


def cmd_engagement_show(args: argparse.Namespace) -> int:
    db = _db(args)
    engagement = _resolve_engagement(db, args.engagement)
    if args.json:
        print(json.dumps(engagement, indent=2, default=str))
        return 0
    print(_color(engagement["name"], BOLD), f"({engagement['id']})")
    print(f"Client:         {engagement['client'] or '—'}")
    print(f"Authorized by:  {engagement['authorized_by']} · {engagement['authorization_ref']}")
    print(f"Window:         {engagement['starts_at']} → {engagement['expires_at']}")
    print(f"Status:         {engagement['status']}")
    print(f"Manifest hash:  {engagement['manifest_hash']}")
    print("Scope:")
    for rule in engagement["scope"]:
        suffix = " (subdomains)" if rule.get("include_subdomains") else ""
        print(f"  {rule['mode']:7} {rule['kind']:6} {rule['value']}{suffix}")
    return 0


def cmd_engagement_revoke(args: argparse.Namespace) -> int:
    db = _db(args)
    engagement = _resolve_engagement(db, args.engagement)
    if not args.yes:
        print("Add --yes to revoke this engagement immediately.")
        return 2
    db.set_engagement_status(engagement["id"], "revoked", actor=args.analyst)
    print(_color(f"Engagement {engagement['id']} revoked.", YELLOW))
    return 0


def _print_scan_summary(db: Database, engagement: dict[str, Any], run_id: str, stats: dict[str, Any]) -> None:
    run = db.get_run(run_id)
    assert run is not None
    print()
    print(_color("Scan complete", GREEN), f"· {run_id}")
    print(f"  status:      {run['status']}")
    print(f"  coverage:    {run['coverage'] * 100:.1f}%")
    print(f"  new:         {stats.get('findings_new', 0)} findings")
    print(f"  updated:     {stats.get('findings_updated', 0)} findings")
    print(f"  evidence:    {stats.get('evidence', 0)} records")
    print(f"  assets:      {stats.get('assets', 0)}")
    print(f"  http:        {stats.get('http_requests', 0)} requests")
    print(f"  duration:    {stats.get('duration_s', 0)}s")
    findings = db.list_findings(engagement["id"], run_id=run_id, limit=12)
    if findings:
        print("\nTop findings:")
        for finding in findings[:8]:
            sev = _color(finding["severity"].upper().ljust(8), SEV_COLORS.get(finding["severity"], ""))
            print(f"  {sev} {finding['confidence']:.3f}  {finding['title']}  {DIM}· {finding['asset_value']}{RESET}")
    print(f"\nReview: {_color('cairn serve', CYAN)}   Report: {_color(f'cairn report --run {run_id}', CYAN)}")


def _run_scan(db: Database, engagement: dict[str, Any], args: argparse.Namespace) -> int:
    config = {
        "online_intel": not args.no_online_intel,
        "active_dns": not args.no_active_dns,
        "source": "cli",
    }
    run_id = db.create_run(engagement["id"], args.mode, config)
    print(f"Run {run_id} queued · mode {args.mode} · engagement {engagement['id']}")
    if args.mode == "passive":
        print("Passive mode: DNS and third-party OSINT only; no packets to target services.")
    print(_color("Scanning under the engagement's expiring scope manifest…", DIM))
    try:
        from .engine.orchestrator import execute_run

        stats = asyncio.run(execute_run(db, run_id))
    except KeyboardInterrupt:
        db.finish_run(run_id, status="cancelled", error="Interrupted by operator")
        db.add_audit(
            engagement["id"], action="run.cancelled", target=run_id, decision="cancelled", details={"reason": "SIGINT"}
        )
        print(_color("\nInterrupted. Run marked cancelled.", YELLOW))
        return 130
    except Exception as exc:
        print(_color(f"Scan failed: {exc}", RED), file=sys.stderr)
        return 1
    if args.json:
        run = db.get_run(run_id)
        print(json.dumps({"run": run, "stats": stats}, indent=2, default=str))
    else:
        _print_scan_summary(db, engagement, run_id, stats)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    db = _db(args)
    engagement = _resolve_engagement(db, args.engagement)
    if engagement["status"] != "active":
        print(_color(f"error: engagement is {engagement['status']}, not active", RED), file=sys.stderr)
        return 2
    return _run_scan(db, engagement, args)


def cmd_findings_list(args: argparse.Namespace) -> int:
    db = _db(args)
    engagement = _resolve_engagement(db, args.engagement)
    findings = db.list_findings(
        engagement["id"],
        min_severity=args.min_severity,
        status=args.status,
        band=args.band,
        run_id=args.run,
        query_text=args.search,
    )
    if args.min_confidence is not None:
        findings = [f for f in findings if f["confidence"] >= args.min_confidence]
    if args.json:
        print(json.dumps(findings, indent=2, default=str))
        return 0
    if not findings:
        print("No matching findings.")
        return 0
    rows = []
    for finding in findings:
        rows.append(
            [
                finding["id"][:14],
                _color(finding["severity"].upper()[:8].ljust(8), SEV_COLORS.get(finding["severity"], "")),
                f"{finding['confidence']:.3f}",
                finding["detector"][:28],
                finding["title"][:52],
                (finding["asset_value"] or "—")[:40],
                finding["status"],
            ]
        )
    print(_table(["id", "severity", "conf", "detector", "title", "asset", "status"], rows))
    print(f"\n{len(findings)} finding(s). Use `cairn finding show <id>` for evidence.")
    return 0


def cmd_finding_show(args: argparse.Namespace) -> int:
    db = _db(args)
    finding = _resolve_finding(db, args.finding)
    if args.json:
        print(json.dumps(finding, indent=2, default=str))
        return 0
    sev = _color(finding["severity"].upper(), SEV_COLORS.get(finding["severity"], ""))
    print(f"{sev}  {_color(finding['title'], BOLD)}")
    print(f"  id:          {finding['id']}")
    print(f"  asset:       {finding.get('asset_value') or '—'}")
    print(f"  detector:    {finding['detector']}")
    print(f"  confidence:  {finding['confidence']:.3f} ({finding['confidence_band']}) · model {finding.get('model_version') or 'heuristic'}")
    print(f"  status:      {finding['status']} · occurrences {finding['occurrences']}")
    print(f"  first/last:  {finding['first_seen']} / {finding['last_seen']}")
    print(f"\n{finding['description']}")
    print(f"\n{_color('Remediation', BOLD)}: {finding['remediation']}")
    if finding.get("explain"):
        print(f"\n{_color('Why this confidence', BOLD)}")
        for item in finding["explain"]:
            print(f"  {item['label']:26} {item['contribution']:+.3f}  (value {item['value']})")
    if finding.get("evidence"):
        print(f"\n{_color('Evidence', BOLD)}")
        for evidence in finding["evidence"][:6]:
            print(f"\n  [{evidence['kind']}] {evidence['locator']}")
            print("  " + evidence["excerpt"].replace("\n", "\n  ")[:1800])
    if finding.get("feedback"):
        print(f"\n{_color('Feedback', BOLD)}")
        for item in finding["feedback"]:
            print(f"  {item['created_at']}  {item['verdict']:14} {item['analyst']}: {item['note']}")
    print(f"\nFeedback: cairn feedback {finding['id']} --verdict confirmed|false_positive|accepted_risk")
    return 0


def cmd_feedback(args: argparse.Namespace) -> int:
    db = _db(args)
    finding = _resolve_finding(db, args.finding)
    analyst = args.analyst or os.environ.get("USERNAME") or os.environ.get("USER") or "local-analyst"
    db.add_feedback(finding["id"], args.verdict, analyst, args.note)
    print(_color(f"Feedback recorded: {args.verdict}", GREEN), f"for {finding['id']}")
    if args.verdict in ("confirmed", "false_positive", "accepted_risk") and not args.no_retrain:
        result = maybe_retrain(db)
        if result:
            print(f"Learning: {result['status']} · model {result.get('model_id')} · Brier {result.get('metrics', {}).get('brier')}")
        else:
            print(_color("Learning: waiting for enough new labels to evaluate a challenger.", DIM))
    return 0


def cmd_learn_stats(args: argparse.Namespace) -> int:
    db = _db(args)
    overview = learning_overview(db)
    champion = overview["champion"]
    print(_color("CAIRN / learning", BOLD))
    print(f"Human labels:      {overview['human_labels']}")
    print(f"Feedback:          {overview['feedback_counts']}")
    if champion:
        metrics = champion["metrics"]
        print(f"Champion model:    #{champion['id']} · Brier {metrics.get('brier')} · ECE {metrics.get('ece')} · "
              f"accuracy {metrics.get('accuracy')} · n={metrics.get('n_eval')}")
    else:
        print("Champion model:    heuristic (not enough feedback yet)")
    print(f"Next promotion:    {overview['next_promotion_at']} labels / improvement threshold")
    print("\nDetector reliability from feedback:")
    if overview["detectors"]:
        print(_table(
            ["detector", "labels", "confirmed", "rate"],
            [[d["detector"], str(d["labels"]), str(d["confirmed"]), f"{d['rate']:.2f}"] for d in overview["detectors"][:12]],
        ))
    else:
        print("  No labeled findings yet.")
    print("\nActive learning queue (0.30–0.70 confidence):")
    if overview["active_learning"]:
        print(_table(
            ["id", "severity", "conf", "detector", "title"],
            [[f["id"][:14], f["severity"], f"{f['confidence']:.3f}", f["detector"][:26], f["title"][:50]] for f in overview["active_learning"]],
        ))
    else:
        print("  Empty.")
    print("\nAdaptive path yield:")
    if overview["paths"]:
        print(_table(
            ["path", "trials", "hits", "yield"],
            [[p["path"], str(p["trials"]), str(p["successes"]), f"{p['successes'] / max(1, p['trials']):.2f}"] for p in overview["paths"][:12]],
        ))
    return 0


def cmd_learn_retrain(args: argparse.Namespace) -> int:
    db = _db(args)
    result = train_confidence_model(db, include_weak=not args.no_weak)
    print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_assets(args: argparse.Namespace) -> int:
    db = _db(args)
    engagement = _resolve_engagement(db, args.engagement)
    assets = db.list_assets(engagement["id"])
    if args.json:
        print(json.dumps(assets, indent=2, default=str))
        return 0
    rows = [[a["kind"], a["value"][:70], a.get("scheme") or "", str(a.get("port") or "")] for a in assets]
    if not rows:
        print("No assets yet. Run a scan.")
        return 0
    print(_table(["kind", "value", "scheme", "port"], rows))
    return 0


def cmd_runs(args: argparse.Namespace) -> int:
    db = _db(args)
    engagement = _resolve_engagement(db, args.engagement)
    runs = db.list_runs(engagement["id"])
    if args.json:
        print(json.dumps(runs, indent=2, default=str))
        return 0
    rows = [
        [
            r["id"][:14],
            r["mode"],
            r["status"],
            f"{r['coverage'] * 100:.1f}%",
            r["created_at"][:19],
            str(r.get("stats", {}).get("findings_new", 0)),
        ]
        for r in runs
    ]
    print(_table(["id", "mode", "status", "coverage", "created", "new findings"], rows))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    db = _db(args)
    run_id = args.run
    if not db.get_run(run_id):
        rows = db.query("SELECT id FROM runs WHERE id LIKE ?", (run_id + "%",))
        if len(rows) != 1:
            print(_color("error: run not found or ambiguous", RED), file=sys.stderr)
            return 2
        run_id = rows[0]["id"]
    if args.format == "html":
        content = render_html(db, run_id)
    elif args.format == "md":
        content = render_markdown(db, run_id)
    else:
        content = render_json(db, run_id)
    if args.out:
        path = Path(args.out)
    elif args.format == "html":
        path = Path("reports") / f"cairn-{run_id}.html"
    else:
        print(content)
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(_color("Report written", GREEN), str(path))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    db = _db(args)
    engagement = _resolve_engagement(db, args.engagement)
    if args.action == "verify":
        ok, count, bad = db.verify_audit(engagement["id"])
        evidence_ok, evidence_count, evidence_bad = db.verify_evidence(engagement["id"])
        print(f"Audit chain:    {'VERIFIED' if ok else 'FAILED'} ({count} events)")
        if not ok:
            print(f"  first failure: event {bad}")
        print(f"Evidence chain: {'VERIFIED' if evidence_ok else 'FAILED'} ({evidence_count} records)")
        if not evidence_ok:
            print(f"  first failure: {evidence_bad}")
        return 0 if ok and evidence_ok else 1
    events = db.list_audit(engagement["id"], limit=args.limit)
    for event in reversed(events):
        print(f"{event['ts']}  {event['actor']:18} {event['action']:24} {event['decision']:12} {event['target']}")
        if args.verbose and event.get("details"):
            print(f"    {json.dumps(event['details'], sort_keys=True)[:400]}")
    return 0


def cmd_scope_check(args: argparse.Namespace) -> int:
    db = _db(args)
    engagement = _resolve_engagement(db, args.engagement)

    async def check() -> int:
        guard = ScopeGuard(engagement, resolver=DNSResolver(), db=db)
        try:
            if args.url:
                target = await guard.check_url(args.url)
                print(_color("ALLOWED", GREEN), f"{args.url} → {target.ip}:{target.port}")
            else:
                if not args.host:
                    print("error: supply --host or --url", file=sys.stderr)
                    return 2
                target = await guard.prepare(args.host, args.port)
                print(_color("ALLOWED", GREEN), f"{target.host}:{target.port} → {target.ip}")
            return 0
        except Exception as exc:
            print(_color("DENIED", RED), str(exc))
            return 1

    return asyncio.run(check())


def cmd_demo(args: argparse.Namespace) -> int:
    db_path = Path(args.db).expanduser() if args.db else Path(".cairn/demo.db").resolve()
    db = Database(db_path)
    lab = DemoLab()
    try:
        lab.start()
    except OSError as exc:
        print(_color(f"error: could not start demo lab: {exc}", RED), file=sys.stderr)
        return 1
    print(_color("Cairn local demo lab", BOLD))
    print(f"  HTTP:  http://127.0.0.1:{lab.ports[0]}/")
    print(f"  HTTP:  http://127.0.0.1:{lab.ports[1]}/")
    if lab.tls_port:
        print(f"  HTTPS: https://127.0.0.1:{lab.tls_port}/  (self-signed, local only)")
    elif lab.tls_skipped:
        print(_color(f"  HTTPS: skipped — {lab.tls_skipped}", DIM))
    try:
        now = datetime.now(UTC)
        ports = tuple(lab.ports)
        scope = validate_scope([ScopeSpec("ip", "127.0.0.1")])
        limits = Limits(
            http_rate=12,
            port_rate=150,
            timeout=6,
            max_hosts=4,
            allowed_ports=ports,
            full_ports=False,
            max_content_paths=40,
        )
        validate_manifest(
            authorized_by="Local demo operator",
            authorization_ref="CAIRN-DEMO-LOCAL-ONLY",
            starts_at=now.isoformat(timespec="seconds"),
            expires_at=(now + timedelta(hours=2)).isoformat(timespec="seconds"),
            scope=scope,
        )
        engagement_id = db.create_engagement(
            name=f"Cairn local demo · {now.strftime('%Y-%m-%d %H:%M')}",
            client="Local demonstration",
            authorized_by="Local demo operator",
            authorization_ref="CAIRN-DEMO-LOCAL-ONLY",
            starts_at=now.isoformat(timespec="seconds"),
            expires_at=(now + timedelta(hours=2)).isoformat(timespec="seconds"),
            scope=scope,
            limits=limits.to_dict(),
            notes="Loopback-only demo with deliberately vulnerable endpoints. No external traffic.",
        )
        print(f"\nEngagement {engagement_id} · scope 127.0.0.1 · ports {', '.join(map(str, ports))}")
        run_id = db.create_run(engagement_id, "standard", {"online_intel": False, "active_dns": False, "source": "demo"})
        print("Running standard scan (no external intelligence, loopback only)…")
        from .engine.orchestrator import execute_run

        stats = asyncio.run(execute_run(db, run_id))
        engagement = db.get_engagement(engagement_id)
        assert engagement is not None
        _print_scan_summary(db, engagement, run_id, stats)
        print(f"\nDatabase: {db_path}")
        if args.serve:
            print(_color("\nDashboard starting. The demo lab stays live until you press Ctrl+C.", GREEN))
            return _serve_db(db_path, args.port, args.open, args.token)
        print(f"\nView the dashboard with: {_color('cairn --db ' + str(db_path) + ' serve', CYAN)}")
        print(f"Report: {_color('cairn --db ' + str(db_path) + ' report --run ' + run_id, CYAN)}")
        return 0
    finally:
        if not args.serve:
            lab.stop()


def _serve_db(db_path: Path, port: int, open_browser: bool, token: str | None) -> int:
    import uvicorn

    from .api.app import create_app

    app = create_app(db_path=db_path, token=token or None)
    url = f"http://127.0.0.1:{port}/"
    print(f"\n{_color('CAIRN dashboard', BOLD)}  {url}")
    print(f"Local access token: {app.state.token}")
    print("The dashboard injects this token automatically. Bind is loopback-only.")
    if open_browser:
        import threading

        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    db = _db(args)
    print(f"Using database: {db.path}", file=sys.stderr)
    return _serve_db(db.path, args.port, args.open, args.token)


# ----------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cairn",
        description="Cairn — evidence-first attack surface intelligence for authorized assessments.",
        epilog="Read ETHICS.md. An explicit, expiring scope manifest is required for every target.",
    )
    parser.add_argument("--db", help="SQLite database path (default: .cairn/cairn.db or CAIRN_DB)")
    parser.add_argument("--version", action="version", version=f"Cairn {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="Initialize the local database")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("doctor", help="Check runtime, database, and optional adapters")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("version", help="Print the version")
    p.set_defaults(func=cmd_version)

    eng = sub.add_parser("engagement", help="Create and inspect authorized engagements")
    eng_sub = eng.add_subparsers(dest="engagement_command", required=True)
    p = eng_sub.add_parser("create", help="Create an expiring, hashed scope manifest")
    p.add_argument("--name", required=True)
    p.add_argument("--client", default="")
    p.add_argument("--authorized-by", required=True, help="Human or organization granting permission")
    p.add_argument("--auth-ref", required=True, help="Ticket, contract, or written approval reference")
    p.add_argument("--expires", default="24h", help="Duration such as 24h, 7d, or 90m (max 180d)")
    p.add_argument("--domain", action="append", default=[], help="Domain to assess (repeatable)")
    p.add_argument("--wildcard", action="store_true", help="Include subdomains of all --domain entries")
    p.add_argument("--ip", action="append", default=[], help="IP to assess (repeatable)")
    p.add_argument("--cidr", action="append", default=[], help="CIDR to assess (repeatable)")
    p.add_argument("--url", action="append", default=[], help="URL path prefix to assess (repeatable)")
    p.add_argument("--exclude-domain", action="append", default=[])
    p.add_argument("--exclude-cidr", action="append", default=[])
    p.add_argument("--exclude-url", action="append", default=[])
    p.add_argument("--ports", default="", help="Ports/ranges, e.g. 80,443,8000-8100 (default: top ports)")
    p.add_argument("--all-ports", action="store_true", help="Authorize all 65,535 TCP ports")
    p.add_argument("--http-rate", type=float, default=4.0, help="Requests/second/host (default 4)")
    p.add_argument("--port-rate", type=float, default=250.0, help="Connects/second/host (default 250)")
    p.add_argument("--max-hosts", type=int, default=256)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--notes", default="")
    p.set_defaults(func=cmd_engagement_create)
    p = eng_sub.add_parser("list", help="List engagements")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_engagement_list)
    p = eng_sub.add_parser("show", help="Show an engagement and its manifest")
    p.add_argument("engagement")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_engagement_show)
    p = eng_sub.add_parser("revoke", help="Revoke an engagement immediately")
    p.add_argument("engagement")
    p.add_argument("--analyst", default="operator")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_engagement_revoke)

    p = sub.add_parser("scan", help="Run a scope-gated assessment")
    p.add_argument("--engagement", required=True)
    p.add_argument("--mode", choices=["passive", "standard", "deep"], default="standard")
    p.add_argument("--no-online-intel", action="store_true", help="Disable certificate transparency and RDAP")
    p.add_argument("--no-active-dns", action="store_true", help="Disable DNS wordlist discovery")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("demo", help="Run a safe loopback-only demonstration")
    p.add_argument("--serve", action="store_true", help="Start the dashboard after the scan")
    p.add_argument("--open", action="store_true", help="Open the dashboard in a browser")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--token", default=None)
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("serve", help="Start the local dashboard and API")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--open", action="store_true")
    p.add_argument("--token", default=None)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("findings", help="List findings")
    p.add_argument("--engagement", required=True)
    p.add_argument("--min-severity", choices=list(SEVERITY_RANK))
    p.add_argument("--min-confidence", type=float)
    p.add_argument("--status", choices=["open", "confirmed", "false_positive", "accepted_risk", "duplicate"])
    p.add_argument("--band", choices=["low", "medium", "high"])
    p.add_argument("--run")
    p.add_argument("--search")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_findings_list)

    finding = sub.add_parser("finding", help="Inspect one finding")
    finding_sub = finding.add_subparsers(dest="finding_command", required=True)
    p = finding_sub.add_parser("show", help="Show evidence, confidence, and feedback")
    p.add_argument("finding")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_finding_show)

    p = sub.add_parser("feedback", help="Record an analyst verdict (drives learning)")
    p.add_argument("finding")
    p.add_argument("--verdict", required=True, choices=["confirmed", "false_positive", "accepted_risk", "uncertain", "duplicate"])
    p.add_argument("--analyst", default="")
    p.add_argument("--note", default="")
    p.add_argument("--no-retrain", action="store_true")
    p.set_defaults(func=cmd_feedback)

    learn = sub.add_parser("learn", help="Inspect or trigger continuous learning")
    learn_sub = learn.add_subparsers(dest="learn_command", required=True)
    p = learn_sub.add_parser("stats", help="Show calibration, detector reliability, and review queue")
    p.set_defaults(func=cmd_learn_stats)
    p = learn_sub.add_parser("retrain", help="Train a challenger and promote only if it wins")
    p.add_argument("--no-weak", action="store_true")
    p.set_defaults(func=cmd_learn_retrain)

    p = sub.add_parser("assets", help="List discovered assets")
    p.add_argument("--engagement", required=True)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_assets)

    p = sub.add_parser("runs", help="List assessment runs")
    p.add_argument("--engagement", required=True)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_runs)

    p = sub.add_parser("report", help="Generate HTML, Markdown, or JSON report")
    p.add_argument("--run", required=True)
    p.add_argument("--format", choices=["html", "md", "json"], default="html")
    p.add_argument("--out")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("audit", help="Verify or inspect the hash-chained audit log")
    p.add_argument("action", choices=["verify", "list"])
    p.add_argument("--engagement", required=True)
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("scope", help="Check whether a target is inside an engagement")
    p.add_argument("action", choices=["check"])
    p.add_argument("--engagement", required=True)
    p.add_argument("--host")
    p.add_argument("--port", type=int, default=80)
    p.add_argument("--url")
    p.set_defaults(func=cmd_scope_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyError as exc:
        print(_color(f"error: {exc}", RED), file=sys.stderr)
        return 2
    except ScopeError as exc:
        print(_color(f"scope error: {exc}", RED), file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
