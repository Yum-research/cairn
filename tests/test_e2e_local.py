from __future__ import annotations

import asyncio

from cairn.engine.orchestrator import execute_run
from cairn.models import ScopeSpec
from cairn.reporting import render_html, render_json, render_markdown

from .conftest import make_engagement


def test_end_to_end_scan_against_loopback_lab(db, lab_server):
    engagement = make_engagement(
        db,
        scope=[ScopeSpec(kind="ip", value="127.0.0.1")],
        allowed_ports=(lab_server,),
        name="Loopback E2E",
    )
    run_id = db.create_run(
        engagement["id"],
        "standard",
        {"online_intel": False, "active_dns": False, "source": "pytest"},
    )
    asyncio.run(execute_run(db, run_id))

    run = db.get_run(run_id)
    assert run["status"] == "completed", run.get("error")
    findings = db.list_findings(engagement["id"])
    detectors = {finding["detector"] for finding in findings}
    assert "web.exposed_env" in detectors
    assert "web.exposed_git" in detectors
    assert all(0.0 < finding["confidence"] <= 1.0 for finding in findings)
    assert all(finding["confidence_band"] in ("low", "medium", "high") for finding in findings)
    assert all(finding["explain"] for finding in findings)

    audit_ok, audit_count, audit_bad = db.verify_audit(engagement["id"])
    evidence_ok, evidence_count, evidence_bad = db.verify_evidence(engagement["id"])
    assert (audit_ok, audit_bad) == (True, None)
    assert (evidence_ok, evidence_bad) == (True, None)
    assert audit_count > 0
    assert evidence_count > 0

    excerpts = [row["excerpt"] for row in db.query("SELECT excerpt FROM evidence")]
    joined = "\n".join(excerpts)
    assert "hunter2" not in joined
    assert "AKIAIOSFODNN7EXAMPLE" not in joined
    assert "supersecretvalue" not in joined

    html = render_html(db, run_id)
    markdown = render_markdown(db, run_id)
    payload = render_json(db, run_id)
    assert "Cairn" in html
    assert "Exposed environment file" in markdown or "environment" in markdown.lower()
    assert '"findings"' in payload
    assert "hunter2" not in html
    assert "hunter2" not in payload
