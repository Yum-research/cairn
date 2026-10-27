from __future__ import annotations

from cairn.db import GENESIS

from .conftest import make_engagement


def test_evidence_hash_chain_detects_tampering(db):
    engagement = make_engagement(db)
    run_id = db.create_run(engagement["id"], "passive", {})
    first = db.add_evidence(
        engagement_id=engagement["id"],
        run_id=run_id,
        kind="http",
        source="fixture",
        locator="http://127.0.0.1/",
        content_sha256="a" * 64,
        excerpt="first observation",
    )
    second = db.add_evidence(
        engagement_id=engagement["id"],
        run_id=run_id,
        kind="dns",
        source="fixture",
        locator="127.0.0.1",
        content_sha256="b" * 64,
        excerpt="second observation",
    )
    valid, count, bad = db.verify_evidence(engagement["id"])
    assert valid is True
    assert count == 2
    assert bad is None

    records = db.query("SELECT id, prev_hash FROM evidence ORDER BY rowid ASC")
    assert records[0]["prev_hash"] == GENESIS
    assert records[1]["prev_hash"] != GENESIS
    assert records[1]["prev_hash"] == db.get_evidence(first)["hash"]
    assert second

    db.execute("UPDATE evidence SET excerpt='tampered' WHERE id=?", (first,))
    valid, count, bad = db.verify_evidence(engagement["id"])
    assert valid is False
    assert count == 2
    assert bad == first


def test_audit_hash_chain_detects_tampering(db):
    engagement = make_engagement(db)
    db.add_audit(
        engagement["id"],
        action="test.one",
        target="fixture",
        decision="allow",
        details={"n": 1},
    )
    db.add_audit(
        engagement["id"],
        action="test.two",
        target="fixture",
        decision="deny",
        details={"n": 2},
    )
    valid, count, bad = db.verify_audit(engagement["id"])
    assert (valid, count, bad) == (True, count, None)
    assert count >= 3  # engagement.created plus two test events

    first = db.one("SELECT id FROM audit_events WHERE action='test.one'")
    db.execute("UPDATE audit_events SET decision='allow-all' WHERE id=?", (first["id"],))
    valid, _, bad = db.verify_audit(engagement["id"])
    assert valid is False
    assert bad == first["id"]
