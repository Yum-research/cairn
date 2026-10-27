from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .config import canonical_json, new_id, utcnow
from .models import DetectorHit, band_for

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client TEXT NOT NULL DEFAULT '',
    authorized_by TEXT NOT NULL,
    authorization_ref TEXT NOT NULL,
    starts_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    manifest_json TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    limits_json TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('domain','ip','cidr','url')),
    value TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'include' CHECK(mode IN ('include','exclude')),
    include_subdomains INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scope_engagement ON scope_rules(engagement_id);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    mode TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    config_json TEXT NOT NULL DEFAULT '{}',
    stats_json TEXT NOT NULL DEFAULT '{}',
    coverage REAL NOT NULL DEFAULT 0,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_engagement ON runs(engagement_id, created_at DESC);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    host TEXT,
    port INTEGER,
    scheme TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    meta_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(engagement_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_assets_engagement ON assets(engagement_id, kind);
CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(engagement_id, host);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    locator TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    excerpt TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence(run_id);

CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    data_json TEXT NOT NULL,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE SET NULL,
    observed_at TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    fingerprint TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_run ON observations(run_id, kind);
CREATE INDEX IF NOT EXISTS idx_obs_asset ON observations(asset_id);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    detector TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    confidence_band TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    features_json TEXT NOT NULL DEFAULT '{}',
    explain_json TEXT NOT NULL DEFAULT '[]',
    fingerprint TEXT NOT NULL,
    model_version INTEGER,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 1,
    UNIQUE(engagement_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id, severity, confidence);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(engagement_id, status);

CREATE TABLE IF NOT EXISTS finding_runs (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    confidence REAL NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    observed_at TEXT NOT NULL,
    PRIMARY KEY(finding_id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_runs_run ON finding_runs(run_id);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    verdict TEXT NOT NULL,
    analyst TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    weight REAL NOT NULL DEFAULT 1.0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feedback_finding ON feedback(finding_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_engagement ON audit_events(engagement_id, id);

CREATE TABLE IF NOT EXISTS models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL,
    n_labels INTEGER NOT NULL DEFAULT 0,
    metrics_json TEXT NOT NULL DEFAULT '{}',
    weights_json TEXT NOT NULL DEFAULT '{}',
    calibration_json TEXT NOT NULL DEFAULT '{}',
    parent_id INTEGER,
    notes TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_models_kind ON models(kind, status, id DESC);

CREATE TABLE IF NOT EXISTS probe_stats (
    key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    trials INTEGER NOT NULL DEFAULT 0,
    successes INTEGER NOT NULL DEFAULT 0,
    reward REAL NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS path_stats (
    path TEXT PRIMARY KEY,
    trials INTEGER NOT NULL DEFAULT 0,
    successes INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT,
    run_id TEXT,
    ts TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, id);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

GENESIS = "0" * 64


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version','1') "
                "ON CONFLICT(key) DO NOTHING"
            )

    @contextmanager
    def tx(self, immediate: bool = False):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [dict(row) for row in rows]

    def one(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        with self.connect() as conn:
            cur = conn.execute(sql, tuple(params))
            return cur.lastrowid or 0

    # ------------------------------------------------------------------ events
    def add_event(
        self,
        run_id: str | None,
        engagement_id: str | None,
        kind: str,
        message: str,
        level: str = "info",
        data: dict[str, Any] | None = None,
    ) -> None:
        self.execute(
            "INSERT INTO events(engagement_id,run_id,ts,level,kind,message,data_json) VALUES(?,?,?,?,?,?,?)",
            (engagement_id, run_id, utcnow(), level, kind, message, canonical_json(data or {})),
        )

    def list_events(self, run_id: str, after_id: int = 0, limit: int = 300) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT * FROM events WHERE run_id=? AND id>? ORDER BY id ASC LIMIT ?",
            (run_id, after_id, limit),
        )
        for row in rows:
            row["data"] = json.loads(row.pop("data_json") or "{}")
        return rows

    # -------------------------------------------------------------- engagements
    def create_engagement(
        self,
        *,
        name: str,
        client: str,
        authorized_by: str,
        authorization_ref: str,
        starts_at: str,
        expires_at: str,
        scope: list[dict[str, Any]],
        limits: dict[str, Any],
        notes: str = "",
        actor: str = "operator",
    ) -> str:
        engagement_id = new_id("eng", 12)
        manifest = {
            "name": name,
            "client": client,
            "authorized_by": authorized_by,
            "authorization_ref": authorization_ref,
            "starts_at": starts_at,
            "expires_at": expires_at,
            "scope": sorted(scope, key=lambda s: (s["mode"], s["kind"], s["value"])),
            "limits": limits,
            "created_at": utcnow(),
        }
        manifest_json = canonical_json(manifest)
        manifest_hash = sha256(manifest_json)
        with self.tx(immediate=True) as conn:
            conn.execute(
                "INSERT INTO engagements(id,name,client,authorized_by,authorization_ref,starts_at,expires_at,"
                "status,manifest_json,manifest_hash,limits_json,notes,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    engagement_id, name, client, authorized_by, authorization_ref, starts_at, expires_at,
                    "active", manifest_json, manifest_hash, canonical_json(limits), notes, utcnow(),
                ),
            )
            for rule in scope:
                conn.execute(
                    "INSERT INTO scope_rules(engagement_id,kind,value,mode,include_subdomains,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        engagement_id,
                        rule["kind"],
                        rule["value"],
                        rule.get("mode", "include"),
                        1 if rule.get("include_subdomains") else 0,
                        utcnow(),
                    ),
                )
        self.add_audit(
            engagement_id,
            action="engagement.created",
            target=name,
            decision="allow",
            details={
                "authorized_by": authorized_by,
                "authorization_ref": authorization_ref,
                "manifest_hash": manifest_hash,
                "expires_at": expires_at,
                "scope_rules": len(scope),
            },
            actor=actor,
        )
        return engagement_id

    def list_engagements(self) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT e.*, "
            "(SELECT COUNT(*) FROM runs r WHERE r.engagement_id=e.id) AS run_count, "
            "(SELECT COUNT(*) FROM findings f WHERE f.engagement_id=e.id AND f.status='open') AS open_findings, "
            "(SELECT MAX(created_at) FROM runs r WHERE r.engagement_id=e.id) AS last_run_at "
            "FROM engagements e ORDER BY e.created_at DESC"
        )
        for row in rows:
            row["scope"] = self.get_scope(row["id"])
        return rows

    def get_engagement(self, engagement_id: str) -> dict[str, Any] | None:
        row = self.one("SELECT * FROM engagements WHERE id=?", (engagement_id,))
        if row:
            row["manifest"] = json.loads(row.pop("manifest_json") or "{}")
            row["limits"] = json.loads(row.pop("limits_json") or "{}")
            row["scope"] = self.get_scope(engagement_id)
        return row

    def get_scope(self, engagement_id: str) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT id,kind,value,mode,include_subdomains FROM scope_rules WHERE engagement_id=? "
            "ORDER BY mode ASC, kind ASC, value ASC",
            (engagement_id,),
        )
        for row in rows:
            row["include_subdomains"] = bool(row["include_subdomains"])
        return rows

    def set_engagement_status(self, engagement_id: str, status: str, actor: str = "operator") -> None:
        self.execute("UPDATE engagements SET status=? WHERE id=?", (status, engagement_id))
        self.add_audit(
            engagement_id, action="engagement.status", target=engagement_id, decision=status, actor=actor,
        )

    # --------------------------------------------------------------------- runs
    def create_run(self, engagement_id: str, mode: str, config: dict[str, Any]) -> str:
        run_id = new_id("run", 12)
        self.execute(
            "INSERT INTO runs(id,engagement_id,mode,status,config_json,created_at) VALUES(?,?,?,?,?,?)",
            (run_id, engagement_id, mode, "queued", canonical_json(config), utcnow()),
        )
        self.add_audit(
            engagement_id,
            action="run.queued",
            target=run_id,
            decision="allow",
            details={"mode": mode, "config": config},
        )
        self.add_event(run_id, engagement_id, "run", f"Run queued in {mode} mode")
        return run_id

    def start_run(self, run_id: str) -> None:
        self.execute(
            "UPDATE runs SET status='running', started_at=? WHERE id=?", (utcnow(), run_id)
        )

    def finish_run(
        self,
        run_id: str,
        *,
        status: str = "completed",
        stats: dict[str, Any] | None = None,
        coverage: float = 0.0,
        error: str | None = None,
    ) -> None:
        self.execute(
            "UPDATE runs SET status=?, finished_at=?, stats_json=?, coverage=?, error=? WHERE id=?",
            (status, utcnow(), canonical_json(stats or {}), round(coverage, 4), error, run_id),
        )
        run = self.get_run(run_id)
        if run:
            self.add_event(
                run_id, run["engagement_id"], "run", f"Run {status}", level="error" if error else "info"
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self.one("SELECT * FROM runs WHERE id=?", (run_id,))
        if row:
            row["config"] = json.loads(row.pop("config_json") or "{}")
            row["stats"] = json.loads(row.pop("stats_json") or "{}")
            row["engagement"] = self.get_engagement(row["engagement_id"])
        return row

    def list_runs(self, engagement_id: str, limit: int = 30) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT * FROM runs WHERE engagement_id=? ORDER BY created_at DESC LIMIT ?",
            (engagement_id, limit),
        )
        for row in rows:
            row["stats"] = json.loads(row.pop("stats_json") or "{}")
            row["config"] = json.loads(row.pop("config_json") or "{}")
        return rows

    def cancel_run(self, run_id: str) -> None:
        self.execute(
            "UPDATE runs SET status='cancelling' WHERE id=? AND status IN ('queued','running')", (run_id,)
        )

    def mark_interrupted_runs(self) -> int:
        rows = self.query("SELECT id, engagement_id FROM runs WHERE status IN ('queued','running','cancelling')")
        for row in rows:
            self.execute(
                "UPDATE runs SET status='interrupted', finished_at=?, error='Process restarted before completion' "
                "WHERE id=?",
                (utcnow(), row["id"]),
            )
            self.add_event(
                row["id"], row["engagement_id"], "run", "Run interrupted by process restart", level="warning"
            )
        return len(rows)

    # ------------------------------------------------------------------- assets
    def upsert_asset(
        self,
        engagement_id: str,
        kind: str,
        value: str,
        *,
        host: str | None = None,
        port: int | None = None,
        scheme: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> str:
        now = utcnow()
        existing = self.one(
            "SELECT id FROM assets WHERE engagement_id=? AND kind=? AND value=?",
            (engagement_id, kind, value),
        )
        if existing:
            self.execute(
                "UPDATE assets SET last_seen=?, host=COALESCE(?,host), port=COALESCE(?,port), "
                "scheme=COALESCE(?,scheme), meta_json=? WHERE id=?",
                (now, host, port, scheme, canonical_json(meta or {}), existing["id"]),
            )
            return existing["id"]
        asset_id = new_id("ast", 12)
        self.execute(
            "INSERT INTO assets(id,engagement_id,kind,value,host,port,scheme,first_seen,last_seen,meta_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (asset_id, engagement_id, kind, value, host, port, scheme, now, now, canonical_json(meta or {})),
        )
        return asset_id

    def list_assets(self, engagement_id: str) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT * FROM assets WHERE engagement_id=? ORDER BY kind, value", (engagement_id,)
        )
        for row in rows:
            row["meta"] = json.loads(row.pop("meta_json") or "{}")
        return rows

    def get_asset(self, asset_id: str) -> dict[str, Any] | None:
        row = self.one("SELECT * FROM assets WHERE id=?", (asset_id,))
        if row:
            row["meta"] = json.loads(row.pop("meta_json") or "{}")
        return row

    # ---------------------------------------------------------------- evidence
    def add_evidence(
        self,
        *,
        engagement_id: str,
        run_id: str,
        kind: str,
        source: str,
        locator: str,
        content_sha256: str,
        excerpt: str,
        collected_at: str | None = None,
    ) -> str:
        evidence_id = new_id("ev", 12)
        ts = collected_at or utcnow()
        with self.tx(immediate=True) as conn:
            last = conn.execute(
                "SELECT hash FROM evidence WHERE engagement_id=? ORDER BY rowid DESC LIMIT 1",
                (engagement_id,),
            ).fetchone()
            prev = last["hash"] if last else GENESIS
            payload = canonical_json(
                {
                    "engagement_id": engagement_id,
                    "run_id": run_id,
                    "kind": kind,
                    "source": source,
                    "locator": locator,
                    "content_sha256": content_sha256,
                    "excerpt": excerpt,
                    "collected_at": ts,
                }
            )
            digest = sha256(prev + payload)
            conn.execute(
                "INSERT INTO evidence(id,engagement_id,run_id,kind,source,locator,content_sha256,excerpt,"
                "collected_at,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    evidence_id, engagement_id, run_id, kind, source, locator,
                    content_sha256, excerpt, ts, prev, digest,
                ),
            )
        return evidence_id

    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        return self.one("SELECT * FROM evidence WHERE id=?", (evidence_id,))

    def get_evidence_many(self, ids: list[str]) -> list[dict[str, Any]]:
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        return self.query(
            f"SELECT * FROM evidence WHERE id IN ({placeholders}) ORDER BY collected_at ASC", ids
        )

    def evidence_count(self, run_id: str) -> int:
        row = self.one("SELECT COUNT(*) AS n FROM evidence WHERE run_id=?", (run_id,))
        return int(row["n"]) if row else 0

    # -------------------------------------------------------------- observation
    def add_observation(
        self,
        *,
        engagement_id: str,
        run_id: str,
        asset_id: str | None,
        kind: str,
        source: str,
        data: dict[str, Any],
        evidence_id: str | None = None,
        confidence: float = 1.0,
        fingerprint: str | None = None,
    ) -> str:
        observation_id = new_id("obs", 12)
        self.execute(
            "INSERT INTO observations(id,engagement_id,run_id,asset_id,kind,source,data_json,evidence_id,"
            "observed_at,confidence,fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                observation_id, engagement_id, run_id, asset_id, kind, source, canonical_json(data),
                evidence_id, utcnow(), confidence, fingerprint,
            ),
        )
        return observation_id

    def list_observations(self, run_id: str, kind: str | None = None) -> list[dict[str, Any]]:
        if kind:
            rows = self.query(
                "SELECT * FROM observations WHERE run_id=? AND kind=? ORDER BY observed_at", (run_id, kind)
            )
        else:
            rows = self.query("SELECT * FROM observations WHERE run_id=? ORDER BY observed_at", (run_id,))
        for row in rows:
            row["data"] = json.loads(row.pop("data_json") or "{}")
        return rows

    # ----------------------------------------------------------------- findings
    def upsert_finding(
        self,
        *,
        engagement_id: str,
        run_id: str,
        asset_id: str | None,
        hit: DetectorHit,
        asset_value: str,
        confidence: float,
        explain: list[dict[str, Any]],
        model_version: int | None,
        evidence_ids: list[str],
    ) -> tuple[str, bool]:
        fingerprint = sha256(hit.fingerprint_key(asset_value))
        now = utcnow()
        with self.tx(immediate=True) as conn:
            row = conn.execute(
                "SELECT id, occurrences FROM findings WHERE engagement_id=? AND fingerprint=?",
                (engagement_id, fingerprint),
            ).fetchone()
            if row:
                finding_id = row["id"]
                already_in_run = conn.execute(
                    "SELECT 1 FROM finding_runs WHERE finding_id=? AND run_id=?", (finding_id, run_id)
                ).fetchone()
                occurrences = row["occurrences"] + (0 if already_in_run else 1)
                conn.execute(
                    "UPDATE findings SET title=?,category=?,severity=?,confidence=?,confidence_band=?,"
                    "description=?,remediation=?,features_json=?,explain_json=?,model_version=?,"
                    "last_seen=?,occurrences=?,asset_id=COALESCE(?,asset_id) WHERE id=?",
                    (
                        hit.title, hit.category, hit.severity, round(confidence, 4), band_for(confidence),
                        hit.description, hit.remediation, canonical_json(hit.features),
                        canonical_json(explain), model_version, now, occurrences, asset_id, finding_id,
                    ),
                )
                conn.execute(
                    "INSERT INTO finding_runs(finding_id,run_id,confidence,evidence_json,observed_at) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(finding_id,run_id) DO UPDATE SET "
                    "confidence=excluded.confidence, evidence_json=excluded.evidence_json, "
                    "observed_at=excluded.observed_at",
                    (finding_id, run_id, round(confidence, 4), canonical_json(evidence_ids), now),
                )
                return finding_id, False
            finding_id = new_id("fnd", 12)
            conn.execute(
                "INSERT INTO findings(id,engagement_id,asset_id,detector,title,category,severity,confidence,"
                "confidence_band,status,description,remediation,features_json,explain_json,fingerprint,"
                "model_version,first_seen,last_seen,occurrences) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    finding_id, engagement_id, asset_id, hit.detector, hit.title, hit.category, hit.severity,
                    round(confidence, 4), band_for(confidence), "open", hit.description, hit.remediation,
                    canonical_json(hit.features), canonical_json(explain), fingerprint, model_version, now, now, 1,
                ),
            )
            conn.execute(
                "INSERT INTO finding_runs(finding_id,run_id,confidence,evidence_json,observed_at) "
                "VALUES(?,?,?,?,?)",
                (finding_id, run_id, round(confidence, 4), canonical_json(evidence_ids), now),
            )
            return finding_id, True

    def list_findings(
        self,
        engagement_id: str,
        *,
        min_severity: str | None = None,
        status: str | None = None,
        band: str | None = None,
        run_id: str | None = None,
        query_text: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        params: list[Any] = [engagement_id]
        sql = (
            "SELECT f.*, a.value AS asset_value, a.kind AS asset_kind, "
            "(SELECT evidence_json FROM finding_runs fr WHERE fr.finding_id=f.id "
            " ORDER BY observed_at DESC LIMIT 1) AS evidence_ids_json "
            "FROM findings f LEFT JOIN assets a ON a.id=f.asset_id WHERE f.engagement_id=?"
        )
        if run_id:
            sql += " AND EXISTS(SELECT 1 FROM finding_runs fr WHERE fr.finding_id=f.id AND fr.run_id=?)"
            params.append(run_id)
        if status:
            sql += " AND f.status=?"
            params.append(status)
        if band:
            sql += " AND f.confidence_band=?"
            params.append(band)
        sql += " ORDER BY f.last_seen DESC LIMIT ?"
        params.append(limit)
        rows = self.query(sql, params)
        rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        for row in rows:
            row["features"] = json.loads(row.pop("features_json") or "{}")
            row["explain"] = json.loads(row.pop("explain_json") or "[]")
            row["evidence_ids"] = json.loads(row.pop("evidence_ids_json") or "[]")
        if min_severity:
            rows = [r for r in rows if rank.get(r["severity"], 0) >= rank.get(min_severity, 0)]
        if query_text:
            needle = query_text.lower()
            rows = [
                r for r in rows
                if needle in (r["title"] + " " + r["detector"] + " " + (r["asset_value"] or "")).lower()
            ]
        rows.sort(
            key=lambda r: (rank.get(r["severity"], 0), r["confidence"], r["last_seen"]), reverse=True
        )
        return rows

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        row = self.one(
            "SELECT f.*, a.value AS asset_value, a.kind AS asset_kind, a.host AS asset_host, "
            "a.port AS asset_port, a.scheme AS asset_scheme FROM findings f "
            "LEFT JOIN assets a ON a.id=f.asset_id WHERE f.id=?",
            (finding_id,),
        )
        if not row:
            return None
        row["features"] = json.loads(row.pop("features_json") or "{}")
        row["explain"] = json.loads(row.pop("explain_json") or "[]")
        runs = self.query(
            "SELECT * FROM finding_runs WHERE finding_id=? ORDER BY observed_at DESC", (finding_id,)
        )
        evidence_ids: list[str] = []
        for run in runs:
            run["evidence_ids"] = json.loads(run.pop("evidence_json") or "[]")
            for eid in run["evidence_ids"]:
                if eid not in evidence_ids:
                    evidence_ids.append(eid)
        row["runs"] = runs
        row["evidence"] = self.get_evidence_many(evidence_ids[:24])
        row["feedback"] = self.list_feedback(finding_id)
        return row

    def add_feedback(
        self,
        finding_id: str,
        verdict: str,
        analyst: str,
        note: str = "",
        weight: float = 1.0,
    ) -> None:
        finding = self.get_finding(finding_id)
        if not finding:
            raise KeyError(f"Unknown finding: {finding_id}")
        self.execute(
            "INSERT INTO feedback(finding_id,engagement_id,verdict,analyst,note,weight,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (finding_id, finding["engagement_id"], verdict, analyst, note, weight, utcnow()),
        )
        status = {
            "confirmed": "confirmed",
            "false_positive": "false_positive",
            "accepted_risk": "accepted_risk",
            "duplicate": "duplicate",
        }.get(verdict)
        if status:
            self.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
        self.add_audit(
            finding["engagement_id"],
            action="finding.feedback",
            target=finding_id,
            decision=verdict,
            details={"analyst": analyst, "note": note, "weight": weight},
            actor=analyst,
        )

    def list_feedback(self, finding_id: str) -> list[dict[str, Any]]:
        return self.query(
            "SELECT * FROM feedback WHERE finding_id=? ORDER BY created_at DESC", (finding_id,)
        )

    def feedback_training_rows(self) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT f.id AS finding_id, f.detector, f.features_json, f.confidence, f.severity, "
            "f.first_seen, fb.verdict, fb.weight, fb.created_at FROM feedback fb "
            "JOIN findings f ON f.id=fb.finding_id WHERE fb.verdict IN "
            "('confirmed','false_positive','accepted_risk') ORDER BY fb.created_at ASC"
        )
        for row in rows:
            row["features"] = json.loads(row.pop("features_json") or "{}")
        return rows

    def feedback_counts(self) -> dict[str, int]:
        rows = self.query("SELECT verdict, COUNT(*) AS n FROM feedback GROUP BY verdict")
        return {r["verdict"]: int(r["n"]) for r in rows}

    def findings_for_run(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT f.*, fr.confidence AS run_confidence, fr.evidence_json, a.value AS asset_value "
            "FROM finding_runs fr JOIN findings f ON f.id=fr.finding_id "
            "LEFT JOIN assets a ON a.id=f.asset_id WHERE fr.run_id=?",
            (run_id,),
        )
        rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        for row in rows:
            row["evidence_ids"] = json.loads(row.pop("evidence_json") or "[]")
            row["features"] = json.loads(row.pop("features_json") or "{}")
            row["explain"] = json.loads(row.pop("explain_json") or "[]")
        rows.sort(key=lambda r: (rank.get(r["severity"], 0), r["run_confidence"]), reverse=True)
        return rows

    def fingerprints_for_run(self, run_id: str) -> set[str]:
        rows = self.query(
            "SELECT f.fingerprint FROM finding_runs fr JOIN findings f ON f.id=fr.finding_id WHERE fr.run_id=?",
            (run_id,),
        )
        return {r["fingerprint"] for r in rows}

    def latest_previous_run(self, engagement_id: str, before_run_id: str) -> dict[str, Any] | None:
        return self.one(
            "SELECT * FROM runs WHERE engagement_id=? AND status='completed' "
            "AND rowid < (SELECT rowid FROM runs WHERE id=?) ORDER BY rowid DESC LIMIT 1",
            (engagement_id, before_run_id),
        )

    # ------------------------------------------------------------------- audit
    def add_audit(
        self,
        engagement_id: str,
        *,
        action: str,
        target: str = "",
        decision: str = "",
        details: dict[str, Any] | None = None,
        actor: str = "operator",
    ) -> None:
        ts = utcnow()
        details_json = canonical_json(details or {})
        with self.tx(immediate=True) as conn:
            last = conn.execute(
                "SELECT hash FROM audit_events WHERE engagement_id=? ORDER BY id DESC LIMIT 1",
                (engagement_id,),
            ).fetchone()
            prev = last["hash"] if last else GENESIS
            payload = canonical_json(
                {
                    "engagement_id": engagement_id,
                    "ts": ts,
                    "actor": actor,
                    "action": action,
                    "target": target,
                    "decision": decision,
                    "details": json.loads(details_json),
                }
            )
            digest = sha256(prev + payload)
            conn.execute(
                "INSERT INTO audit_events(engagement_id,ts,actor,action,target,decision,details_json,prev_hash,hash) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (engagement_id, ts, actor, action, target, decision, details_json, prev, digest),
            )

    def list_audit(self, engagement_id: str, limit: int = 500) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT * FROM audit_events WHERE engagement_id=? ORDER BY id DESC LIMIT ?",
            (engagement_id, limit),
        )
        for row in rows:
            row["details"] = json.loads(row.pop("details_json") or "{}")
        return rows

    def verify_audit(self, engagement_id: str) -> tuple[bool, int, str | None]:
        rows = self.query(
            "SELECT * FROM audit_events WHERE engagement_id=? ORDER BY id ASC", (engagement_id,)
        )
        prev = GENESIS
        for row in rows:
            payload = canonical_json(
                {
                    "engagement_id": row["engagement_id"],
                    "ts": row["ts"],
                    "actor": row["actor"],
                    "action": row["action"],
                    "target": row["target"],
                    "decision": row["decision"],
                    "details": json.loads(row["details_json"] or "{}"),
                }
            )
            expected = sha256(prev + payload)
            if row["prev_hash"] != prev or row["hash"] != expected:
                return False, len(rows), row["id"]
            prev = row["hash"]
        return True, len(rows), None

    def verify_evidence(self, engagement_id: str) -> tuple[bool, int, str | None]:
        rows = self.query(
            "SELECT * FROM evidence WHERE engagement_id=? ORDER BY rowid ASC", (engagement_id,)
        )
        prev = GENESIS
        for row in rows:
            payload = canonical_json(
                {
                    "engagement_id": row["engagement_id"],
                    "run_id": row["run_id"],
                    "kind": row["kind"],
                    "source": row["source"],
                    "locator": row["locator"],
                    "content_sha256": row["content_sha256"],
                    "excerpt": row["excerpt"],
                    "collected_at": row["collected_at"],
                }
            )
            expected = sha256(prev + payload)
            if row["prev_hash"] != prev or row["hash"] != expected:
                return False, len(rows), row["id"]
            prev = row["hash"]
        return True, len(rows), None

    # ------------------------------------------------------------------ learning
    def add_model(
        self,
        *,
        kind: str,
        status: str,
        n_labels: int,
        metrics: dict[str, Any],
        weights: dict[str, Any],
        calibration: dict[str, Any],
        parent_id: int | None,
        notes: str = "",
    ) -> int:
        return self.execute(
            "INSERT INTO models(kind,created_at,status,n_labels,metrics_json,weights_json,calibration_json,"
            "parent_id,notes) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                kind, utcnow(), status, n_labels, canonical_json(metrics), canonical_json(weights),
                canonical_json(calibration), parent_id, notes,
            ),
        )

    def get_model(self, model_id: int) -> dict[str, Any] | None:
        return self._model_row(self.one("SELECT * FROM models WHERE id=?", (model_id,)))

    def champion_model(self, kind: str = "confidence") -> dict[str, Any] | None:
        return self._model_row(
            self.one(
                "SELECT * FROM models WHERE kind=? AND status='champion' ORDER BY id DESC LIMIT 1", (kind,)
            )
        )

    @staticmethod
    def _model_row(row: dict[str, Any] | None) -> dict[str, Any] | None:
        if row:
            row["metrics"] = json.loads(row.pop("metrics_json") or "{}")
            row["weights"] = json.loads(row.pop("weights_json") or "{}")
            row["calibration"] = json.loads(row.pop("calibration_json") or "{}")
        return row

    def list_models(self, kind: str = "confidence", limit: int = 50) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT * FROM models WHERE kind=? ORDER BY id DESC LIMIT ?", (kind, limit)
        )
        return [self._model_row(r) for r in rows]  # type: ignore[misc]

    def demote_champions(self, kind: str) -> None:
        self.execute("UPDATE models SET status='archived' WHERE kind=? AND status='champion'", (kind,))

    def record_probe(self, key: str, kind: str, success: bool, reward: float = 1.0) -> None:
        self.execute(
            "INSERT INTO probe_stats(key,kind,trials,successes,reward,updated_at) VALUES(?,?,1,?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET trials=trials+1, successes=successes+excluded.successes, "
            "reward=reward+excluded.reward, updated_at=excluded.updated_at",
            (key, kind, 1 if success else 0, reward if success else 0.0, utcnow()),
        )

    def probe_stats(self) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM probe_stats ORDER BY kind, key")

    def record_path(self, path: str, finding: bool) -> None:
        self.execute(
            "INSERT INTO path_stats(path,trials,successes,updated_at) VALUES(?,1,?,?) "
            "ON CONFLICT(path) DO UPDATE SET trials=trials+1, successes=successes+excluded.successes, "
            "updated_at=excluded.updated_at",
            (path, 1 if finding else 0, utcnow()),
        )

    def path_stats(self) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM path_stats ORDER BY trials DESC, path ASC")

    # --------------------------------------------------------------- aggregates
    def engagement_summary(self, engagement_id: str) -> dict[str, Any]:
        engagement = self.get_engagement(engagement_id)
        if not engagement:
            return {}
        findings = self.list_findings(engagement_id)
        runs = self.list_runs(engagement_id, limit=10)
        assets = self.list_assets(engagement_id)
        severity: dict[str, int] = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        bands = {"high": 0, "medium": 0, "low": 0}
        for finding in findings:
            if finding["status"] in ("false_positive", "duplicate"):
                continue
            severity[finding["severity"]] = severity.get(finding["severity"], 0) + 1
            bands[finding["confidence_band"]] = bands.get(finding["confidence_band"], 0) + 1
        last_run = runs[0] if runs else None
        delta = None
        if last_run and last_run.get("status") == "completed":
            prev = self.latest_previous_run(engagement_id, last_run["id"])
            if prev:
                current = self.fingerprints_for_run(last_run["id"])
                before = self.fingerprints_for_run(prev["id"])
                delta = {
                    "new": len(current - before),
                    "resolved": len(before - current),
                    "persistent": len(current & before),
                    "previous_run_id": prev["id"],
                }
        return {
            "engagement": engagement,
            "findings": findings[:200],
            "severity": severity,
            "bands": bands,
            "runs": runs,
            "assets": assets,
            "asset_counts": _count_by(assets, "kind"),
            "last_run": last_run,
            "delta": delta,
            "feedback": self.feedback_counts(),
            "verify": {
                "audit": self.verify_audit(engagement_id),
                "evidence": self.verify_evidence(engagement_id),
            },
        }

    def overall_stats(self) -> dict[str, Any]:
        return {
            "engagements": self.one("SELECT COUNT(*) AS n FROM engagements")["n"],  # type: ignore[index]
            "findings": self.one("SELECT COUNT(*) AS n FROM findings")["n"],  # type: ignore[index]
            "evidence": self.one("SELECT COUNT(*) AS n FROM evidence")["n"],  # type: ignore[index]
            "runs": self.one("SELECT COUNT(*) AS n FROM runs")["n"],  # type: ignore[index]
            "feedback": self.feedback_counts(),
        }

    def active_learning(self, engagement_id: str | None = None, limit: int = 25) -> list[dict[str, Any]]:
        sql = (
            "SELECT f.id, f.title, f.detector, f.severity, f.confidence, f.asset_id, a.value AS asset_value "
            "FROM findings f LEFT JOIN assets a ON a.id=f.asset_id WHERE f.status='open' "
            "AND f.confidence BETWEEN 0.30 AND 0.70 "
            "AND NOT EXISTS(SELECT 1 FROM feedback fb WHERE fb.finding_id=f.id)"
        )
        params: list[Any] = []
        if engagement_id:
            sql += " AND f.engagement_id=?"
            params.append(engagement_id)
        sql += " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        sql += "WHEN 'low' THEN 3 ELSE 4 END, f.confidence ASC LIMIT ?"
        params.append(limit)
        return self.query(sql, params)


def _count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "unknown")
        out[value] = out.get(value, 0) + 1
    return out
