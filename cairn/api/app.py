from __future__ import annotations

import asyncio
import json
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .. import __version__
from ..config import APP_NAME, Limits, default_db_path, parse_ports
from ..db import Database
from ..engine.orchestrator import execute_run
from ..intel.learning import learning_overview, maybe_retrain, train_confidence_model
from ..models import SafetyError
from ..net.ratelimit import CancellationToken
from ..reporting import render_html, render_json, render_markdown
from ..scope import ScopeError, ScopeSpec, validate_manifest, validate_scope

GUI_DIR = Path(__file__).resolve().parent.parent / "gui"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "testserver"}


class ScopeRuleIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    kind: Literal["domain", "ip", "cidr", "url"]
    value: str = Field(min_length=1, max_length=2048)
    mode: Literal["include", "exclude"] = "include"
    include_subdomains: bool = False


class EngagementIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=2, max_length=120)
    client: str = Field(default="", max_length=120)
    authorized_by: str = Field(min_length=2, max_length=160)
    authorization_ref: str = Field(min_length=3, max_length=240)
    expires_hours: int = Field(default=24, ge=1, le=4320)
    notes: str = Field(default="", max_length=4000)
    scope: list[ScopeRuleIn] = Field(min_length=1)
    ports: str = Field(default="", max_length=2000)
    full_ports: bool = False
    http_rate: float = Field(default=4.0, gt=0, le=50)
    port_rate: float = Field(default=250.0, gt=0, le=1000)
    max_hosts: int = Field(default=256, ge=1, le=4096)
    timeout: float = Field(default=8.0, ge=1, le=30)
    confirm_authorized: bool = False


class RunIn(BaseModel):
    mode: Literal["passive", "standard", "deep"] = "standard"
    online_intel: bool = True
    active_dns: bool = True


class FeedbackIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    verdict: Literal["confirmed", "false_positive", "accepted_risk", "uncertain", "duplicate"]
    analyst: str = Field(default="local-analyst", min_length=1, max_length=120)
    note: str = Field(default="", max_length=4000)


class RetrainIn(BaseModel):
    include_weak: bool = True


class RunManager:
    def __init__(self, db: Database):
        self.db = db
        self.tasks: dict[str, asyncio.Task[None]] = {}
        self.tokens: dict[str, CancellationToken] = {}

    def start(self, engagement_id: str, body: RunIn) -> str:
        engagement = self.db.get_engagement(engagement_id)
        if not engagement:
            raise KeyError("Engagement not found")
        if engagement["status"] != "active":
            raise ScopeError("Engagement is not active")
        active = self.db.one(
            "SELECT id FROM runs WHERE engagement_id=? AND status IN ('queued','running','cancelling')",
            (engagement_id,),
        )
        if active:
            raise RuntimeError(f"Run {active['id']} is already active for this engagement")
        config = {
            "online_intel": body.online_intel,
            "active_dns": body.active_dns,
            "source": "api",
        }
        run_id = self.db.create_run(engagement_id, body.mode, config)
        token = CancellationToken()
        self.tokens[run_id] = token
        task = asyncio.create_task(self._runner(run_id, token), name=f"cairn-{run_id}")
        self.tasks[run_id] = task
        task.add_done_callback(lambda _task, rid=run_id: self._cleanup(rid))
        return run_id

    async def _runner(self, run_id: str, token: CancellationToken) -> None:
        try:
            await execute_run(self.db, run_id, token=token)
        except asyncio.CancelledError:
            self.db.finish_run(run_id, status="cancelled", error="Server shutdown")
            raise
        except Exception:
            # execute_run records the failure in the run and audit trail.
            return

    def _cleanup(self, run_id: str) -> None:
        self.tasks.pop(run_id, None)
        self.tokens.pop(run_id, None)

    async def cancel(self, run_id: str) -> None:
        run = self.db.get_run(run_id)
        if not run:
            raise KeyError("Run not found")
        if run["status"] not in ("queued", "running", "cancelling"):
            return
        self.db.cancel_run(run_id)
        token = self.tokens.get(run_id)
        if token:
            token.cancel()

    async def shutdown(self) -> None:
        for run_id, task in list(self.tasks.items()):
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
            run = self.db.get_run(run_id)
            if run and run["status"] in ("queued", "running", "cancelling"):
                self.db.finish_run(run_id, status="cancelled", error="Server shutdown")


def create_app(
    *,
    db_path: str | Path | None = None,
    token: str | None = None,
    gui_dir: str | Path | None = None,
) -> FastAPI:
    api_token = token or secrets.token_urlsafe(24)
    static_dir = Path(gui_dir) if gui_dir else GUI_DIR

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db = Database(db_path or default_db_path())
        db.mark_interrupted_runs()
        app.state.db = db
        app.state.manager = RunManager(db)
        app.state.token = api_token
        yield
        await app.state.manager.shutdown()

    app = FastAPI(
        title="Cairn local API",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.token = api_token
    app.state.static_dir = static_dir
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        raw_host = request.headers.get("host") or ""
        host = (urlsplit(f"//{raw_host}").hostname or "").lower()
        if request.url.path.startswith("/api") and request.url.path != "/api/health":
            if host not in LOOPBACK_HOSTS:
                return JSONResponse({"detail": "Local-only API: unexpected Host header"}, status_code=421)
            supplied = request.headers.get("x-cairn-token", "")
            if not secrets.compare_digest(supplied, app.state.token):
                return JSONResponse({"detail": "Missing or invalid local access token"}, status_code=401)
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ScopeError)
    async def scope_error_handler(_request: Request, exc: ScopeError):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.exception_handler(SafetyError)
    async def safety_error_handler(_request: Request, exc: SafetyError):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(KeyError)
    async def key_error_handler(_request: Request, exc: KeyError):
        return JSONResponse({"detail": str(exc).strip("'\"")}, status_code=404)

    @app.exception_handler(RuntimeError)
    async def runtime_error_handler(_request: Request, exc: RuntimeError):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "name": APP_NAME, "version": __version__}

    @app.get("/", response_class=HTMLResponse)
    async def index():
        path = static_dir / "index.html"
        if not path.exists():
            return HTMLResponse("<h1>Cairn</h1><p>GUI assets are missing.</p>", status_code=500)
        nonce = secrets.token_urlsafe(18)
        content = path.read_text(encoding="utf-8")
        # The token is injected inside a <script> block. HTML escaping would
        # produce entities that script data does not decode, so use JSON for a
        # safe JavaScript string literal (tokens are URL-safe by construction).
        token_json = json.dumps(app.state.token).replace("</", "<\\/")
        content = content.replace("__CAIRN_TOKEN__", token_json)
        content = content.replace("__CAIRN_NONCE__", nonce)
        content = content.replace("__CAIRN_VERSION__", __version__)
        response = HTMLResponse(content)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        return response

    @app.get("/api/engagements")
    async def list_engagements():
        db: Database = app.state.db
        rows = db.list_engagements()
        for row in rows:
            row["manifest"] = json.loads(row.pop("manifest_json", "{}") or "{}")
            row["limits"] = json.loads(row.pop("limits_json", "{}") or "{}")
        return {"engagements": rows, "overall": db.overall_stats()}

    @app.post("/api/engagements", status_code=201)
    async def create_engagement(body: EngagementIn):
        if not body.confirm_authorized:
            raise ScopeError("Explicit authorization confirmation is required")
        scope_specs = [
            ScopeSpec(
                kind=item.kind,
                value=item.value,
                include_subdomains=item.include_subdomains,
                mode=item.mode,
            )
            for item in body.scope
        ]
        scope = validate_scope(scope_specs)
        now = datetime.now(UTC)
        try:
            allowed_ports = parse_ports("", all_ports=True) if body.full_ports else parse_ports(body.ports or None)
        except ValueError as exc:
            raise ScopeError(str(exc)) from exc
        if len(allowed_ports) > 2048 and not body.full_ports:
            raise ScopeError("Explicit port lists above 2,048 entries require full_ports=true")
        limits = Limits(
            http_rate=body.http_rate,
            port_rate=body.port_rate,
            timeout=body.timeout,
            max_hosts=body.max_hosts,
            allowed_ports=tuple(allowed_ports),
            full_ports=body.full_ports,
        )
        starts = now.isoformat(timespec="seconds")
        expires = (now + timedelta(hours=body.expires_hours)).isoformat(timespec="seconds")
        validate_manifest(
            authorized_by=body.authorized_by,
            authorization_ref=body.authorization_ref,
            starts_at=starts,
            expires_at=expires,
            scope=scope,
        )
        db: Database = app.state.db
        engagement_id = db.create_engagement(
            name=body.name,
            client=body.client,
            authorized_by=body.authorized_by,
            authorization_ref=body.authorization_ref,
            starts_at=starts,
            expires_at=expires,
            scope=scope,
            limits=limits.to_dict(),
            notes=body.notes,
            actor=body.authorized_by,
        )
        return db.get_engagement(engagement_id)

    @app.get("/api/engagements/{engagement_id}")
    async def get_engagement(engagement_id: str):
        db: Database = app.state.db
        summary = db.engagement_summary(engagement_id)
        if not summary:
            raise KeyError("Engagement not found")
        return summary

    @app.post("/api/engagements/{engagement_id}/runs")
    async def start_run(engagement_id: str, body: RunIn):
        manager: RunManager = app.state.manager
        run_id = manager.start(engagement_id, body)
        return app.state.db.get_run(run_id)

    @app.get("/api/engagements/{engagement_id}/findings")
    async def list_findings(
        engagement_id: str,
        min_severity: str | None = None,
        status: str | None = None,
        band: str | None = None,
        run_id: str | None = None,
        q: str | None = None,
    ):
        db: Database = app.state.db
        return {
            "findings": db.list_findings(
                engagement_id,
                min_severity=min_severity,
                status=status,
                band=band,
                run_id=run_id,
                query_text=q,
            )
        }

    @app.get("/api/engagements/{engagement_id}/assets")
    async def list_assets(engagement_id: str):
        return {"assets": app.state.db.list_assets(engagement_id)}

    @app.get("/api/engagements/{engagement_id}/runs")
    async def list_runs(engagement_id: str):
        return {"runs": app.state.db.list_runs(engagement_id)}

    @app.post("/api/engagements/{engagement_id}/revoke")
    async def revoke_engagement(engagement_id: str, request: Request):
        db: Database = app.state.db
        if not db.get_engagement(engagement_id):
            raise KeyError("Engagement not found")
        db.set_engagement_status(engagement_id, "revoked", actor="api")
        return {"status": "revoked"}

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str, after: int = 0):
        db: Database = app.state.db
        run = db.get_run(run_id)
        if not run:
            raise KeyError("Run not found")
        return {
            "run": run,
            "events": db.list_events(run_id, after_id=after),
            "findings": db.findings_for_run(run_id),
        }

    @app.get("/api/runs/{run_id}/events")
    async def get_events(run_id: str, after: int = 0):
        return {"events": app.state.db.list_events(run_id, after_id=after)}

    @app.post("/api/runs/{run_id}/cancel")
    async def cancel_run(run_id: str):
        await app.state.manager.cancel(run_id)
        return {"status": "cancelling"}

    @app.get("/api/findings/{finding_id}")
    async def get_finding(finding_id: str):
        finding = app.state.db.get_finding(finding_id)
        if not finding:
            raise KeyError("Finding not found")
        return finding

    @app.post("/api/findings/{finding_id}/feedback")
    async def feedback(finding_id: str, body: FeedbackIn):
        db: Database = app.state.db
        db.add_feedback(finding_id, body.verdict, body.analyst, body.note)
        learning = None
        if body.verdict in ("confirmed", "false_positive", "accepted_risk"):
            learning = await asyncio.to_thread(maybe_retrain, db)
        return {"status": "recorded", "learning": learning}

    @app.get("/api/learning")
    async def learning(engagement_id: str | None = None):
        db: Database = app.state.db
        overview = learning_overview(db)
        if engagement_id:
            overview["active_learning"] = db.active_learning(engagement_id)
        return overview

    @app.post("/api/learning/retrain")
    async def retrain(body: RetrainIn):
        result = await asyncio.to_thread(train_confidence_model, app.state.db, include_weak=body.include_weak)
        return result

    @app.get("/api/audit")
    async def audit(engagement_id: str):
        db: Database = app.state.db
        events = db.list_audit(engagement_id)
        ok, count, bad = db.verify_audit(engagement_id)
        evidence_ok, evidence_count, evidence_bad = db.verify_evidence(engagement_id)
        return {
            "events": events,
            "verification": {
                "audit_valid": ok,
                "audit_events": count,
                "audit_failure_id": bad,
                "evidence_valid": evidence_ok,
                "evidence_records": evidence_count,
                "evidence_failure_id": evidence_bad,
            },
        }

    @app.get("/api/report/{run_id}")
    async def report(run_id: str, format: Literal["html", "md", "json"] = "html"):
        db: Database = app.state.db
        if not db.get_run(run_id):
            raise KeyError("Run not found")
        if format == "html":
            content, media, ext = render_html(db, run_id), "text/html; charset=utf-8", "html"
        elif format == "md":
            content, media, ext = render_markdown(db, run_id), "text/markdown; charset=utf-8", "md"
        else:
            content, media, ext = render_json(db, run_id), "application/json", "json"
        return Response(
            content,
            media_type=media,
            headers={"Content-Disposition": f'attachment; filename="cairn-{run_id}.{ext}"'},
        )

    return app
