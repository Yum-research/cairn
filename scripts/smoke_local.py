"""Local-only end-to-end test fixture. Never binds a public interface."""

from __future__ import annotations

import asyncio
import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cairn.config import Limits
from cairn.db import Database
from cairn.engine.orchestrator import execute_run
from cairn.scope import ScopeSpec, validate_manifest, validate_scope


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "CairnDemo/1.4.2"

    def log_message(self, format, *args):  # noqa: A002
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            body = (
                b"<html><head><title>Cairn Demo Portal</title></head><body>"
                b"<h1>Welcome</h1><script src='/static/jquery-1.12.4.min.js'></script>"
                b"<a href='/login'>Sign in</a></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "CairnDemo/1.4.2")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.send_header("Set-Cookie", "session=supersecretvalue; Path=/")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/.git/HEAD":
            self._send(200, "text/plain", b"ref: refs/heads/main\n")
        elif path == "/.git/config":
            self._send(200, "text/plain", b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n")
        elif path == "/.env":
            self._send(
                200,
                "text/plain",
                b"DATABASE_URL=postgres://admin:hunter2@db/app\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nSECRET_KEY=abc123\n",
            )
        elif path == "/backup/":
            self._send(200, "text/html", b"<html><title>Index of /backup</title><body>Index of /backup</body></html>")
        elif path == "/admin":
            self._send(200, "text/html", b"<html><title>Admin Login</title><body><form>Password <input name=password></form></body></html>")
        elif path == "/robots.txt":
            self._send(200, "text/plain", b"User-agent: *\nDisallow: /admin\nDisallow: /backup/\n")
        elif path == "/.well-known/security.txt":
            self._send(200, "text/plain", b"Contact: mailto:security@example.invalid\nExpires: 2027-01-01T00:00:00Z\n")
        elif path == "/health":
            self._send(200, "text/plain", b"ok")
        else:
            self._send(404, "text/html", b"<html><title>Not Found</title>Not Found</body></html>")

    def _send(self, status: int, ctype: str, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


async def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print("demo port", port)
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    db = Database(tmp)
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    scope = validate_scope([ScopeSpec(kind="ip", value="127.0.0.1")])
    limits = Limits(allowed_ports=(port,), http_rate=100, port_rate=100, timeout=5)
    validate_manifest(
        authorized_by="Local Operator",
        authorization_ref="LOCAL-TEST-ONLY",
        starts_at=now.isoformat(),
        expires_at=(now + timedelta(hours=2)).isoformat(),
        scope=scope,
    )
    eng = db.create_engagement(
        name="Local demo",
        client="Self",
        authorized_by="Local Operator",
        authorization_ref="LOCAL-TEST-ONLY",
        starts_at=now.isoformat(),
        expires_at=(now + timedelta(hours=2)).isoformat(),
        scope=scope,
        limits=limits.to_dict(),
    )
    print("engagement", eng)
    run_id = db.create_run(eng, "standard", {"online_intel": False, "active_dns": False})
    print("run", run_id)
    try:
        stats = await execute_run(db, run_id)
        print(json.dumps(stats, indent=2, default=str)[:6000])
    except Exception:
        import traceback

        traceback.print_exc()
    finally:
        server.shutdown()
    findings = db.list_findings(eng)
    print("FINDINGS", len(findings))
    for finding in findings:
        print(f"- {finding['severity']:8} {finding['confidence']:.3f} {finding['detector']}: {finding['title']} @ {finding['asset_value']}")
    run = db.get_run(run_id)
    print("RUN STATUS", run["status"], "COVERAGE", run["coverage"], "ERROR", run["error"])
    print("AUDIT", db.verify_audit(eng), "EVIDENCE", db.verify_evidence(eng))
    print("DB", tmp)


if __name__ == "__main__":
    asyncio.run(main())
