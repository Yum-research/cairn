from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from cairn.config import Limits
from cairn.db import Database
from cairn.scope import ScopeSpec, validate_manifest, validate_scope


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    return Database(tmp_path / "cairn-test.db")


def make_engagement(
    db: Database,
    *,
    scope: list[ScopeSpec] | None = None,
    allowed_ports: tuple[int, ...] = (80, 443, 8080),
    name: str = "Test engagement",
    expires_hours: int = 4,
):
    now = datetime.now(UTC)
    specs = scope or [ScopeSpec(kind="ip", value="127.0.0.1")]
    resolved = validate_scope(specs)
    starts = now.isoformat(timespec="seconds")
    expires = (now + timedelta(hours=expires_hours)).isoformat(timespec="seconds")
    validate_manifest(
        authorized_by="Test Operator",
        authorization_ref="TEST-AUTH-001",
        starts_at=starts,
        expires_at=expires,
        scope=resolved,
    )
    limits = Limits(
        allowed_ports=allowed_ports,
        http_rate=100,
        port_rate=100,
        timeout=5,
        max_hosts=32,
    )
    engagement_id = db.create_engagement(
        name=name,
        client="Self",
        authorized_by="Test Operator",
        authorization_ref="TEST-AUTH-001",
        starts_at=starts,
        expires_at=expires,
        scope=resolved,
        limits=limits.to_dict(),
    )
    return db.get_engagement(engagement_id)


class LabHandler(BaseHTTPRequestHandler):
    """Small loopback-only fixture. It never contacts a real target."""

    server_version = "CairnTest/1.0"

    def log_message(self, format, *args):  # noqa: A002
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._send(
                200,
                "text/html",
                b"<html><head><title>Cairn Test Portal</title></head><body>"
                b"<h1>Welcome</h1><a href='/login'>Sign in</a></body></html>",
                extra={"Set-Cookie": "session=supersecretvalue; Path=/"},
            )
        elif path == "/.git/HEAD":
            self._send(200, "text/plain", b"ref: refs/heads/main\n")
        elif path == "/.env":
            self._send(
                200,
                "text/plain",
                b"DATABASE_URL=postgres://admin:hunter2@db/app\n"
                b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nSECRET_KEY=abc123\n",
            )
        elif path == "/admin":
            self._send(
                200,
                "text/html",
                b"<html><title>Admin Login</title><body><form>"
                b"Password <input name=password></form></body></html>",
            )
        elif path == "/robots.txt":
            self._send(200, "text/plain", b"User-agent: *\nDisallow: /admin\n")
        else:
            self._send(404, "text/html", b"<html><title>Not Found</title></html>")

    def _send(self, status: int, content_type: str, body: bytes, extra: dict[str, str] | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def lab_server() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def wait_for_poll(predicate, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()
