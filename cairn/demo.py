from __future__ import annotations

import json
import os
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def _openssl_binary() -> str | None:
    """Find OpenSSL without assuming it is on PATH (common on Windows)."""
    found = shutil.which("openssl")
    if found:
        return found
    for candidate in (
        Path(r"C:\Program Files\Git\usr\bin\openssl.exe"),
        Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe"),
        Path("/usr/bin/openssl"),
        Path("/opt/homebrew/bin/openssl"),
    ):
        if candidate.exists():
            return str(candidate)
    return None


def ensure_demo_cert(cert_path: Path) -> tuple[Path, Path] | None:
    """Generate a short-lived loopback certificate for the demo only.

    The key never leaves the local machine and is excluded from version
    control. If OpenSSL is unavailable, the demo simply runs without HTTPS.
    """
    key_path = cert_path.with_name("demo_key.pem")
    if cert_path.exists() and key_path.exists():
        return cert_path, key_path
    binary = _openssl_binary()
    if not binary:
        return None
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        binary,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-nodes",
        "-days",
        "30",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        os.chmod(key_path, 0o600)
    except (OSError, subprocess.SubprocessError):
        for path in (cert_path, key_path):
            path.unlink(missing_ok=True)
        return None
    return cert_path, key_path


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "CairnDemo/1.4.2"
    sys_version = ""

    def log_message(self, format, *args):  # noqa: A002
        return

    def do_HEAD(self):
        self.do_GET(head=True)

    def do_GET(self, head: bool = False):
        path = urlsplit(self.path).path
        variant = getattr(self.server, "variant", "portal")
        host = self.headers.get("Host", "127.0.0.1")
        scheme = "https" if getattr(self.server, "is_tls", False) else "http"
        base = f"{scheme}://{host}"
        title = "Cairn Demo Portal" if variant == "portal" else "Legacy Admin Console"
        if path == "/":
            self._send(
                200,
                "text/html; charset=utf-8",
                f"""<!doctype html><html><head><title>{title}</title></head>
<body><h1>{title}</h1><p>Local demonstration environment. No real customer data.</p>
<script src="/static/jquery-1.12.4.min.js"></script>
<a href="/login">Sign in</a> · <a href="/admin">Admin</a>
</body></html>""".encode(),
                head=head,
            )
        elif path == "/.git/HEAD":
            self._send(200, "text/plain", b"ref: refs/heads/main\n", head=head)
        elif path == "/.git/config":
            self._send(
                200,
                "text/plain",
                b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://git.example.invalid/demo.git\n",
                head=head,
            )
        elif path == "/.env":
            self._send(
                200,
                "text/plain",
                b"DATABASE_URL=postgres://demo:supersecretvalue@db.internal/demo\n"
                b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                b"SECRET_KEY=demo-secret-value-123456\nSMTP_PASSWORD=not-a-real-password\n",
                head=head,
            )
        elif path in ("/backup/", "/backups/", "/files/", "/uploads/"):
            self._send(
                200,
                "text/html",
                f"<html><head><title>Index of {path}</title></head><body><h1>Index of {path}</h1>"
                "<a href='customer-export.csv'>customer-export.csv</a><br><a href='archive.zip'>archive.zip</a>"
                "</body></html>".encode(),
                head=head,
            )
        elif path in ("/admin", "/login", "/wp-login.php"):
            self._send(
                200,
                "text/html",
                b"<html><head><title>Admin Login</title></head><body><h1>Administrator sign in</h1>"
                b"<form><label>Username <input name='username'></label><label>Password <input name='password' type='password'></label>"
                b"<button>Log in</button></form></body></html>",
                head=head,
            )
        elif path == "/server-status":
            self._send(
                200,
                "text/html",
                b"<html><head><title>Apache Server Status</title></head><body>"
                b"<h1>Apache Server Status for 127.0.0.1</h1><p>Server uptime: 12 days</p>"
                b"<table><tr><td>GET /admin HTTP/1.1</td><td>127.0.0.1</td></tr></table></body></html>",
                head=head,
            )
        elif path == "/actuator/env":
            payload = {
                "activeProfiles": ["prod"],
                "propertySources": [
                    {
                        "name": "applicationConfig",
                        "properties": {
                            "spring.datasource.password": {"value": "demo-db-password"},
                            "demo.api.key": {"value": "demo-api-key-value"},
                        },
                    }
                ],
            }
            self._send(200, "application/json", json.dumps(payload).encode(), head=head)
        elif path == "/actuator":
            self._send(
                200,
                "application/json",
                b'{"_links":{"self":{"href":"/actuator"},"env":{"href":"/actuator/env"}}}',
                head=head,
            )
        elif path == "/swagger-ui.html":
            self._send(
                200,
                "text/html",
                b"<html><head><title>Swagger UI</title></head><body><div id='swagger-ui'>SwaggerUIBundle</div></body></html>",
                head=head,
            )
        elif path == "/config.json":
            self._send(
                200,
                "application/json",
                b'{"api_endpoint":"/api/v1","public_key":"demo","feature_flags":{"billing":true}}',
                head=head,
            )
        elif path == "/metrics":
            self._send(
                200,
                "text/plain",
                b"# HELP http_requests_total Total requests\n# TYPE http_requests_total counter\n"
                b'http_requests_total{path="/admin",status="200"} 42\n',
                head=head,
            )
        elif path == "/robots.txt":
            self._send(
                200,
                "text/plain",
                b"User-agent: *\nDisallow: /admin\nDisallow: /backup/\nDisallow: /actuator\nSitemap: "
                + f"{base}/sitemap.xml\n".encode(),
                head=head,
            )
        elif path == "/sitemap.xml":
            self._send(
                200,
                "application/xml",
                (
                    "<?xml version='1.0'?><urlset>"
                    f"<url><loc>{base}/</loc></url>"
                    f"<url><loc>{base}/admin</loc></url>"
                    f"<url><loc>{base}/docs</loc></url>"
                    "</urlset>"
                ).encode(),
                head=head,
            )
        elif path == "/.well-known/security.txt":
            self._send(
                200,
                "text/plain",
                b"Contact: mailto:security@cairn.invalid\nExpires: 2027-01-01T00:00:00Z\nPreferred-Languages: en\n",
                head=head,
            )
        elif path == "/health":
            self._send(200, "text/plain", b"ok\n", head=head)
        elif path == "/api":
            self._send(200, "application/json", b'{"version":"v1","status":"ok"}', head=head)
        else:
            self._send(
                404,
                "text/html",
                b"<html><head><title>Not Found</title></head><body><h1>404 Not Found</h1></body></html>",
                head=head,
            )

    def _send(self, status: int, content_type: str, body: bytes, *, head: bool = False):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Set-Cookie", "demo_session=demo-session-value; Path=/; HttpOnly")
        self.send_header("Referrer-Policy", "unsafe-url")
        self.end_headers()
        if not head:
            self.wfile.write(body)


class DemoLab:
    """Two HTTP listeners and one self-signed HTTPS listener, loopback only."""

    def __init__(
        self,
        ports: tuple[int, int, int] = (18080, 18081, 9443),
        *,
        cert_dir: str | Path | None = None,
    ):
        self.requested_ports = ports
        self.cert_dir = Path(cert_dir) if cert_dir else Path.cwd() / ".cairn"
        self.servers: list[ThreadingHTTPServer] = []
        self.threads: list[threading.Thread] = []
        self.ports: list[int] = []
        self.tls_port: int | None = None
        self.tls_skipped: str | None = None

    def start(self) -> DemoLab:
        try:
            for index, requested in enumerate(self.requested_ports[:2]):
                port = self._listen(requested, variant="portal" if index == 0 else "legacy")
                self.ports.append(port)
            pair = ensure_demo_cert(self.cert_dir / "demo_cert.pem")
            if pair:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(pair[0], pair[1])
                self.tls_port = self._listen(
                    self.requested_ports[2] if len(self.requested_ports) > 2 else 9443,
                    variant="portal",
                    tls=context,
                )
                self.ports.append(self.tls_port)
            else:
                self.tls_skipped = "OpenSSL is unavailable; HTTPS demo listener skipped"
        except Exception:
            self.stop()
            raise
        return self

    def _listen(self, requested: int, *, variant: str, tls: ssl.SSLContext | None = None) -> int:
        """Bind the requested port, falling back to an ephemeral one if busy."""
        try:
            server = ThreadingHTTPServer(("127.0.0.1", requested), DemoHandler)
        except OSError:
            server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
        try:
            server.daemon_threads = True
            server.variant = variant  # type: ignore[attr-defined]
            server.is_tls = tls is not None  # type: ignore[attr-defined]
            if tls is not None:
                server.socket = tls.wrap_socket(server.socket, server_side=True)
        except Exception:
            server.server_close()
            raise
        self._serve(server)
        return int(server.server_address[1])

    def _serve(self, server: ThreadingHTTPServer) -> None:
        self.servers.append(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.threads.append(thread)

    def stop(self) -> None:
        for server in self.servers:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass
        self.servers.clear()
        self.threads.clear()
        self.ports.clear()

    def summary(self) -> dict[str, Any]:
        return {"ports": self.ports, "tls_port": self.tls_port}

    def __enter__(self) -> DemoLab:
        return self.start()

    def __exit__(self, *args: Any) -> None:
        self.stop()
