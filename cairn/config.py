from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

APP_NAME = "Cairn"
APP_TAGLINE = "Evidence-first attack surface intelligence"
USER_AGENT = "CairnRecon/0.1 (+authorized security assessment; contact engagement owner)"
DEFAULT_DB = ".cairn/cairn.db"
MAX_EXCERPT = 1600
MAX_HTTP_BODY = 512 * 1024
MAX_EVIDENCE_PER_RUN = 4000

# Conservative defaults. Engagements may lower these, but cannot raise the
# hard ceilings without an explicit operator flag (documented in ETHICS.md).
DEFAULT_HTTP_RATE = 4.0          # requests / second / host
DEFAULT_PORT_RATE = 250.0        # connection attempts / second / host
DEFAULT_DNS_RATE = 20.0          # queries / second / host
DEFAULT_HTTP_CONCURRENCY = 6
DEFAULT_TIMEOUT = 8.0

TOP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 162, 389, 443,
    445, 465, 514, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1883, 2049, 2181,
    2375, 2376, 3000, 3306, 3389, 4444, 5000, 5432, 5601, 5672, 5900, 5984,
    6379, 6443, 7001, 8000, 8008, 8080, 8081, 8443, 8500, 8888, 9000, 9090,
    9200, 9300, 9443, 10000, 11211, 15672, 27017, 27018, 50000,
)

WEB_PORTS: frozenset[int] = frozenset(
    {80, 81, 443, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8443, 8500, 8888, 9000, 9090, 9443, 10000, 15672, 18080, 18081}
)

PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 1883: "mqtt", 2049: "nfs",
    2181: "zookeeper", 2375: "docker", 3000: "http", 3306: "mysql",
    3389: "rdp", 5000: "http", 5432: "postgresql", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 5984: "couchdb", 6379: "redis", 6443: "kubernetes",
    8000: "http", 8080: "http-proxy", 8081: "http", 8443: "https-alt",
    8888: "http", 9000: "http", 9090: "http", 9200: "elasticsearch",
    9300: "elasticsearch", 11211: "memcached", 15672: "rabbitmq",
    27017: "mongodb", 27018: "mongodb",
}

# Ports that are useful to know about but are higher impact. They are never
# auto-classified as vulnerable; only as exposed services with evidence.
SENSITIVE_PORTS: frozenset[int] = frozenset(
    {23, 135, 139, 445, 1433, 2375, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017}
)

SAFE_MODES = ("passive", "standard", "deep")


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def new_id(prefix: str, n: int = 10) -> str:
    return f"{prefix}_{secrets.token_hex(n // 2)}"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def default_db_path() -> Path:
    override = os.environ.get("CAIRN_DB")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.cwd() / DEFAULT_DB).resolve()


def data_path(name: str) -> Path:
    return Path(__file__).resolve().parent / "data" / name


def parse_ports(spec: str | None = None, *, all_ports: bool = False) -> tuple[int, ...]:
    """Parse '80,443,8000-8100'. Returns a sorted, deduplicated tuple."""
    if all_ports or (spec or "").strip().lower() in ("all", "*", "1-65535"):
        return tuple(range(1, 65536))
    if not spec or not spec.strip():
        return TOP_PORTS
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise ValueError(f"Invalid port range: {chunk}") from exc
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Port range out of bounds: {chunk}")
            if end - start > 4096:
                raise ValueError(f"Port range too wide ({chunk}); use --all-ports for a full scan")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise ValueError(f"Invalid port: {chunk}") from exc
            if not 1 <= port <= 65535:
                raise ValueError(f"Port out of bounds: {port}")
            ports.add(port)
    if not ports:
        raise ValueError("No valid ports supplied")
    return tuple(sorted(ports))


@dataclass(frozen=True)
class Limits:
    http_rate: float = DEFAULT_HTTP_RATE
    port_rate: float = DEFAULT_PORT_RATE
    dns_rate: float = DEFAULT_DNS_RATE
    http_concurrency: int = DEFAULT_HTTP_CONCURRENCY
    timeout: float = DEFAULT_TIMEOUT
    max_hosts: int = 256
    max_content_paths: int = 36
    allowed_ports: tuple[int, ...] = TOP_PORTS
    max_evidence: int = MAX_EVIDENCE_PER_RUN
    full_ports: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "http_rate": self.http_rate,
            "port_rate": self.port_rate,
            "dns_rate": self.dns_rate,
            "http_concurrency": self.http_concurrency,
            "timeout": self.timeout,
            "max_hosts": self.max_hosts,
            "max_content_paths": self.max_content_paths,
            "allowed_ports": list(self.allowed_ports),
            "max_evidence": self.max_evidence,
            "full_ports": self.full_ports,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> Limits:
        raw = raw or {}
        return cls(
            http_rate=float(raw.get("http_rate", DEFAULT_HTTP_RATE)),
            port_rate=float(raw.get("port_rate", DEFAULT_PORT_RATE)),
            dns_rate=float(raw.get("dns_rate", DEFAULT_DNS_RATE)),
            http_concurrency=int(raw.get("http_concurrency", DEFAULT_HTTP_CONCURRENCY)),
            timeout=float(raw.get("timeout", DEFAULT_TIMEOUT)),
            max_hosts=int(raw.get("max_hosts", 256)),
            max_content_paths=int(raw.get("max_content_paths", 36)),
            allowed_ports=tuple(int(p) for p in raw.get("allowed_ports", TOP_PORTS)),
            max_evidence=int(raw.get("max_evidence", MAX_EVIDENCE_PER_RUN)),
            full_ports=bool(raw.get("full_ports", False)),
        )


@dataclass
class AppConfig:
    db_path: Path = field(default_factory=default_db_path)
    host: str = "127.0.0.1"
    port: int = 8787
    token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    open_browser: bool = False
