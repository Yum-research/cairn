from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any

from ..config import PORT_SERVICES, SENSITIVE_PORTS, WEB_PORTS
from ..models import SafetyError
from .ratelimit import CancellationToken, HostRateLimiter

_BANNER_PATTERNS = (
    (re.compile(r"^SSH-([\d.]+)-(\S+)", re.I), "ssh"),
    (re.compile(r"^220[ -].*?(?:SMTP|ESMTP|Mail)", re.I), "smtp"),
    (re.compile(r"^220[ -].*?FTP", re.I), "ftp"),
    (re.compile(r"^HTTP/\d", re.I), "http"),
    (re.compile(r"^RFB\s", re.I), "vnc"),
    (re.compile(r"^\+OK", re.I), "pop3"),
    (re.compile(r"^\* OK", re.I), "imap"),
)


@dataclass
class PortResult:
    port: int
    open: bool
    service: str | None
    banner: str | None = None
    latency_ms: int | None = None
    tls: dict[str, Any] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "open": self.open,
            "service": self.service,
            "banner": self.banner,
            "latency_ms": self.latency_ms,
            "tls": self.tls,
        }


@dataclass
class PortScanSummary:
    host: str
    ports: list[PortResult] = field(default_factory=list)
    attempted: int = 0
    filtered: int = 0

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.open]


def guess_service(port: int, banner: str | None = None) -> str | None:
    if banner:
        for pattern, name in _BANNER_PATTERNS:
            if pattern.search(banner.strip()):
                return name
    return PORT_SERVICES.get(port)


async def _banner(reader: asyncio.StreamReader, timeout: float = 0.9) -> str | None:
    try:
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
    except (TimeoutError, OSError, asyncio.IncompleteReadError):
        return None
    if not data:
        return None
    return data.decode("utf-8", "replace").strip()[:400]


async def scan_ports(
    ip: str,
    ports: list[int] | tuple[int, ...],
    *,
    rate: float = 250,
    concurrency: int = 300,
    timeout: float = 3.0,
    token: CancellationToken | None = None,
    banner_timeout: float = 0.9,
) -> PortScanSummary:
    """TCP connect scan with a per-host token bucket.

    This is deliberately a connect scan: no raw sockets, no privileges, no
    crafted packets. It is slower than a SYN scan but portable and honest
    about its limits (filtered ports are not distinguished perfectly from
    closed ports on every stack).
    """

    ports = [int(p) for p in ports]
    if not ports:
        return PortScanSummary(host=ip)
    if len(ports) > 65535:
        raise SafetyError("Port list exceeds 65,535 entries")
    if concurrency < 1 or rate <= 0:
        raise SafetyError("Invalid scan rate or concurrency")
    summary = PortScanSummary(host=ip, attempted=len(ports))
    limiter = HostRateLimiter(rate)
    queue: asyncio.Queue[int] = asyncio.Queue()
    for port in ports:
        queue.put_nowait(port)
    results: list[PortResult] = []
    lock = asyncio.Lock()

    async def worker() -> None:
        while not queue.empty():
            if token and token.cancelled:
                return
            port = queue.get_nowait()
            try:
                await limiter.acquire(ip)
                started = time.perf_counter()
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=timeout
                    )
                except (TimeoutError, OSError) as exc:
                    async with lock:
                        if isinstance(exc, OSError):
                            summary.filtered += 1
                    continue
                latency = int((time.perf_counter() - started) * 1000)
                banner = None
                if port not in WEB_PORTS and port not in (443, 8443, 9443, 465, 993, 995, 636):
                    banner = await _banner(reader, banner_timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
                service = guess_service(port, banner)
                result = PortResult(
                    port=port,
                    open=True,
                    service=service,
                    banner=banner,
                    latency_ms=latency,
                )
                async with lock:
                    results.append(result)
            finally:
                queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(min(concurrency, len(ports)))]
    await asyncio.gather(*workers, return_exceptions=False)
    summary.ports = sorted(results, key=lambda p: p.port)
    return summary


def is_sensitive_port(port: int) -> bool:
    return port in SENSITIVE_PORTS


def is_web_port(port: int, service: str | None = None) -> bool:
    return port in WEB_PORTS or service in ("http", "https", "http-proxy", "https-alt") or port in (
        3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000, 18080, 18081,
    )
