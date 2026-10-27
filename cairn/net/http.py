from __future__ import annotations

import asyncio
import re
import ssl
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from ..config import MAX_HTTP_BODY, USER_AGENT
from ..redact import redact_text, redact_url
from ..scope import ScopeGuard
from .ratelimit import CancellationToken, HostRateLimiter

_TEXTUAL = re.compile(r"(?i)^(text/|application/(json|xml|javascript|xhtml|x-www-form-urlencoded)|image/svg)")
_CHARSET = re.compile(r"charset=([\w-]+)", re.I)


@dataclass
class HTTPResult:
    url: str
    status: int | None = None
    headers: list[list[str]] = field(default_factory=list)
    body: str = ""
    raw: bytes = b""
    truncated: bool = False
    content_type: str = ""
    elapsed_ms: int | None = None
    redirects: list[str] = field(default_factory=list)
    final_url: str = ""
    tls_verified: bool = True
    error: str | None = None
    scope_blocked_redirect: str | None = None

    @property
    def header_map(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for key, value in self.headers:
            out.setdefault(key.lower(), []).append(value)
        return out

    def header(self, name: str) -> str | None:
        values = self.header_map.get(name.lower())
        return values[0] if values else None

    def to_meta(self) -> dict[str, Any]:
        return {
            "url": redact_url(self.url),
            "final_url": redact_url(self.final_url),
            "status": self.status,
            "content_type": self.content_type,
            "content_length": len(self.raw),
            "truncated": self.truncated,
            "elapsed_ms": self.elapsed_ms,
            "redirects": [redact_url(url) for url in self.redirects],
            "tls_verified": self.tls_verified,
            "error": redact_text(self.error or "", 500) or None,
            "headers": {
                k: [redact_text(v, 500) for v in values]
                for k, values in self.header_map.items()
            },
        }


class SafeHTTPClient:
    def __init__(
        self,
        guard: ScopeGuard,
        *,
        timeout: float = 8.0,
        rate: float = 4.0,
        claim_token: CancellationToken | None = None,
        max_bytes: int = MAX_HTTP_BODY,
    ):
        self.guard = guard
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.rate = HostRateLimiter(rate)
        self.token = claim_token
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5",
            "Accept-Language": "en-US,en;q=0.7",
            "Connection": "close",
        }
        limits = httpx.Limits(max_connections=24, max_keepalive_connections=8, keepalive_expiry=10)
        self._client = httpx.AsyncClient(
            verify=True,
            follow_redirects=False,
            timeout=httpx.Timeout(timeout),
            headers=headers,
            limits=limits,
        )
        self._client_unverified = httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=httpx.Timeout(timeout),
            headers=headers,
            limits=limits,
        )

    async def close(self) -> None:
        await self._client.aclose()
        await self._client_unverified.aclose()

    async def get(
        self,
        url: str,
        *,
        max_bytes: int | None = None,
        allow_redirects: bool = True,
        max_redirects: int = 3,
        extra_headers: dict[str, str] | None = None,
    ) -> HTTPResult:
        current = url
        result = HTTPResult(url=url, final_url=url)
        redirects: list[str] = []
        for _step in range(max_redirects + 1):
            if self.token and self.token.cancelled:
                result.error = "cancelled"
                return result
            try:
                prepared = await self.guard.check_url(current)
            except PermissionError as exc:
                result.error = f"scope: {exc}"
                result.scope_blocked_redirect = current
                break
            host = prepared.host
            await self.rate.acquire(host)
            started = time.perf_counter()
            try:
                resp, raw, truncated, verified = await self._fetch_once(
                    current, max_bytes=max_bytes or self.max_bytes, extra_headers=extra_headers
                )
            except httpx.HTTPError as exc:
                result.error = _short_error(exc)
                result.elapsed_ms = int((time.perf_counter() - started) * 1000)
                break
            result.status = resp.status_code
            result.headers = [[k, v] for k, v in resp.headers.multi_items()]
            result.content_type = resp.headers.get("content-type", "")
            result.raw = raw
            result.truncated = truncated
            result.tls_verified = verified
            result.elapsed_ms = int((time.perf_counter() - started) * 1000)
            result.final_url = current
            result.body = _decode(raw, result.content_type)
            location = resp.headers.get("location")
            if allow_redirects and resp.status_code in (301, 302, 303, 307, 308) and location:
                target = urljoin(current, location)
                redirects.append(target)
                if len(redirects) > max_redirects:
                    break
                current = target
                continue
            break
        result.redirects = redirects
        return result

    async def _fetch_once(
        self,
        url: str,
        *,
        max_bytes: int,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[httpx.Response, bytes, bool, bool]:
        client = self._client
        try:
            resp, raw, truncated = await self._consume(client, url, max_bytes, extra_headers)
            return resp, raw, truncated, True
        except httpx.ConnectError as exc:
            if urlsplit(url).scheme != "https" or not _is_tls_error(exc):
                raise
            client = self._client_unverified
        resp, raw, truncated = await self._consume(client, url, max_bytes, extra_headers)
        return resp, raw, truncated, False

    async def _consume(
        self,
        client: httpx.AsyncClient,
        url: str,
        max_bytes: int,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[httpx.Response, bytes, bool]:
        req = client.build_request("GET", url, headers=extra_headers)
        resp = await client.send(req, stream=True)
        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            is_text = bool(_TEXTUAL.search(resp.headers.get("content-type", "")))
            cap = max_bytes if is_text else min(max_bytes, 32_768)
            async for chunk in resp.aiter_bytes():
                if not chunk:
                    continue
                remaining = cap - total
                if remaining <= 0:
                    truncated = True
                    break
                chunks.append(chunk[:remaining])
                total += min(len(chunk), remaining)
                if total >= cap:
                    truncated = True
                    break
        finally:
            await resp.aclose()
        return resp, b"".join(chunks), truncated

    async def head(self, url: str) -> HTTPResult:
        prepared = await self.guard.check_url(url)
        await self.rate.acquire(prepared.host)
        try:
            resp = await self._client.head(url)
        except httpx.HTTPError as exc:
            return HTTPResult(url=url, error=_short_error(exc))
        return HTTPResult(
            url=url,
            status=resp.status_code,
            headers=[[k, v] for k, v in resp.headers.multi_items()],
            elapsed_ms=None,
            final_url=str(resp.url),
        )

    async def __aenter__(self) -> SafeHTTPClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await asyncio.shield(self.close())


def _decode(raw: bytes, content_type: str) -> str:
    match = _CHARSET.search(content_type)
    encoding = match.group(1) if match else "utf-8"
    try:
        return raw.decode(encoding, "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")


def _is_tls_error(exc: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, (ssl.SSLError, ssl.SSLCertVerificationError)):
            return True
        message = str(current).lower()
        if "certificate verify failed" in message or "ssl" in message:
            return True
        current = current.__cause__ or current.__context__
    return False


def _short_error(exc: BaseException) -> str:
    text = str(exc) or exc.__class__.__name__
    return re.sub(r"\s+", " ", text)[:500]
