from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ..catalog import tech_signatures
from ..db import Database
from ..intel.policy import select_content_paths
from ..models import DetectorHit
from ..net.dns import DNSResolver
from ..net.http import HTTPResult, SafeHTTPClient
from ..net.ratelimit import CancellationToken, StatsCounter
from ..net.tls import probe_tls
from ..redact import key_names_from_env
from ..scope import ScopeGuard
from .detectors import (
    content_hits,
    cookie_hits,
    cors_hit,
    disclosure_hits,
    extract_title,
    security_header_hits,
    tls_hits,
)
from .findings import FindingEmitter
from .recorder import CoverageTracker, RunRecorder
from .types import ContentProbe, WebSnapshot


@dataclass
class WebScanOutcome:
    host: str
    port: int
    scheme: str
    final_url: str
    title: str
    status: int | None
    technologies: list[dict[str, Any]] = field(default_factory=list)
    findings: int = 0
    tls: dict[str, Any] | None = None
    discovered_urls: list[str] = field(default_factory=list)
    error: str | None = None

    def to_meta(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "status": self.status,
            "scheme": self.scheme,
            "final_url": self.final_url,
            "technologies": self.technologies,
            "tls": self.tls,
            "last_scan": "current",
        }


class WebScanner:
    def __init__(
        self,
        *,
        db: Database,
        guard: ScopeGuard,
        http: SafeHTTPClient,
        resolver: DNSResolver,
        recorder: RunRecorder,
        coverage: CoverageTracker,
        emitter: FindingEmitter,
        run_id: str,
        mode: str,
        limits: dict[str, Any],
        token: CancellationToken,
        stats: StatsCounter,
    ):
        self.db = db
        self.guard = guard
        self.http = http
        self.resolver = resolver
        self.recorder = recorder
        self.coverage = coverage
        self.emitter = emitter
        self.run_id = run_id
        self.mode = mode
        self.limits = limits
        self.token = token
        self.stats = stats
        self.content_limit = int(limits.get("max_content_paths", 36))
        self.timeout = float(limits.get("timeout", 8.0))
        self._path_lock = asyncio.Lock()

    async def scan(
        self,
        *,
        host: str,
        ip: str,
        port: int,
        service: str | None,
        asset_id: str,
    ) -> WebScanOutcome:
        preferred = "https" if port in (443, 8443, 9443) else "http"
        alternative = "http" if preferred == "https" else "https"
        outcome: WebScanOutcome | None = None
        for scheme in (preferred, alternative):
            if self.token.cancelled:
                return WebScanOutcome(host, port, scheme, "", "", None, error="cancelled")
            base = _origin(host, port, scheme)
            tls = None
            if scheme == "https":
                tls = await probe_tls(host, ip, port, timeout=self.timeout, server_hostname=host)
                if not tls.get("connected"):
                    continue
            main = await self.http.get(base, allow_redirects=True)
            self.stats.incr("http.requests")
            if main.error and scheme == preferred:
                continue
            if main.error:
                outcome = WebScanOutcome(host, port, scheme, base, "", None, tls=tls, error=main.error)
                break
            outcome = await self._analyze(
                host=host,
                port=port,
                scheme=scheme,
                base=base,
                main=main,
                tls=tls,
                service=service,
                asset_id=asset_id,
            )
            break
        if outcome is None:
            outcome = WebScanOutcome(host, port, preferred, "", "", None, error="no HTTP response")
        return outcome

    async def _analyze(
        self,
        *,
        host: str,
        port: int,
        scheme: str,
        base: str,
        main: HTTPResult,
        tls: dict[str, Any] | None,
        service: str | None,
        asset_id: str,
    ) -> WebScanOutcome:
        final_url = main.final_url or base
        title = extract_title(main.body)
        technologies = detect_technologies(main)
        parts = urlsplit(final_url)
        origin = f"{parts.scheme}://{parts.netloc}"
        evidence_text = _response_evidence(main, title)
        base_evidence = self.recorder.evidence(
            "http.response",
            "web",
            final_url,
            evidence_text,
            raw=main.raw,
        )
        tls_evidence = None
        if tls:
            tls_evidence = self.recorder.evidence(
                "tls.certificate",
                "tls",
                f"{host}:{port}",
                json.dumps(tls.get("certificate") or {"connected": tls.get("connected")}, indent=2, sort_keys=True),
            )
        self.recorder.observation(
            asset_id=asset_id,
            kind="web.response",
            source="web",
            data={
                **main.to_meta(),
                "title": title,
                "technologies": technologies,
                "tls": tls,
            },
            evidence_id=base_evidence,
        )
        if technologies:
            self.recorder.observation(
                asset_id=asset_id,
                kind="web.technology",
                source="web",
                data={"technologies": technologies},
                evidence_id=base_evidence,
            )
        if tls:
            self.recorder.observation(
                asset_id=asset_id,
                kind="tls.certificate",
                source="tls",
                data=tls,
                evidence_id=tls_evidence,
            )

        baseline = await self._baseline(origin)
        hashes = hashlib.sha256(self.run_id.encode()).hexdigest()
        paths = select_content_paths(
            self.db,
            limit=self.content_limit,
            deep=self.mode == "deep",
            seed=hashes,
        )
        content_coverage = 0.5
        content: list[ContentProbe] = []
        if not self.token.cancelled:
            self.coverage.expect("content", len(paths))
            content = await self._probe_content(origin, paths, baseline, asset_id)
            content_coverage = min(1.0, len([p for p in content if p.result.status is not None]) / max(1, len(paths)))
            content_coverage = 0.35 + 0.65 * content_coverage

        snapshot = WebSnapshot(
            host=host,
            port=port,
            scheme=scheme,
            base_url=base,
            final_url=final_url,
            main=main,
            title=title,
            technologies=technologies,
            tls=tls,
            content=content,
            baseline=baseline,
            evidence_id=base_evidence,
            tls_evidence_id=tls_evidence,
        )
        hits: list[DetectorHit] = []
        hits.extend(security_header_hits(snapshot))
        hits.extend(cookie_hits(snapshot))
        hits.extend(disclosure_hits(snapshot))
        hits.extend(tls_hits(snapshot))
        if not self.token.cancelled:
            hits.extend(await self._cors_hits(base, snapshot))
        for probe in content:
            hits.extend(content_hits(probe))

        seen: set[str] = set()
        finding_count = 0
        for hit in hits:
            key = hit.fingerprint_key(host)
            if key in seen:
                continue
            seen.add(key)
            self.emitter.emit(
                hit,
                asset_id=asset_id,
                asset_value=host,
                coverage=content_coverage,
            )
            finding_count += 1
        discovered = self._extract_discoveries(content)
        return WebScanOutcome(
            host=host,
            port=port,
            scheme=scheme,
            final_url=final_url,
            title=title,
            status=main.status,
            technologies=technologies,
            findings=finding_count,
            tls=tls,
            discovered_urls=discovered,
        )

    async def _baseline(self, origin: str) -> HTTPResult | None:
        path = f"/cairn-soft404-{secrets.token_hex(5)}"
        try:
            result = await self.http.get(origin + path, allow_redirects=False, max_bytes=64 * 1024)
            self.stats.incr("http.requests")
            self.coverage.expect("content", 1)
            if result.status is not None:
                self.coverage.achieve("content", 1)
            return result
        except Exception:
            return None

    async def _probe_content(
        self,
        origin: str,
        paths: list[dict[str, Any]],
        baseline: HTTPResult | None,
        asset_id: str,
    ) -> list[ContentProbe]:
        semaphore = asyncio.Semaphore(5)
        results: list[ContentProbe] = []
        lock = asyncio.Lock()

        async def one(entry: dict[str, Any]) -> None:
            if self.token.cancelled:
                return
            path = entry["path"]
            url = origin + path
            async with semaphore:
                result = await self.http.get(url, allow_redirects=False, max_bytes=256 * 1024)
            self.stats.incr("http.requests")
            self.stats.incr("web.content_probes")
            if result.status is None:
                async with lock:
                    self.coverage.fail("content", f"{url}: {result.error or 'no response'}")
                return
            async with lock:
                self.coverage.achieve("content", 1)
            soft = _is_soft_404(result, baseline)
            evidence_id = None
            if result.status in (200, 401, 403) and result.raw:
                evidence_id = self.recorder.evidence(
                    "http.content",
                    "web",
                    url,
                    _content_evidence(result),
                    raw=result.raw,
                )
            probe = ContentProbe(entry=entry, url=url, result=result, evidence_id=evidence_id, soft404=soft)
            if entry.get("probe") == "env" and result.status == 200:
                probe.key_names = key_names_from_env(result.body)
            hits = content_hits(probe)
            self.db.record_path(path, finding=bool(hits))
            self.recorder.observation(
                asset_id=asset_id,
                kind="web.content",
                source="web",
                data={
                    "path": path,
                    "probe": entry.get("probe"),
                    "status": result.status,
                    "content_type": result.content_type,
                    "length": len(result.raw),
                    "soft404": soft,
                    "key_names": probe.key_names[:20],
                },
                evidence_id=evidence_id,
                confidence=0.35 if soft else 1.0,
            )
            async with lock:
                results.append(probe)
                for hit in hits:
                    hit.evidence_ids = list(dict.fromkeys([*hit.evidence_ids, evidence_id] if evidence_id else hit.evidence_ids))
                # Stash hits on the probe entry for the analysis loop; the
                # entry dict is per-run and never persisted.
                entry["_hits"] = hits

        await asyncio.gather(*(one(entry) for entry in paths))
        for entry in paths:
            stashed = entry.pop("_hits", [])
            if stashed:
                # Hits are re-derived in _analyze from the ContentProbe; the
                # stash exists only to update path stats consistently.
                del stashed
        return sorted(results, key=lambda p: p.entry["path"])

    async def _cors_hits(self, base: str, snapshot: WebSnapshot) -> list[DetectorHit]:
        try:
            test = await self.http.get(
                base,
                allow_redirects=False,
                max_bytes=64 * 1024,
                extra_headers={"Origin": "https://cairn.invalid"},
            )
            self.stats.incr("http.requests")
        except Exception:
            return []
        if test.status is None:
            return []
        headers = test.header_map
        acao = (headers.get("access-control-allow-origin") or [""])[0]
        acac = (headers.get("access-control-allow-credentials") or [""])[0].lower() == "true"
        if acao == "https://cairn.invalid" and acac:
            evidence = self.recorder.evidence(
                "http.cors",
                "web",
                base,
                _content_evidence(test),
                raw=test.raw,
            )
            hits = cors_hit(snapshot, reflected=True, credentials=True)
            for hit in hits:
                if evidence:
                    hit.evidence_ids.append(evidence)
            return hits
        return []

    def _extract_discoveries(self, content: list[ContentProbe]) -> list[str]:
        urls: list[str] = []
        for probe in content:
            if probe.entry.get("probe") == "sitemap" and probe.result.status == 200:
                for match in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", probe.result.body[:200000]):
                    if match.startswith("http"):
                        urls.append(match)
            if probe.entry.get("probe") == "security_txt" and probe.result.status == 200:
                pass
        return list(dict.fromkeys(urls))[:100]


def _origin(host: str, port: int, scheme: str) -> str:
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}" if port == default else f"{scheme}://{host}:{port}"


def _response_evidence(result: HTTPResult, title: str) -> str:
    headers = "\n".join(f"{k}: {v}" for k, values in result.header_map.items() for v in values)
    body = (result.body or "")[:1800]
    return (
        f"HTTP {result.status} {result.final_url or result.url}\n"
        f"Content-Type: {result.content_type}\n"
        f"Title: {title}\n"
        f"TLS verified: {result.tls_verified}\n"
        f"Redirects: {result.redirects}\n"
        f"Headers:\n{headers}\n\nBody excerpt:\n{body}"
    )


def _content_evidence(result: HTTPResult) -> str:
    headers = "\n".join(f"{k}: {v}" for k, values in result.header_map.items() for v in values)
    return (
        f"HTTP {result.status} {result.url}\nContent-Type: {result.content_type}\n"
        f"Length read: {len(result.raw)}\nHeaders:\n{headers}\n\nBody excerpt:\n"
        f"{(result.body or '')[:1600]}"
    )


def _is_soft_404(result: HTTPResult, baseline: HTTPResult | None) -> bool:
    if baseline is None or baseline.status is None:
        return False
    if result.status != baseline.status or result.status not in (200, 403):
        return False
    left, right = len(result.raw), len(baseline.raw)
    same_size = abs(left - right) <= max(80, int(0.08 * max(left, right, 1)))
    left_title = extract_title(result.body).lower()
    right_title = extract_title(baseline.body or "").lower()
    return same_size and left_title == right_title


def detect_technologies(result: HTTPResult) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    headers = result.header_map
    body = result.body[:250_000]
    for signature in tech_signatures():
        version = None
        source = None
        for header, regex in signature.get("_headers", {}).items():
            for value in headers.get(header, []):
                match = regex.search(value)
                if match:
                    source = f"header:{header}"
                    version = _group(match)
                    break
            if source:
                break
        if not source and signature.get("_body"):
            match = signature["_body"].search(body)
            if match:
                source = "body"
                version = _group(match)
        if not source or signature["name"] in seen:
            continue
        seen.add(signature["name"])
        found.append(
            {
                "name": signature["name"],
                "category": signature.get("category", "unknown"),
                "version": version,
                "source": source,
            }
        )
        if len(found) >= 30:
            break
    return found


def _group(match: Any) -> str | None:
    try:
        value = match.group(1)
        return value.strip() if value else None
    except (IndexError, AttributeError):
        return None
