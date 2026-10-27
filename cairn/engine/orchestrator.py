from __future__ import annotations

import asyncio
import ipaddress
import time
from datetime import UTC, datetime
from typing import Any

from ..config import TOP_PORTS, Limits
from ..db import Database
from ..intel.confidence import ConfidenceEngine
from ..intel.learning import detector_prior_for
from ..models import SafetyError, ScopeError
from ..net.dns import DNSResolver
from ..net.http import SafeHTTPClient
from ..net.ports import PortResult, is_sensitive_port, is_web_port, scan_ports
from ..net.ratelimit import CancellationToken, StatsCounter
from ..scope import ScopeGuard
from .detectors import dangling_cname_hit, sensitive_port_hit
from .findings import FindingEmitter
from .passive import PassiveIntel, enumerate_subdomains, provider_for_cname
from .recorder import CoverageTracker, RunRecorder
from .webscan import WebScanner


async def execute_run(db: Database, run_id: str, *, token: CancellationToken | None = None) -> dict[str, Any]:
    run = db.get_run(run_id)
    if not run:
        raise KeyError(f"Unknown run: {run_id}")
    engagement = run["engagement"]
    mode = run["mode"]
    config = run.get("config") or {}
    if engagement is None:
        raise KeyError("Run has no engagement")
    limits = Limits.from_dict(engagement.get("limits"))
    resolver = DNSResolver(timeout=min(4.0, limits.timeout))
    recorder = RunRecorder(
        db,
        engagement_id=engagement["id"],
        run_id=run_id,
        max_evidence=limits.max_evidence,
    )
    coverage = CoverageTracker()
    stats = recorder.stats
    token = token or CancellationToken()
    started = time.perf_counter()
    db.start_run(run_id)
    db.add_audit(
        engagement["id"],
        action="run.started",
        target=run_id,
        decision="allow",
        details={"mode": mode, "online_intel": bool(config.get("online_intel", True))},
    )
    recorder.event("run", f"Scan started in {mode} mode")

    monitor = asyncio.create_task(_monitor_cancellation(db, run_id, engagement["id"], token))
    http: SafeHTTPClient | None = None
    passive: PassiveIntel | None = None
    try:
        guard = ScopeGuard(engagement, resolver=resolver, db=db)
        guard.audit(
            "scope.validated",
            target=engagement["name"],
            decision="allow",
            details={"scope_rules": len(engagement["scope"]), "mode": mode},
        )
        http = SafeHTTPClient(
            guard,
            timeout=limits.timeout,
            rate=limits.http_rate,
            claim_token=token,
        )
        confidence = ConfidenceEngine(db)
        emitter = FindingEmitter(
            db, recorder, confidence, engagement_id=engagement["id"], run_id=run_id
        )
        hostmap, ip_hosts, base_domains = await _collect_seed_hosts(
            guard=guard,
            resolver=resolver,
            recorder=recorder,
            coverage=coverage,
            stats=stats,
            limits=limits,
            token=token,
        )
        if config.get("online_intel", True):
            passive = PassiveIntel()
            try:
                await _passive_intel(
                    db=db,
                    passive=passive,
                    guard=guard,
                    resolver=resolver,
                    recorder=recorder,
                    coverage=coverage,
                    hostmap=hostmap,
                    ip_hosts=ip_hosts,
                    base_domains=base_domains,
                    limits=limits,
                    stats=stats,
                    token=token,
                )
            except Exception as exc:
                recorder.event("osint", f"Passive intelligence failed: {exc}", level="warning")

        # Active subdomain discovery runs only for wildcard-scoped domains and
        # never in passive mode.
        if mode in ("standard", "deep") and config.get("active_dns", True):
            from ..catalog import subdomain_wordlist

            for domain in list(base_domains)[:8]:
                if token.cancelled:
                    break
                names, info = await enumerate_subdomains(
                    guard, resolver, domain, wordlist=subdomain_wordlist(), limit=120
                )
                if info.get("skipped"):
                    recorder.event("dns", f"Subdomain discovery skipped for {domain}: {info['skipped']}")
                    continue
                for name in names:
                    if name in hostmap:
                        continue
                    if len(hostmap) >= limits.max_hosts:
                        break
                    hostmap[name] = {"ips": set(), "explicit": False, "sources": {"active_dns"}}
                    await _resolve_into(name, hostmap, ip_hosts, guard, resolver, recorder, coverage, stats)
                recorder.event("dns", f"Subdomain discovery for {domain}: {len(names)} resolved names", data=info)

        await _dns_phase(
            guard=guard,
            resolver=resolver,
            recorder=recorder,
            coverage=coverage,
            hostmap=hostmap,
            ip_hosts=ip_hosts,
            stats=stats,
            token=token,
        )

        findings_from_dns = await _dangling_cnames(
            db=db,
            resolver=resolver,
            guard=guard,
            recorder=recorder,
            emitter=emitter,
            hostmap=hostmap,
            ip_hosts=ip_hosts,
        )

        web_targets: dict[tuple[str, str, int], dict[str, Any]] = {}
        open_port_count = 0
        if mode in ("standard", "deep") and not token.cancelled:
            ports = _scan_ports_for_mode(limits, mode)
            summaries = await _port_phase(
                db=db,
                guard=guard,
                recorder=recorder,
                coverage=coverage,
                emitter=emitter,
                hostmap=hostmap,
                ip_hosts=ip_hosts,
                ports=ports,
                limits=limits,
                token=token,
                stats=stats,
                web_targets=web_targets,
            )
            open_port_count = sum(len(s.open_ports) for s in summaries)

        if mode in ("standard", "deep") and not token.cancelled and web_targets:
            scanner = WebScanner(
                db=db,
                guard=guard,
                http=http,
                resolver=resolver,
                recorder=recorder,
                coverage=coverage,
                emitter=emitter,
                run_id=run_id,
                mode=mode,
                limits=limits.to_dict(),
                token=token,
                stats=stats,
            )
            await _web_phase(
                db=db,
                scanner=scanner,
                recorder=recorder,
                coverage=coverage,
                hostmap=hostmap,
                web_targets=web_targets,
                limits=limits,
                token=token,
                stats=stats,
            )

        coverage_score = coverage.score()
        elapsed = round(time.perf_counter() - started, 2)
        result_stats = {
            "mode": mode,
            "duration_s": elapsed,
            "domains": sum(1 for h in hostmap.values() if not _is_ip_host(h)),
            "ips": len(ip_hosts),
            "open_ports": open_port_count,
            "web_targets": len(web_targets),
            "findings_new": emitter.created,
            "findings_updated": emitter.updated,
            "findings_dns": findings_from_dns,
            "evidence": recorder.evidence_count,
            "observations": recorder.stats.values.get("observations", 0),
            "assets": stats.values.get("assets", 0),
            "coverage": coverage.to_dict(),
            "http_requests": stats.values.get("http.requests", 0),
            **recorder.stats.to_dict(),
        }
        status = "cancelled" if token.cancelled else "completed"
        db.finish_run(run_id, status=status, stats=result_stats, coverage=coverage_score)
        db.add_audit(
            engagement["id"],
            action="run.finished",
            target=run_id,
            decision=status,
            details={
                "coverage": coverage_score,
                "findings_new": emitter.created,
                "findings_updated": emitter.updated,
                "evidence": recorder.evidence_count,
                "duration_s": elapsed,
            },
        )
        recorder.event("run", f"Scan {status} in {elapsed:.1f}s with {emitter.created} new findings")
        return result_stats
    except (ScopeError, SafetyError) as exc:
        db.finish_run(run_id, status="failed", stats={}, coverage=0.0, error=str(exc))
        db.add_audit(
            engagement["id"], action="run.refused", target=run_id, decision="deny", details={"reason": str(exc)}
        )
        recorder.event("run", f"Scan refused: {exc}", level="error")
        raise
    except Exception as exc:
        db.finish_run(run_id, status="failed", stats={}, coverage=0.0, error=f"{type(exc).__name__}: {exc}")
        db.add_audit(
            engagement["id"], action="run.failed", target=run_id, decision="error", details={"reason": str(exc)}
        )
        recorder.event("run", f"Scan failed: {type(exc).__name__}: {exc}", level="error")
        raise
    finally:
        monitor.cancel()
        if passive is not None:
            await passive.close()
        if http is not None:
            await http.close()


async def _monitor_cancellation(db: Database, run_id: str, engagement_id: str, token: CancellationToken) -> None:
    while True:
        await asyncio.sleep(2.0)
        try:
            run = db.one("SELECT status FROM runs WHERE id=?", (run_id,))
            engagement = db.one("SELECT status, expires_at FROM engagements WHERE id=?", (engagement_id,))
        except Exception:
            continue
        if not run or run["status"] in ("cancelling", "cancelled", "failed", "completed"):
            token.cancel()
            return
        if engagement and engagement["status"] != "active":
            token.cancel()
            return
        if engagement:
            try:
                end = datetime.fromisoformat(str(engagement["expires_at"]).replace("Z", "+00:00"))
                if end.tzinfo is None:
                    end = end.replace(tzinfo=UTC)
                if datetime.now(UTC) > end:
                    token.cancel()
                    return
            except ValueError:
                token.cancel()
                return


async def _collect_seed_hosts(
    *,
    guard: ScopeGuard,
    resolver: DNSResolver,
    recorder: RunRecorder,
    coverage: CoverageTracker,
    stats: StatsCounter,
    limits: Limits,
    token: CancellationToken,
) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]], set[str]]:
    seeds = guard.iter_hosts(limit=limits.max_hosts * 4)
    hostmap: dict[str, dict[str, Any]] = {}
    ip_hosts: dict[str, set[str]] = {}
    base_domains: set[str] = set()
    for seed in seeds:
        if token.cancelled:
            break
        explicit_ip = _is_ip(seed)
        hostmap.setdefault(
            seed,
            {
                "ips": {seed} if explicit_ip else set(),
                "explicit": True,
                "sources": {"scope"},
                "kind": "ip" if explicit_ip else "domain",
            },
        )
        if explicit_ip:
            recorder.asset("ip", seed, host=seed)
            ip_hosts.setdefault(seed, set()).add(seed)
            stats.incr("ips")
        else:
            base_domains.add(seed)
            recorder.asset("domain", seed, host=seed)
            stats.incr("domains")
    for host in list(hostmap):
        if _is_ip(host):
            continue
        await _resolve_into(host, hostmap, ip_hosts, guard, resolver, recorder, coverage, stats)
        if len(ip_hosts) > limits.max_hosts:
            raise SafetyError(
                f"Scope resolves to {len(ip_hosts)} unique addresses, above max_hosts={limits.max_hosts}. "
                "Narrow the manifest or raise max_hosts explicitly."
            )
    return hostmap, ip_hosts, base_domains


async def _resolve_into(
    host: str,
    hostmap: dict[str, dict[str, Any]],
    ip_hosts: dict[str, set[str]],
    guard: ScopeGuard,
    resolver: DNSResolver,
    recorder: RunRecorder,
    coverage: CoverageTracker,
    stats: StatsCounter,
) -> None:
    entry = hostmap.setdefault(host, {"ips": set(), "explicit": False, "sources": {"dns"}, "kind": "domain"})
    if entry["ips"]:
        return
    coverage.expect("dns", 1)
    try:
        ips = await guard.resolve(host)
    except Exception as exc:
        coverage.fail("dns", f"{host}: {exc}")
        recorder.event("dns", f"Resolution failed for {host}: {exc}", level="warning")
        return
    coverage.achieve("dns", 1)
    for ip in ips:
        entry["ips"].add(ip)
        ip_hosts.setdefault(ip, set()).add(host)
        recorder.asset("ip", ip, host=ip)
    stats.incr("dns.resolved")


async def _passive_intel(
    *,
    db: Database,
    passive: PassiveIntel,
    guard: ScopeGuard,
    resolver: DNSResolver,
    recorder: RunRecorder,
    coverage: CoverageTracker,
    hostmap: dict[str, dict[str, Any]],
    ip_hosts: dict[str, set[str]],
    base_domains: set[str],
    limits: Limits,
    stats: StatsCounter,
    token: CancellationToken,
) -> None:
    added = 0
    out_of_scope = 0
    for domain in sorted(base_domains)[:30]:
        if token.cancelled:
            return
        names, meta = await passive.certificate_transparency(domain)
        evidence = recorder.evidence(
            "osint.ct",
            "crt.sh",
            meta.get("url", ""),
            f"Certificate Transparency query for {domain}\n{meta.get('excerpt', '')}",
        )
        recorder.observation(
            asset_id=None,
            kind="osint.certificate_transparency",
            source="crt.sh",
            data={k: v for k, v in meta.items() if k != "excerpt"},
            evidence_id=evidence,
        )
        stats.incr("osint.ct_queries")
        for name in names:
            if not guard.can_host(name):
                out_of_scope += 1
                continue
            if name in hostmap or added >= 150:
                continue
            hostmap[name] = {"ips": set(), "explicit": False, "sources": {"ct"}, "kind": "domain"}
            recorder.asset("domain", name, host=name)
            stats.incr("domains")
            added += 1
            await _resolve_into(name, hostmap, ip_hosts, guard, resolver, recorder, coverage, stats)
        rdap = await passive.rdap(domain)
        if rdap:
            evidence = recorder.evidence(
                "osint.rdap",
                "rdap.org",
                rdap.get("url", ""),
                str({k: rdap.get(k) for k in ("handle", "status", "events", "nameservers", "entities")}),
            )
            recorder.observation(
                asset_id=None,
                kind="osint.rdap",
                source="rdap.org",
                data=rdap,
                evidence_id=evidence,
            )
            stats.incr("osint.rdap_queries")
        if len(ip_hosts) > limits.max_hosts:
            raise SafetyError(f"Passive discovery exceeded max_hosts={limits.max_hosts}")
    recorder.event("osint", f"Passive intelligence added {added} candidates ({out_of_scope} out of scope)")


async def _dns_phase(
    *,
    guard: ScopeGuard,
    resolver: DNSResolver,
    recorder: RunRecorder,
    coverage: CoverageTracker,
    hostmap: dict[str, dict[str, Any]],
    ip_hosts: dict[str, set[str]],
    stats: StatsCounter,
    token: CancellationToken,
) -> None:
    domains = [host for host in hostmap if not _is_ip(host)][:160]
    semaphore = asyncio.Semaphore(12)

    async def one(host: str) -> None:
        if token.cancelled:
            return
        async with semaphore:
            try:
                records = await resolver.enumerate_common(host)
            except Exception as exc:
                coverage.fail("dns", f"{host}: {exc}")
                return
        coverage.achieve("dns", 1)
        stats.incr("dns.enumerated")
        evidence = recorder.evidence(
            "dns.records", "dns", host, f"Common DNS records for {host}\n{records}"
        )
        recorder.observation(
            asset_id=None,
            kind="dns.records",
            source="dns",
            data={"host": host, "records": records},
            evidence_id=evidence,
        )
        entry = hostmap[host]
        for qtype in ("A", "AAAA"):
            for record in records.get(qtype, []):
                value = record.get("value")
                if value and _is_ip(str(value)):
                    entry["ips"].add(str(value))
                    ip_hosts.setdefault(str(value), set()).add(host)
                    recorder.asset("ip", str(value), host=str(value))
        for record in records.get("CNAME", []):
            target = str(record.get("value") or "").rstrip(".").lower()
            if target:
                entry.setdefault("cnames", set()).add(target)

    await asyncio.gather(*(one(host) for host in domains))
    for ip in list(ip_hosts)[: limits_guard(hostmap)]:
        if token.cancelled:
            break
        try:
            names = await resolver.reverse(ip)
        except Exception:
            continue
        if names:
            evidence = recorder.evidence("dns.ptr", "dns", ip, f"PTR for {ip}: {names}")
            recorder.observation(
                asset_id=None, kind="dns.ptr", source="dns", data={"ip": ip, "names": names}, evidence_id=evidence
            )
            stats.incr("dns.ptr")


def limits_guard(hostmap: dict[str, Any]) -> int:
    return max(32, min(512, len(hostmap) * 2))


async def _dangling_cnames(
    *,
    db: Database,
    resolver: DNSResolver,
    guard: ScopeGuard,
    recorder: RunRecorder,
    emitter: FindingEmitter,
    hostmap: dict[str, dict[str, Any]],
    ip_hosts: dict[str, set[str]],
) -> int:
    count = 0
    for host, entry in hostmap.items():
        for cname in sorted(entry.get("cnames", set()))[:20]:
            if cname in hostmap:
                continue
            try:
                await resolver.resolve_host(cname)
                continue
            except Exception:
                pass
            provider = provider_for_cname(cname)
            evidence = recorder.evidence(
                "dns.cname", "dns", host, f"{host} CNAME {cname}\nTarget did not resolve during this run."
            )
            # Find an asset id for the host.
            asset = db.one(
                "SELECT id FROM assets WHERE engagement_id=? AND kind='domain' AND value=?",
                (recorder.engagement_id, host),
            )
            for hit in dangling_cname_hit(host, cname, provider, evidence):
                emitter.emit(
                    hit,
                    asset_id=asset["id"] if asset else None,
                    asset_value=host,
                    coverage=0.7,
                )
                count += 1
    return count


def _scan_ports_for_mode(limits: Limits, mode: str) -> list[int]:
    ports = list(dict.fromkeys(int(p) for p in limits.allowed_ports))
    if mode == "standard" and len(ports) > 300:
        standard = [p for p in ports if p in TOP_PORTS]
        ports = standard or ports[:200]
    return ports


async def _port_phase(
    *,
    db: Database,
    guard: ScopeGuard,
    recorder: RunRecorder,
    coverage: CoverageTracker,
    emitter: FindingEmitter,
    hostmap: dict[str, dict[str, Any]],
    ip_hosts: dict[str, set[str]],
    ports: list[int],
    limits: Limits,
    token: CancellationToken,
    stats: StatsCounter,
    web_targets: dict[tuple[str, str, int], dict[str, Any]],
) -> list[Any]:
    if not ports:
        return []
    ips = sorted(ip_hosts)
    if len(ips) > limits.max_hosts:
        raise SafetyError(f"Port scan would touch {len(ips)} hosts, above max_hosts={limits.max_hosts}")
    semaphore = asyncio.Semaphore(3)
    summaries = []

    async def one(ip: str) -> None:
        if token.cancelled:
            return
        coverage.expect("ports", 1)
        async with semaphore:
            summary = await scan_ports(
                ip,
                ports,
                rate=limits.port_rate,
                concurrency=min(300, max(20, len(ports))),
                timeout=min(4.0, limits.timeout),
                token=token,
            )
        summaries.append(summary)
        coverage.achieve("ports", 1)
        stats.incr("ports.scanned")
        display_hosts = sorted(ip_hosts.get(ip, {ip}))
        for result in summary.open_ports:
            stats.incr("ports.open")
            await _record_open_port(
                db=db,
                guard=guard,
                recorder=recorder,
                emitter=emitter,
                ip=ip,
                result=result,
                display_hosts=display_hosts,
                web_targets=web_targets,
            )

    await asyncio.gather(*(one(ip) for ip in ips))
    return summaries


async def _record_open_port(
    *,
    db: Database,
    guard: ScopeGuard,
    recorder: RunRecorder,
    emitter: FindingEmitter,
    ip: str,
    result: PortResult,
    display_hosts: list[str],
    web_targets: dict[tuple[str, str, int], dict[str, Any]],
) -> None:
    banner_text = (
        f"TCP connect to {ip}:{result.port} succeeded.\n"
        f"Service guess: {result.service}\nLatency: {result.latency_ms} ms\n"
        f"Banner: {result.banner or '(none)'}"
    )
    evidence = recorder.evidence("network.tcp", "port-scan", f"{ip}:{result.port}", banner_text)
    primary = display_hosts[0] if display_hosts else ip
    service_asset = recorder.asset(
        "service",
        f"{primary}:{result.port}",
        host=ip,
        port=result.port,
        meta={"service": result.service, "banner": result.banner, "ip": ip},
    )
    recorder.observation(
        asset_id=service_asset,
        kind="port.open",
        source="port-scan",
        data=result.to_dict(),
        evidence_id=evidence,
    )
    if is_sensitive_port(result.port):
        for hit in sensitive_port_hit(primary, result.port, result.service, result.banner, evidence):
            emitter.emit(hit, asset_id=service_asset, asset_value=primary, coverage=0.9)
    # Probe HTTP on known web ports and on otherwise unidentified services.
    # This catches web apps on non-standard ports without sending protocol
    # probes to services we already recognize (SSH, SMTP, databases).
    if is_web_port(result.port, result.service) or (
        result.service is None and not is_sensitive_port(result.port)
    ):
        hosts = display_hosts[:3] if display_hosts else [ip]
        for host in hosts:
            key = (host, ip, result.port)
            web_targets.setdefault(
                key,
                {"host": host, "ip": ip, "port": result.port, "service": result.service},
            )


async def _web_phase(
    *,
    db: Database,
    scanner: WebScanner,
    recorder: RunRecorder,
    coverage: CoverageTracker,
    hostmap: dict[str, dict[str, Any]],
    web_targets: dict[tuple[str, str, int], dict[str, Any]],
    limits: Limits,
    token: CancellationToken,
    stats: StatsCounter,
) -> None:
    semaphore = asyncio.Semaphore(3)

    async def one(target: dict[str, Any]) -> None:
        if token.cancelled:
            return
        host = target["host"]
        port = target["port"]
        scheme = "https" if port in (443, 8443, 9443) else "http"
        base = f"{scheme}://{host}:{port}/"
        url_asset = recorder.asset(
            "url", base, host=host, port=port, scheme=scheme, meta={"discovered_by": "port-scan"}
        )
        coverage.expect("http", 1)
        async with semaphore:
            outcome = await scanner.scan(
                host=host,
                ip=target["ip"],
                port=port,
                service=target.get("service"),
                asset_id=url_asset,
            )
        if outcome.error:
            coverage.fail("http", f"{host}:{port}: {outcome.error}")
            recorder.event("web", f"HTTP probe failed for {host}:{port}: {outcome.error}", level="warning")
            return
        coverage.achieve("http", 1)
        stats.incr("web.services")
        db.upsert_asset(
            recorder.engagement_id,
            "url",
            base,
            host=host,
            port=port,
            scheme=scheme,
            meta=outcome.to_meta(),
        )
        recorder.event(
            "web",
            f"Web surface mapped: {base} ({outcome.status}, {len(outcome.technologies)} technologies)",
            data={"title": outcome.title, "findings": outcome.findings},
        )
        for discovered in outcome.discovered_urls[:50]:
            if not guard_can_url(scanner.guard, discovered):
                continue
            recorder.asset(
                "url",
                discovered,
                host=host,
                port=port,
                scheme=scheme,
                meta={"discovered_by": "sitemap"},
            )
            stats.incr("web.discovered_urls")

    await asyncio.gather(*(one(target) for target in web_targets.values()))


def guard_can_url(guard: ScopeGuard, url: str) -> bool:
    try:
        return guard.can_url(url)
    except Exception:
        return False


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_ip_host(entry: dict[str, Any]) -> bool:
    return entry.get("kind") == "ip"


def _prior(detector: str) -> float:
    return detector_prior_for(detector)
