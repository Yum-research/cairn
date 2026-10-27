from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit

from .config import TOP_PORTS
from .models import PreparedTarget, SafetyError, ScopeError, ScopeSpec

ALWAYS_DENIED_HOSTS = {
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
}
ALWAYS_DENIED_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # AWS / GCP / Azure / DigitalOcean metadata
    ipaddress.ip_address("169.254.170.2"),    # ECS task metadata
    ipaddress.ip_address("100.100.100.200"),  # Alibaba metadata
    ipaddress.ip_address("fd00:ec2::254"),    # AWS IPv6 metadata
}
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class HostResolver(Protocol):
    async def resolve_host(self, host: str) -> list[str]: ...


class SystemResolver:
    """Last-resort resolver used by the CLI when no DNS client is injected."""

    async def resolve_host(self, host: str) -> list[str]:
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        try:
            infos = await socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ScopeError(f"Could not resolve {host!r}: {exc}") from exc
        out: list[str] = []
        for info in infos:
            addr = info[4][0]
            if addr not in out:
                out.append(addr)
        if not out:
            raise ScopeError(f"Could not resolve {host!r}")
        return out


def _normalize_host(host: str) -> str:
    host = (host or "").strip().rstrip(".").lower()
    if not host:
        raise ScopeError("Empty host")
    if "://" in host or "/" in host or "@" in host or ":" in host:
        raise ScopeError(f"Not a bare host: {host!r}")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError(f"Invalid hostname: {host!r}") from exc
    if ascii_host in ALWAYS_DENIED_HOSTS:
        raise ScopeError(f"Refusing metadata hostname: {host}")
    if len(ascii_host) > 253:
        raise ScopeError(f"Hostname too long: {host}")
    label_host = ascii_host[4:] if ascii_host.startswith("xn--") else ascii_host
    labels = label_host.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise ScopeError(f"Invalid hostname: {host!r}")
    return ascii_host


def _normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    return _normalize_host(value)


def _normalize_url(value: str) -> str:
    parts = urlsplit(value.strip())
    if parts.scheme.lower() not in ("http", "https"):
        raise ScopeError("URL scope must use http:// or https://")
    if not parts.hostname:
        raise ScopeError(f"URL scope has no host: {value!r}")
    if parts.username or parts.password:
        raise ScopeError("URL scope must not contain credentials")
    host = _normalize_host(parts.hostname)
    port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    if not (1 <= port <= 65535):
        raise ScopeError("URL scope port out of range")
    path = parts.path or "/"
    return f"{parts.scheme.lower()}://{host}:{port}{path}"


def validate_scope(specs: list[ScopeSpec]) -> list[dict[str, Any]]:
    if not specs:
        raise ScopeError("An engagement requires at least one include rule")
    if not any(spec.mode == "include" for spec in specs):
        raise ScopeError("An engagement requires at least one include rule")
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for spec in specs:
        kind = spec.kind.strip().lower()
        if kind not in ("domain", "ip", "cidr", "url"):
            raise ScopeError(f"Unsupported scope kind: {kind}")
        mode = (spec.mode or "include").lower()
        if mode not in ("include", "exclude"):
            raise ScopeError(f"Unsupported scope mode: {mode}")
        if kind == "domain":
            value = _normalize_domain(spec.value)
            include_subdomains = spec.include_subdomains or spec.value.strip().lower().startswith("*.")
        elif kind == "ip":
            try:
                addr = ipaddress.ip_address(spec.value.strip())
            except ValueError as exc:
                raise ScopeError(f"Invalid IP: {spec.value!r}") from exc
            if _ip_denied(addr):
                raise ScopeError(f"IP {addr} is blocked by safety policy")
            value = str(addr)
            include_subdomains = False
        elif kind == "cidr":
            try:
                net = ipaddress.ip_network(spec.value.strip(), strict=False)
            except ValueError as exc:
                raise ScopeError(f"Invalid CIDR: {spec.value!r}") from exc
            if net.num_addresses > 65536 and mode == "include":
                raise ScopeError(
                    f"CIDR {net} is too large for a manifest (max 65,536 addresses). "
                    "Split it into explicit engagement ranges."
                )
            if net.is_link_local or net.is_multicast or net.is_reserved:
                raise ScopeError(f"CIDR {net} is blocked by safety policy")
            if any(denied in net for denied in ALWAYS_DENIED_IPS if denied.version == net.version):
                raise ScopeError(f"CIDR {net} contains a cloud metadata address")
            value = str(net)
            include_subdomains = False
        else:
            value = _normalize_url(spec.value)
            include_subdomains = False
        key = (mode, kind, value)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "kind": kind,
                "value": value,
                "mode": mode,
                "include_subdomains": bool(include_subdomains),
            }
        )
    return out


def validate_manifest(
    *, authorized_by: str, authorization_ref: str, starts_at: str, expires_at: str, scope: list[dict[str, Any]]
) -> None:
    if not authorized_by.strip():
        raise ScopeError("authorized_by is required (the human or organization granting permission)")
    if not authorization_ref.strip():
        raise ScopeError("authorization_ref is required (ticket, contract, or written approval reference)")
    include = [s for s in scope if s.get("mode", "include") == "include"]
    if not include:
        raise ScopeError("Scope manifest has no include rules")
    try:
        start = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
        end = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScopeError("Invalid engagement timestamps") from exc
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    now = datetime.now(UTC)
    if end <= now:
        raise ScopeError("Engagement expiry is in the past")
    if end <= start:
        raise ScopeError("Engagement expires before it starts")
    if end - start > timedelta(days=180):
        raise ScopeError("Maximum engagement window is 180 days; create a renewed engagement instead")
    if start > now + timedelta(minutes=10):
        raise ScopeError("Engagement cannot start in the future")


def _ip_denied(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip in ALWAYS_DENIED_IPS:
        return True
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return True
    if ip.is_link_local:
        return True
    if ip.version == 4 and ip.is_loopback:
        # Loopback is allowed only when it appears in explicit scope; this
        # function is consulted for resolved addresses. Callers decide.
        return False
    if ip.version == 4 and ip in ipaddress.ip_network("0.0.0.0/8"):
        return True
    return False


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    rule: dict[str, Any] | None = None
    resolved_ips: list[str] = field(default_factory=list)


class ScopeGuard:
    """The only path from the engine to a target.

    The guard enforces: active, unexpired engagement; explicit include rules;
    excludes-first matching; allowed ports; metadata/link-local blocks; DNS
    re-resolution on every request; and an audit trail for decisions.
    """

    def __init__(
        self,
        engagement: dict[str, Any],
        *,
        resolver: HostResolver | None = None,
        db: Any | None = None,
    ):
        self.engagement = engagement
        self.engagement_id = engagement["id"]
        self.rules: list[dict[str, Any]] = engagement.get("scope") or []
        self.resolver = resolver or SystemResolver()
        self.db = db
        self.limits = engagement.get("limits") or {}
        allowed = self.limits.get("allowed_ports") or list(TOP_PORTS)
        self.allowed_ports = frozenset(int(p) for p in allowed)
        self._assert_active()

    def _assert_active(self) -> None:
        if self.engagement.get("status") != "active":
            raise ScopeError(f"Engagement {self.engagement_id} is {self.engagement.get('status')!r}, not active")
        now = datetime.now(UTC)
        try:
            end = datetime.fromisoformat(str(self.engagement["expires_at"]).replace("Z", "+00:00"))
            start = datetime.fromisoformat(str(self.engagement["starts_at"]).replace("Z", "+00:00"))
        except (KeyError, ValueError) as exc:
            raise ScopeError("Engagement has invalid timestamps") from exc
        if end.tzinfo is None:
            end = end.replace(tzinfo=UTC)
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        if now < start:
            raise ScopeError(f"Engagement has not started ({start.isoformat()})")
        if now > end:
            raise ScopeError(f"Engagement expired at {end.isoformat()}")

    # ------------------------------------------------------------------ rules
    def _match_domain(self, rule_value: str, host: str, subdomains: bool) -> bool:
        if host == rule_value:
            return True
        return subdomains and host.endswith("." + rule_value)

    def can_host(self, host: str) -> bool:
        try:
            host = _normalize_host(host)
        except ScopeError:
            return False
        for rule in self.rules:
            if rule["mode"] != "exclude":
                continue
            if rule["kind"] == "domain" and self._match_domain(
                rule["value"], host, bool(rule.get("include_subdomains"))
            ):
                return False
        for rule in self.rules:
            if rule["mode"] != "include":
                continue
            if rule["kind"] == "domain" and self._match_domain(
                rule["value"], host, bool(rule.get("include_subdomains"))
            ):
                return True
            if rule["kind"] == "url":
                parts = urlsplit(rule["value"])
                if parts.hostname == host:
                    return True
            if rule["kind"] in ("ip", "cidr"):
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(rule["value"], strict=False):
                        return True
                except ValueError:
                    continue
        return False

    def _ip_excluded(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        for rule in self.rules:
            if rule["mode"] != "exclude":
                continue
            if rule["kind"] in ("ip", "cidr") and addr in ipaddress.ip_network(rule["value"], strict=False):
                return True
        return False

    def _ip_in_scope(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int) -> bool:
        if port not in self.allowed_ports or _ip_denied(addr) or self._ip_excluded(addr):
            return False
        for rule in self.rules:
            if rule["mode"] != "include":
                continue
            if rule["kind"] in ("ip", "cidr") and addr in ipaddress.ip_network(rule["value"], strict=False):
                return True
        return False

    def can_ip(self, ip: str, port: int | None = None) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if port is None:
            if _ip_denied(addr) or self._ip_excluded(addr):
                return False
            return any(
                rule["kind"] in ("ip", "cidr")
                and addr in ipaddress.ip_network(rule["value"], strict=False)
                for rule in self.rules
                if rule["mode"] == "include"
            )
        return self._ip_in_scope(addr, port)

    def _resolved_authorized(self, host: str, ip: str, port: int) -> bool:
        """Authorize a resolved address against the current connection.

        A domain grant authorizes public addresses, not a DNS rebind into
        loopback, RFC1918 space, or cloud metadata. Private targets must be
        explicitly represented by an IP or CIDR include rule.
        """

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if _ip_denied(addr) or self._ip_excluded(addr):
            return False
        if _is_ip(host):
            return True
        if addr.is_private or addr.is_loopback:
            return self._ip_in_scope(addr, port)
        return True

    def _match_url_rule(self, url: str, rule_value: str) -> bool:
        left, right = urlsplit(url), urlsplit(rule_value)
        if (left.scheme, left.hostname, left.port) != (right.scheme, right.hostname, right.port):
            return False
        return left.path.startswith(right.path)

    def can_url(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
            host = _normalize_host(parts.hostname or "")
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except (ValueError, ScopeError):
            return False
        if parts.scheme not in ("http", "https") or port not in self.allowed_ports:
            return False
        if _is_ip(host):
            addr = ipaddress.ip_address(host)
            if _ip_denied(addr) or self._ip_excluded(addr):
                return False
        for rule in self.rules:
            if rule["mode"] != "exclude":
                continue
            if rule["kind"] == "url" and self._match_url_rule(url, rule["value"]):
                return False
            if rule["kind"] == "domain" and self._match_domain(
                rule["value"], host, bool(rule.get("include_subdomains"))
            ):
                return False
        for rule in self.rules:
            if rule["mode"] != "include":
                continue
            if rule["kind"] == "url" and self._match_url_rule(url, rule["value"]):
                return True
            if rule["kind"] == "domain" and self._match_domain(
                rule["value"], host, bool(rule.get("include_subdomains"))
            ):
                return True
            if rule["kind"] in ("ip", "cidr"):
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(rule["value"], strict=False):
                        return True
                except ValueError:
                    pass
        return False

    # --------------------------------------------------------------- resolving
    async def resolve(self, host: str) -> list[str]:
        host = _normalize_host(host)
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        ips = await self.resolver.resolve_host(host)
        clean: list[str] = []
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ScopeError(f"Resolver returned invalid address {ip!r}") from exc
            if _ip_denied(addr):
                raise ScopeError(f"{host} resolves to a blocked address ({ip})")
            clean.append(str(addr))
        if not clean:
            raise ScopeError(f"{host} did not resolve to any address")
        return clean

    async def prepare(self, host: str, port: int, scheme: str = "http") -> PreparedTarget:
        host = _normalize_host(host)
        if port not in self.allowed_ports:
            raise ScopeError(f"Port {port} is not in this engagement's allowed_ports")
        if not (self.can_host(host) or self.can_ip(host, port)):
            raise ScopeError(f"{host}:{port} is outside the engagement scope")
        try:
            ipaddress.ip_address(host)
            ips = [host]
            if not self.can_ip(host, port):
                raise ScopeError(f"IP {host} is outside the engagement scope")
        except ValueError:
            ips = await self.resolve(host)
            if not self.can_host(host):
                raise ScopeError(f"Hostname {host} is outside the engagement scope") from None
        for candidate in ips:
            if not self._resolved_authorized(host, candidate, port):
                raise ScopeError(
                    f"Resolved address {candidate} is not authorized for {host}:{port}; "
                    "explicitly scope private or sensitive targets"
                )
        ip = ips[0]
        if scheme == "https":
            url = f"https://{host}:{port}/"
        else:
            url = f"http://{host}:{port}/"
        return PreparedTarget(host=host, url=url, scheme=scheme, port=port, ip=ip)

    async def check_url(self, url: str) -> PreparedTarget:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ScopeError("Only http and https are permitted")
        host = _normalize_host(parts.hostname or "")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if not self.can_url(url):
            raise ScopeError(f"URL is outside the engagement scope: {url}")
        ips = await self.resolve(host) if not _is_ip(host) else [host]
        if not ips:
            raise ScopeError("No resolved address for URL")
        for candidate in ips:
            if not self._resolved_authorized(host, candidate, port):
                raise ScopeError(
                    f"Resolved address {candidate} is not authorized for {host}:{port}; "
                    "explicitly scope private or sensitive targets"
                )
        return PreparedTarget(host=host, url=url, scheme=parts.scheme, port=port, ip=ips[0])

    # ------------------------------------------------------------------- audit
    def audit(self, action: str, target: str, decision: str, details: dict[str, Any] | None = None) -> None:
        if self.db is not None:
            self.db.add_audit(
                self.engagement_id,
                action=action,
                target=target,
                decision=decision,
                details=details or {},
            )

    # ------------------------------------------------------------------- seeds
    def include_rules(self) -> list[dict[str, Any]]:
        return [rule for rule in self.rules if rule["mode"] == "include"]

    def excluded_hosts(self) -> list[str]:
        return [r["value"] for r in self.rules if r["mode"] == "exclude" and r["kind"] == "domain"]

    def iter_hosts(self, limit: int = 4096) -> list[str]:
        hosts: list[str] = []
        for rule in self.include_rules():
            if rule["kind"] in ("ip", "domain"):
                hosts.append(rule["value"])
            elif rule["kind"] == "cidr":
                net = ipaddress.ip_network(rule["value"], strict=False)
                if net.num_addresses > limit:
                    raise SafetyError(
                        f"CIDR {net} expands to {net.num_addresses} hosts, above the {limit} host ceiling"
                    )
                candidates = net.hosts() if net.prefixlen < (31 if net.version == 4 else 127) else (net.network_address,)
                for addr in candidates:
                    hosts.append(str(addr))
                    if len(hosts) > limit:
                        raise SafetyError(f"Scope expansion exceeded {limit} hosts")
            elif rule["kind"] == "url":
                parsed = urlsplit(rule["value"])
                if parsed.hostname:
                    hosts.append(parsed.hostname)
        seen: set[str] = set()
        out: list[str] = []
        for host in hosts:
            if host not in seen:
                seen.add(host)
                out.append(host)
        return out


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class _FakeResolver:
    async def resolve_host(self, host: str) -> list[str]:
        return [host]
