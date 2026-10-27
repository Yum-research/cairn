from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from cairn.models import SafetyError, ScopeError, ScopeSpec
from cairn.scope import ScopeGuard, validate_manifest, validate_scope

from .conftest import make_engagement


class StaticResolver:
    def __init__(self, *ips: str):
        self.ips = list(ips)

    async def resolve_host(self, host: str) -> list[str]:
        return list(self.ips)


def test_scope_normalizes_wildcards_and_urls():
    rules = validate_scope(
        [
            ScopeSpec(kind="domain", value="*.Example.COM."),
            ScopeSpec(kind="url", value="HTTPS://Example.com:8443/app"),
        ]
    )
    assert rules[0]["value"] == "example.com"
    assert rules[0]["include_subdomains"] is True
    assert rules[1]["value"] == "https://example.com:8443/app"


@pytest.mark.parametrize(
    "spec",
    [
        ScopeSpec(kind="domain", value="https://example.com/path"),
        ScopeSpec(kind="url", value="ftp://example.com/"),
        ScopeSpec(kind="url", value="https://user:pass@example.com/"),
        ScopeSpec(kind="ip", value="169.254.169.254"),
        ScopeSpec(kind="cidr", value="169.254.0.0/16"),
        ScopeSpec(kind="cidr", value="0.0.0.0/0"),
    ],
)
def test_scope_rejects_dangerous_or_malformed_rules(spec):
    with pytest.raises(ScopeError):
        validate_scope([spec])


def test_manifest_requires_authorization_and_short_window():
    scope = validate_scope([ScopeSpec(kind="ip", value="127.0.0.1")])
    now = datetime.now(UTC)
    with pytest.raises(ScopeError, match="authorization_ref"):
        validate_manifest(
            authorized_by="Operator",
            authorization_ref=" ",
            starts_at=now.isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
            scope=scope,
        )
    with pytest.raises(ScopeError, match="Maximum engagement window"):
        validate_manifest(
            authorized_by="Operator",
            authorization_ref="AUTH-1",
            starts_at=now.isoformat(),
            expires_at=(now + timedelta(days=181)).isoformat(),
            scope=scope,
        )
    with pytest.raises(ScopeError, match="past"):
        validate_manifest(
            authorized_by="Operator",
            authorization_ref="AUTH-1",
            starts_at=(now - timedelta(days=2)).isoformat(),
            expires_at=(now - timedelta(days=1)).isoformat(),
            scope=scope,
        )


def test_guard_is_default_deny_and_excludes_win(db):
    engagement = make_engagement(
        db,
        scope=[
            ScopeSpec(kind="domain", value="example.com", include_subdomains=True),
            ScopeSpec(kind="domain", value="secret.example.com", mode="exclude"),
        ],
    )
    guard = ScopeGuard(engagement, resolver=StaticResolver("93.184.216.34"))
    assert guard.can_host("example.com")
    assert guard.can_host("www.example.com")
    assert not guard.can_host("secret.example.com")
    assert not guard.can_host("notexample.com")
    assert not guard.can_ip("127.0.0.1", 80)
    assert not guard.can_host("metadata.google.internal")


def test_guard_blocks_metadata_and_private_dns_rebinding(db):
    engagement = make_engagement(
        db,
        scope=[ScopeSpec(kind="domain", value="example.com", include_subdomains=True)],
    )
    guard = ScopeGuard(engagement, resolver=StaticResolver("169.254.169.254"))
    with pytest.raises(ScopeError):
        asyncio.run(guard.resolve("example.com"))

    guard = ScopeGuard(engagement, resolver=StaticResolver("127.0.0.1"))
    with pytest.raises(ScopeError, match="not authorized"):
        # A domain grant must not authorize a DNS rebind into loopback space.
        asyncio.run(guard.prepare("example.com", 80))


def test_explicit_loopback_scope_allows_local_lab(db):
    engagement = make_engagement(db, allowed_ports=(80, 8080))
    guard = ScopeGuard(engagement, resolver=StaticResolver("127.0.0.1"))
    target = asyncio.run(guard.prepare("127.0.0.1", 8080))
    assert target.ip == "127.0.0.1"
    assert target.url == "http://127.0.0.1:8080/"

    with pytest.raises(ScopeError, match="allowed_ports"):
        asyncio.run(guard.prepare("127.0.0.1", 22))


def test_guard_rejects_out_of_scope_urls_and_ports(db):
    engagement = make_engagement(
        db,
        scope=[ScopeSpec(kind="url", value="http://93.184.216.34:8080/app")],
        allowed_ports=(80, 8080),
    )
    guard = ScopeGuard(engagement, resolver=StaticResolver("93.184.216.34"))
    assert guard.can_url("http://93.184.216.34:8080/app/page")
    assert not guard.can_url("http://93.184.216.34:8080/other")
    assert not guard.can_url("http://93.184.216.34:9090/app")
    assert not guard.can_url("http://evil.example/app")


def test_scope_expansion_has_a_host_ceiling(db):
    engagement = make_engagement(db)
    rules = [
        {
            "kind": "cidr",
            "value": "10.0.0.0/8",
            "mode": "include",
            "include_subdomains": False,
        }
    ]
    engagement["scope"] = rules
    guard = ScopeGuard(engagement)
    with pytest.raises(SafetyError, match="host ceiling"):
        guard.iter_hosts(limit=4)
