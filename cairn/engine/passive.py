from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import quote

import httpx

from ..config import USER_AGENT
from ..scope import ScopeGuard

CRT_URL = "https://crt.sh/?q={query}&output=json&exclude=expired"
RDAP_URL = "https://rdap.org/domain/{domain}"

CLOUD_SUFFIXES = (
    "github.io",
    "herokuapp.com",
    "s3.amazonaws.com",
    "s3-website",
    "azurewebsites.net",
    "cloudapp.azure.com",
    "cloudfront.net",
    "fastly.net",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "web.app",
    "firebaseapp.com",
    "myshopify.com",
    "statuspage.io",
    "zendesk.com",
    "readthedocs.io",
    "surge.sh",
    "bitbucket.io",
    "wordpress.com",
    "ghost.io",
    "trafficmanager.net",
    "blob.core.windows.net",
)


class PassiveIntel:
    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": USER_AGENT, "Accept": "application/json,text/plain,*/*"},
            follow_redirects=True,
            limits=httpx.Limits(max_connections=4),
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def certificate_transparency(self, domain: str) -> tuple[list[str], dict[str, Any]]:
        url = CRT_URL.format(query=quote(f"%.{domain}"))
        try:
            response = await self.client.get(url)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            return [], {"url": url, "error": str(exc)[:500]}
        names: set[str] = set()
        for entry in data if isinstance(data, list) else []:
            for raw in str(entry.get("name_value", "")).splitlines():
                name = raw.strip().lower().lstrip("*.").rstrip(".")
                if name and _valid_hostname(name) and name.endswith(domain):
                    names.add(name)
            if len(names) >= 1000:
                break
        return sorted(names), {
            "url": url,
            "records": len(data) if isinstance(data, list) else 0,
            "names": len(names),
            "excerpt": "\n".join(sorted(names)[:80]),
        }

    async def rdap(self, domain: str) -> dict[str, Any] | None:
        url = RDAP_URL.format(domain=domain)
        try:
            response = await self.client.get(url)
            if response.status_code != 200:
                return None
            data = response.json()
        except (httpx.HTTPError, ValueError):
            return None
        events = {}
        for event in data.get("events", []):
            action = str(event.get("eventAction", ""))
            date = event.get("eventDate")
            if action and date:
                events[action] = date
        entities = []
        for entity in data.get("entities", [])[:12]:
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [None, []])
            name = ""
            for item in (vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []):
                if item and item[0] == "fn" and len(item) > 3:
                    name = str(item[3])
            if roles or name:
                entities.append({"name": name, "roles": roles})
        return {
            "url": url,
            "handle": data.get("handle"),
            "status": data.get("status", []),
            "events": events,
            "nameservers": [n.get("ldhName") for n in data.get("nameservers", []) if n.get("ldhName")],
            "entities": entities,
            "secure_dns": data.get("secureDNS", {}),
        }


async def enumerate_subdomains(
    guard: ScopeGuard,
    resolver: Any,
    domain: str,
    *,
    wordlist: tuple[str, ...],
    limit: int = 200,
    concurrency: int = 20,
) -> tuple[list[str], dict[str, Any]]:
    """Active DNS discovery, only inside a wildcard-scoped domain.

    A random-label probe detects wildcard DNS. If wildcard DNS is present,
    brute-force results are not trusted and the function returns no names.
    """

    if not guard.can_host(f"cairn-{__import__('secrets').token_hex(4)}.{domain}"):
        return [], {"skipped": "no wildcard scope for subdomain enumeration"}
    if guard.can_host(f"cairn-probe-{__import__('secrets').token_hex(4)}.{domain}"):
        # A random label clearly inside the wildcard. Resolve it to distinguish
        # policy allowance from wildcard DNS.
        pass
    try:
        wildcard_ips = await resolver.resolve_host(
            f"cairn-wildcard-{__import__('secrets').token_hex(4)}.{domain}"
        )
    except Exception:
        wildcard_ips = []
    if wildcard_ips:
        return [], {
            "skipped": "wildcard DNS detected",
            "wildcard_ips": wildcard_ips[:5],
        }
    semaphore = asyncio.Semaphore(concurrency)
    found: list[str] = []
    lock = asyncio.Lock()

    async def probe(word: str) -> None:
        host = f"{word}.{domain}"
        if not guard.can_host(host):
            return
        async with semaphore:
            try:
                ips = await resolver.resolve_host(host)
            except Exception:
                return
        if not ips:
            return
        async with lock:
            if len(found) < limit:
                found.append(host)

    await asyncio.gather(*(probe(word) for word in wordlist[:500]))
    return sorted(set(found)), {"tested": len(wordlist[:500]), "found": len(found)}


def provider_for_cname(cname: str) -> str | None:
    value = cname.lower().rstrip(".")
    for suffix in CLOUD_SUFFIXES:
        if value == suffix or value.endswith("." + suffix):
            return suffix
    return None


def _valid_hostname(name: str) -> bool:
    if len(name) > 253 or "." not in name:
        return False
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", name))
