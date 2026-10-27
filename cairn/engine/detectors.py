from __future__ import annotations

import re

from ..models import DetectorHit
from ..redact import key_names_from_env
from .types import ContentProbe, WebSnapshot

_LOGIN_HINTS = re.compile(
    r"(?i)(sign\s*in|log\s*in|login|password|username|authenticate|administrator|admin\s*console)"
)
_HTML = re.compile(r"(?i)<html|<body|<!doctype")
_GIT_REF = re.compile(r"^(ref:\s+refs/|[0-9a-f]{40}\s*$)", re.M)
_TITLE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")


def extract_title(body: str) -> str:
    match = _TITLE.search(body or "")
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:180]


def security_header_hits(snapshot: WebSnapshot) -> list[DetectorHit]:
    headers = snapshot.main.header_map
    missing: list[str] = []
    csp = headers.get("content-security-policy", [""])[0]
    if "frame-ancestors" not in csp.lower() and "x-frame-options" not in headers:
        missing.append("frame-ancestors / X-Frame-Options")
    if snapshot.scheme == "https" and "strict-transport-security" not in headers:
        missing.append("Strict-Transport-Security")
    if not csp and _HTML.search(snapshot.main.body[:4000] or ""):
        missing.append("Content-Security-Policy")
    if "x-content-type-options" not in headers:
        missing.append("X-Content-Type-Options")
    if "referrer-policy" not in headers:
        missing.append("Referrer-Policy")
    if "permissions-policy" not in headers:
        missing.append("Permissions-Policy")
    if not missing:
        return []
    severity = "low" if any(
        h in missing for h in ("frame-ancestors / X-Frame-Options", "Strict-Transport-Security", "Content-Security-Policy")
    ) else "info"
    return [
        DetectorHit(
            detector="web.security_headers",
            title="Security response headers are incomplete",
            category="hardening",
            severity=severity,
            description=(
                "The response is missing one or more browser security headers: "
                + ", ".join(missing)
                + ". Missing headers do not prove exploitability, but they remove defence-in-depth controls."
            ),
            remediation=(
                "Set a restrictive Content-Security-Policy, HSTS on HTTPS origins, "
                "X-Content-Type-Options: nosniff, a frame-ancestors policy, Referrer-Policy, "
                "and Permissions-Policy appropriate to the application."
            ),
            evidence_ids=[snapshot.evidence_id] if snapshot.evidence_id else [],
            features={"specificity": 0.98, "direct": 1.0, "soft404_clear": 1.0, "coverage": 0.8},
            discriminator="|".join(sorted(missing)),
        )
    ]


def cookie_hits(snapshot: WebSnapshot) -> list[DetectorHit]:
    hits: list[DetectorHit] = []
    set_cookies = snapshot.main.header_map.get("set-cookie", [])
    for raw in set_cookies[:20]:
        first, *attributes = [part.strip() for part in raw.split(";")]
        if "=" not in first:
            continue
        name = first.split("=", 1)[0].strip()
        if not name:
            continue
        lowered = [a.lower() for a in attributes]
        missing: list[str] = []
        if snapshot.scheme == "https" and "secure" not in lowered:
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if not any(a.startswith("samesite") for a in lowered):
            missing.append("SameSite")
        if not missing:
            continue
        severity = "low" if "Secure" in missing or "HttpOnly" in missing else "info"
        hits.append(
            DetectorHit(
                detector="web.cookie_flags",
                title=f"Cookie protections are incomplete ({name})",
                category="hardening",
                severity=severity,
                description=(
                    f"Cookie {name!r} is missing: {', '.join(missing)}. "
                    "Cookie attributes reduce session theft and cross-site request risk."
                ),
                remediation=(
                    f"Set {', '.join(missing)} on cookie {name!r}; use __Host- prefixes for "
                    "high-value session cookies where compatible."
                ),
                evidence_ids=[snapshot.evidence_id] if snapshot.evidence_id else [],
                features={"specificity": 0.97, "direct": 1.0, "soft404_clear": 1.0},
                discriminator=name + "|" + "|".join(missing),
            )
        )
    return hits


def disclosure_hits(snapshot: WebSnapshot) -> list[DetectorHit]:
    headers = snapshot.main.header_map
    disclosed: list[str] = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        for value in headers.get(name, []):
            if re.search(r"\d+\.\d+", value):
                disclosed.append(f"{name}: {value}")
    if not disclosed:
        return []
    return [
        DetectorHit(
            detector="web.server_disclosure",
            title="Software version is disclosed in response headers",
            category="information_disclosure",
            severity="info",
            description=(
                "Response headers reveal specific software versions: " + "; ".join(disclosed) + ". "
                "Version disclosure narrows attacker research but is not a vulnerability by itself."
            ),
            remediation=(
                "Remove or genericize version-bearing headers (server_tokens off, remove X-Powered-By) "
                "and keep the disclosed components patched."
            ),
            evidence_ids=[snapshot.evidence_id] if snapshot.evidence_id else [],
            features={"specificity": 0.95, "direct": 1.0},
            discriminator="|".join(sorted(disclosed))[:300],
        )
    ]


def tls_hits(snapshot: WebSnapshot) -> list[DetectorHit]:
    tls = snapshot.tls or {}
    if not tls.get("connected"):
        return []
    hits: list[DetectorHit] = []
    evidence = [snapshot.tls_evidence_id] if snapshot.tls_evidence_id else []
    if not tls.get("verified"):
        error = str(tls.get("verification_error") or "certificate validation failed")
        if "hostname mismatch" in error.lower() or "doesn't match" in error.lower():
            reason = "certificate does not match the requested hostname"
        elif "expired" in error.lower():
            reason = "certificate is expired"
        elif "self-signed" in error.lower() or "self signed" in error.lower():
            reason = "certificate is self-signed"
        elif "unable to get local issuer" in error.lower():
            reason = "certificate chain is incomplete or untrusted"
        else:
            reason = "certificate could not be validated"
        hits.append(
            DetectorHit(
                detector="tls.certificate_untrusted",
                title="TLS certificate is not trusted",
                category="transport_security",
                severity="medium",
                description=(
                    f"The TLS certificate for {snapshot.host}:{snapshot.port} is not trusted: {reason}. "
                    "Browsers and API clients may warn or refuse to connect."
                ),
                remediation=(
                    "Install a certificate from a trusted CA, include the full intermediate chain, "
                    "and monitor expiry automatically."
                ),
                evidence_ids=evidence,
                features={"specificity": 0.99, "direct": 1.0, "coverage": 0.9},
                discriminator="untrusted",
            )
        )
    days = (tls.get("certificate") or {}).get("days_remaining")
    if isinstance(days, int) and 0 <= days <= 30:
        hits.append(
            DetectorHit(
                detector="tls.certificate_expiry",
                title="TLS certificate expires soon",
                category="transport_security",
                severity="low",
                description=f"The TLS certificate expires in {days} day(s).",
                remediation="Automate certificate renewal and renew before expiry.",
                evidence_ids=evidence,
                features={"specificity": 0.99, "direct": 1.0},
                discriminator=f"days-{days}",
            )
        )
    protocol = str(tls.get("protocol") or "")
    if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        hits.append(
            DetectorHit(
                detector="tls.protocol",
                title="Legacy TLS protocol is negotiated",
                category="transport_security",
                severity="medium",
                description=f"The service negotiated {protocol}, which is deprecated and lacks modern security properties.",
                remediation="Require TLS 1.2 or newer, disable legacy protocol versions, and retest old clients.",
                evidence_ids=evidence,
                features={"specificity": 0.99, "direct": 1.0},
                discriminator=protocol,
            )
        )
    return hits


def content_hits(probe: ContentProbe) -> list[DetectorHit]:
    entry = probe.entry
    result = probe.result
    probe_type = entry.get("probe", "generic")
    if result.status is None or result.error:
        return []
    status = result.status
    body = result.body or ""
    raw = result.raw or b""
    lowered = body.lower()
    title = extract_title(body)
    if probe.soft404:
        # Strong signatures can still be real on a catch-all host, but the
        # baseline materially reduces confidence. We keep only unambiguous
        # structural signatures.
        strong = probe_type in ("git", "git_config", "env", "svn", "hg", "ds_store")
        if not strong:
            return []
    evidence = [probe.evidence_id] if probe.evidence_id else []
    base_features = {"direct": 1.0, "soft404_clear": 0.35 if probe.soft404 else 1.0}
    severity = entry.get("severity", "info")
    title_cfg = entry.get("title", "Exposed resource")
    category = entry.get("category", "information_disclosure")
    remediation = entry.get("remediation", "Review the exposure and restrict access as appropriate.")
    hit: DetectorHit | None = None

    if probe_type == "git":
        if status == 200 and _GIT_REF.search(body[:500]):
            hit = DetectorHit(
                detector="web.exposed_git",
                title="Exposed Git repository metadata",
                category="source_exposure",
                severity="high",
                description=(
                    "The server returned a valid Git ref for /.git/HEAD, indicating source-control "
                    "metadata is deployed in the web root. Attackers can reconstruct source code and "
                    "sometimes credentials from the repository."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.99, "corroboration": 0.7},
                discriminator="/.git/HEAD",
            )
    elif probe_type == "git_config":
        if status == 200 and "[core]" in lowered and "repositoryformatversion" in lowered:
            hit = DetectorHit(
                detector="web.exposed_git",
                title="Exposed Git configuration",
                category="source_exposure",
                severity="high",
                description=(
                    "The Git configuration file is readable. It can reveal remote URLs, branch "
                    "configuration, and deployment structure."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.99, "corroboration": 0.8},
                discriminator="/.git/config",
            )
    elif probe_type == "env":
        keys = key_names_from_env(body)
        probe.key_names = keys
        if status == 200 and len(keys) >= 2 and not _HTML.search(body[:1000]):
            sensitive = [k for k in keys if re.search(r"(?i)(KEY|TOKEN|SECRET|PASS|DB_|DATABASE|AWS|SMTP|STRIPE)", k)]
            hit = DetectorHit(
                detector="web.exposed_env",
                title="Exposed environment file",
                category="secret_exposure",
                severity="high",
                description=(
                    "The server returned an environment file with "
                    f"{len(keys)} variable names"
                    + (f", including sensitive-looking names: {', '.join(sensitive[:6])}" if sensitive else "")
                    + ". Values are redacted by Cairn; rotate any credentials it contained."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={
                    **base_features,
                    "specificity": 0.98,
                    "corroboration": 0.75 if sensitive else 0.5,
                },
                discriminator=entry.get("path", "/.env"),
            )
    elif probe_type == "ds_store":
        if status == 200 and (b"Bud1" in raw[:2000] or "Bud1" in body[:2000]):
            hit = DetectorHit(
                detector="web.directory_listing",
                title="Exposed macOS metadata file",
                category="information_disclosure",
                severity="low",
                description=(
                    ".DS_Store is downloadable. It can disclose file and directory names from a "
                    "developer workstation that were included in the deployment."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.95},
                discriminator="/.DS_Store",
            )
    elif probe_type == "server_status":
        if status == 200 and ("apache server status" in lowered or "server status" in lowered):
            hit = DetectorHit(
                detector="web.directory_listing",
                title="Apache server-status is exposed",
                category="information_disclosure",
                severity="medium",
                description=(
                    "mod_status output is publicly reachable and may disclose request paths, client "
                    "addresses, and worker state."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.95},
                discriminator="/server-status",
            )
    elif probe_type == "phpinfo":
        if status == 200 and "php version" in lowered and "phpinfo" in lowered:
            hit = DetectorHit(
                detector="web.exposed_debug",
                title="phpinfo() output is exposed",
                category="information_disclosure",
                severity="medium",
                description=(
                    "A phpinfo page discloses build options, paths, extensions, and sometimes "
                    "environment values."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.98},
                discriminator="/phpinfo.php",
            )
    elif probe_type == "actuator":
        if status == 200 and ("propertysources" in lowered or '"activeprofiles"' in lowered):
            hit = DetectorHit(
                detector="web.exposed_debug",
                title="Spring Boot actuator environment is exposed",
                category="secret_exposure",
                severity="high",
                description=(
                    "The Spring Boot /actuator/env endpoint is readable. It can expose configuration "
                    "values and credentials, which are redacted in Cairn evidence."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.98, "corroboration": 0.7},
                discriminator="/actuator/env",
            )
    elif probe_type == "actuator_index":
        if status == 200 and '"_links"' in body:
            hit = DetectorHit(
                detector="web.exposed_debug",
                title="Spring Boot actuator index is exposed",
                category="information_disclosure",
                severity="low",
                description="The actuator index advertises management endpoints that may be sensitive.",
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.9},
                discriminator="/actuator",
            )
    elif probe_type == "swagger":
        if status == 200 and ("swagger" in lowered or "openapi" in lowered):
            hit = DetectorHit(
                detector="web.api_docs",
                title=title_cfg,
                category=category,
                severity=severity,
                description=(
                    "API documentation is publicly reachable. It reveals routes, parameters, and "
                    "authentication schemes, which improves an attacker's map of the application."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.9},
                discriminator=entry.get("path", "/swagger"),
            )
    elif probe_type == "directory":
        if status == 200 and ("index of /" in lowered or "directory listing for" in lowered):
            hit = DetectorHit(
                detector="web.directory_listing",
                title="Directory listing is enabled",
                category="data_exposure",
                severity=severity,
                description=(
                    f"Auto-indexing is enabled at {entry.get('path')}. Directory listings expose file "
                    "names that may not be linked from the application."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.97},
                discriminator=entry.get("path", "/"),
            )
    elif probe_type == "admin":
        hints = _LOGIN_HINTS.search(body[:20000]) is not None
        lookup = title.lower()
        if status in (401, 403):
            hit = DetectorHit(
                detector="web.admin_interface",
                title=title_cfg,
                category="administrative_surface",
                severity="low",
                description=(
                    f"The administrative path {entry.get('path')} is reachable but protected "
                    f"(HTTP {status}). This confirms the interface exists on the public surface."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.85, "direct": 1.0},
                discriminator=entry.get("path", "/admin") + ":protected",
            )
        elif status == 200 and hints and not probe.soft404 and any(
            word in (body[:20000] + " " + lookup) for word in ("sign in", "log in", "login", "password")
        ):
            hit = DetectorHit(
                detector="web.admin_interface",
                title=title_cfg,
                category="administrative_surface",
                severity=severity,
                description=(
                    f"A login interface is reachable at {entry.get('path')}. Administrative surfaces "
                    "should be restricted and monitored even when authentication is enforced."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.72, "direct": 0.9},
                discriminator=entry.get("path", "/admin"),
            )
    elif probe_type == "backup":
        ctype = (result.content_type or "").lower()
        if status == 200 and len(raw) > 200 and "text/html" not in ctype and not probe.soft404:
            hit = DetectorHit(
                detector="web.exposed_backup",
                title=title_cfg,
                category="data_exposure",
                severity=severity,
                description=(
                    f"A non-HTML archive/download ({ctype or 'unknown type'}, {len(raw)} bytes read) "
                    f"was returned for {entry.get('path')}. It may contain source, data, or credentials."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.85},
                discriminator=entry.get("path", "/backup"),
            )
    elif probe_type == "svn":
        if status == 200 and (body.startswith("10\n") or "dir\n" in body[:200]):
            hit = DetectorHit(
                detector="web.exposed_git",
                title="Exposed Subversion metadata",
                category="source_exposure",
                severity=severity,
                description="Subversion administrative metadata is readable from the web root.",
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.9},
                discriminator="/.svn/entries",
            )
    elif probe_type == "hg":
        if status == 200 and ("revlogv1" in lowered or "dotencode" in lowered):
            hit = DetectorHit(
                detector="web.exposed_git",
                title="Exposed Mercurial metadata",
                category="source_exposure",
                severity=severity,
                description="Mercurial repository metadata is readable from the web root.",
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.9},
                discriminator="/.hg/requires",
            )
    elif probe_type == "source":
        if status == 200 and not probe.soft404 and not _HTML.search(body[:200]):
            if (entry.get("path") == "/Dockerfile" and body.lstrip().upper().startswith("FROM ")) or (
                entry.get("path") == "/docker-compose.yml" and "services:" in lowered
            ) or (entry.get("path") == "/package.json" and '"name"' in body and '"version"' in body) or (
                entry.get("path") == "/composer.json" and '"require"' in body
            ):
                hit = DetectorHit(
                    detector="web.exposed_source",
                    title=title_cfg,
                    category="source_exposure",
                    severity=severity,
                    description=f"A build or package manifest is readable at {entry.get('path')}.",
                    remediation=remediation,
                    evidence_ids=evidence,
                    features={**base_features, "specificity": 0.9},
                    discriminator=entry.get("path", "/Dockerfile"),
                )
    elif probe_type == "metrics":
        if status == 200 and ("# help " in lowered or "# type " in lowered):
            hit = DetectorHit(
                detector="web.exposed_debug",
                title="Metrics endpoint is publicly reachable",
                category="information_disclosure",
                severity=severity,
                description=(
                    "Prometheus-style metrics are public. Labels can reveal internal service names, "
                    "versions, and traffic patterns."
                ),
                remediation=remediation,
                evidence_ids=evidence,
                features={**base_features, "specificity": 0.9},
                discriminator="/metrics",
            )
    elif probe_type == "config":
        if status == 200 and not probe.soft404 and ('"' in body or ":" in body) and not _HTML.search(body[:300]):
            if re.search(r"(?i)(api|auth|token|key|secret|database|endpoint)", body[:8000]):
                hit = DetectorHit(
                    detector="web.exposed_config",
                    title=title_cfg,
                    category="information_disclosure",
                    severity=severity,
                    description=(
                        "A configuration document is public and contains configuration-like keys. "
                        "Values are redacted in evidence."
                    ),
                    remediation=remediation,
                    evidence_ids=evidence,
                    features={**base_features, "specificity": 0.8},
                    discriminator="/config.json",
                )
    return [hit] if hit else []


def cors_hit(snapshot: WebSnapshot, *, reflected: bool, credentials: bool) -> list[DetectorHit]:
    if not (reflected and credentials):
        return []
    return [
        DetectorHit(
            detector="web.cors_credentials",
            title="Cross-origin access with credentials is allowed",
            category="misconfiguration",
            severity="medium",
            description=(
                "The origin reflected the supplied Origin header while allowing credentials. "
                "If this applies to authenticated endpoints, hostile sites may read authenticated "
                "responses; validation with a non-production account is required."
            ),
            remediation=(
                "Use an explicit origin allow-list, never reflect arbitrary origins with credentials, "
                "and keep Access-Control-Allow-Credentials disabled unless required."
            ),
            evidence_ids=[snapshot.evidence_id] if snapshot.evidence_id else [],
            features={"specificity": 0.7, "direct": 0.8, "coverage": 0.6},
            discriminator="cors-reflection-credentials",
        )
    ]


def sensitive_port_hit(
    host: str,
    port: int,
    service: str | None,
    banner: str | None,
    evidence_id: str | None,
) -> list[DetectorHit]:
    if port not in (23, 445, 1433, 2375, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017):
        return []
    label = {
        23: "Telnet", 445: "SMB", 1433: "Microsoft SQL Server", 2375: "Docker API",
        3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL", 5900: "VNC",
        5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
        27017: "MongoDB",
    }.get(port, service or f"service on {port}")
    severity = "high" if port in (23, 2375, 6379, 11211, 27017) else "medium"
    return [
        DetectorHit(
            detector="port.sensitive_service",
            title=f"{label} service is reachable",
            category="network_exposure",
            severity=severity,
            description=(
                f"TCP port {port} is open on {host} and was identified as {label}. Cairn did not "
                "attempt authentication or exploitation; exposure alone is not proof of unauthorized access."
            ),
            remediation=(
                "Restrict the service to management networks, require strong authentication, "
                "and verify that no default or empty credentials are configured."
            ),
            evidence_ids=[evidence_id] if evidence_id else [],
            features={"specificity": 0.9 if banner else 0.72, "direct": 1.0, "coverage": 0.9},
            discriminator=f"tcp-{port}",
        )
    ]


def dangling_cname_hit(
    host: str,
    cname: str,
    provider: str | None,
    evidence_id: str | None,
) -> list[DetectorHit]:
    return [
        DetectorHit(
            detector="dns.dangling_cname",
            title="CNAME target does not resolve",
            category="subdomain_takeover",
            severity="medium" if provider else "low",
            description=(
                f"{host} is an alias for {cname}, which does not currently resolve. "
                + (
                    f"The target belongs to a known hosted provider ({provider}); if the resource is "
                    "unclaimed, an attacker may be able to register it. Provider-specific validation "
                    "is required before claiming takeover."
                    if provider
                    else "Dangling aliases can become takeover paths if the target is claimable."
                )
            ),
            remediation=(
                "Remove the dangling DNS record or re-create the provider resource, then add "
                "ownership verification and DNS change monitoring."
            ),
            evidence_ids=[evidence_id] if evidence_id else [],
            features={"specificity": 0.8 if provider else 0.55, "direct": 1.0, "coverage": 0.7},
            discriminator=f"cname-{cname}",
        )
    ]
