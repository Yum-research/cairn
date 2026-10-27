from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .config import MAX_EXCERPT

_REDACTED = "[REDACTED]"

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Authorization / bearer tokens
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/\-=]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*)(?!bearer)[^\r\n,;]{4,}"), r"\1[REDACTED]"),
    # key=value style secrets, keeps names for evidence
    (
        re.compile(
            r"(?i)\b(api[_-]?key|secret|client[_-]?secret|password|passwd|pwd|token|access[_-]?key|"
            r"private[_-]?key|session[_-]?id|auth[_-]?key|jwt)(\s*[:=]\s*)([\"']?)([^\s\"'&;,]{3,})\3"
        ),
        r"\1\2\3[REDACTED]\3",
    ),
    # Cookies: keep attributes after the first pair, redact values
    (
        re.compile(r"(?i)\b(set-cookie|cookie)\s*:\s*([^=\s;]+)=([^;,\r\n]+)"),
        r"\1: \2=[REDACTED]",
    ),
    # Credentials embedded in URLs
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    # Private keys and long opaque tokens
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED AWS KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED SLACK TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "[REDACTED API KEY]"),
)

_SENSITIVE_QUERY_KEYS = re.compile(
    r"(?i)(token|key|secret|password|passwd|pwd|auth|session|jwt|signature|sig|code)$"
)


def redact_text(value: str, limit: int = MAX_EXCERPT) -> str:
    """Redact likely credentials while preserving enough evidence to verify.

    Cairn never stores full secret values. Keeping key names and structural
    context is sufficient for a finding, and dramatically reduces the blast
    radius of the evidence database itself.
    """

    text = value or ""
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    if len(text) > limit:
        text = text[:limit] + f"\n... [truncated, {len(text) - limit} bytes omitted]"
    return text


def redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return redact_text(url)
    query = []
    for key, val in parse_qsl(parts.query, keep_blank_values=True):
        query.append((key, _REDACTED if _SENSITIVE_QUERY_KEYS.search(key) else val))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def key_names_from_env(text: str, limit: int = 60) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name = line.split("=", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,80}", name):
            names.append(name)
        if len(names) >= limit:
            break
    return names
