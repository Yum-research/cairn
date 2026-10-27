from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any

from .config import data_path
from .models import SEVERITIES


@lru_cache(maxsize=1)
def content_paths() -> tuple[dict[str, Any], ...]:
    raw = json.loads((data_path("content_paths.json")).read_text(encoding="utf-8"))
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw.get("paths", []):
        path = str(item.get("path", "")).strip()
        if not path.startswith("/") or path in seen:
            continue
        seen.add(path)
        entry = dict(item)
        entry.setdefault("probe", "generic")
        entry.setdefault("weight", 0.3)
        entry.setdefault("mandatory", False)
        severity = str(entry.get("severity", "info")).strip()
        entry["severity"] = severity if severity in SEVERITIES else "info"
        out.append(entry)
    return tuple(out)


@lru_cache(maxsize=1)
def subdomain_wordlist() -> tuple[str, ...]:
    raw = json.loads((data_path("content_paths.json")).read_text(encoding="utf-8"))
    return tuple(dict.fromkeys(str(w).strip().lower() for w in raw.get("wordlist", []) if str(w).strip()))


@lru_cache(maxsize=1)
def tech_signatures() -> tuple[dict[str, Any], ...]:
    raw = json.loads((data_path("tech_signatures.json")).read_text(encoding="utf-8"))
    compiled: list[dict[str, Any]] = []
    for signature in raw.get("signatures", []):
        entry = dict(signature)
        entry["_headers"] = {
            header.lower(): re.compile(pattern, re.I | re.S)
            for header, pattern in (signature.get("headers") or {}).items()
        }
        if signature.get("body"):
            entry["_body"] = re.compile(signature["body"], re.I | re.S)
        compiled.append(entry)
    return tuple(compiled)


def path_catalog(limit: int | None = None, deep: bool = False) -> list[dict[str, Any]]:
    paths = list(content_paths())
    if not deep:
        paths = [p for p in paths if p.get("mandatory") or p.get("weight", 0) >= 0.55]
    if limit is not None:
        paths = paths[:limit]
    return paths
