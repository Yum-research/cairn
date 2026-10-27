from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..net.http import HTTPResult


@dataclass
class ContentProbe:
    entry: dict[str, Any]
    url: str
    result: HTTPResult
    evidence_id: str | None = None
    soft404: bool = False
    key_names: list[str] = field(default_factory=list)


@dataclass
class WebSnapshot:
    host: str
    port: int
    scheme: str
    base_url: str
    final_url: str
    main: HTTPResult
    title: str
    technologies: list[dict[str, Any]]
    tls: dict[str, Any] | None
    content: list[ContentProbe]
    baseline: HTTPResult | None
    evidence_id: str | None = None
    tls_evidence_id: str | None = None

    def to_meta(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "base_url": self.base_url,
            "final_url": self.final_url,
            "title": self.title,
            "technologies": self.technologies,
            "tls": self.tls,
            "http": self.main.to_meta(),
            "content_probes": [
                {
                    "path": probe.entry["path"],
                    "status": probe.result.status,
                    "content_type": probe.result.content_type,
                    "length": len(probe.result.raw),
                    "soft404": probe.soft404,
                }
                for probe in self.content
            ],
        }
