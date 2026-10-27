from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from ..config import MAX_EVIDENCE_PER_RUN
from ..db import Database
from ..net.ratelimit import StatsCounter
from ..redact import redact_text


class RunRecorder:
    """Writes observations/evidence with redaction and per-run budgets."""

    def __init__(
        self,
        db: Database,
        *,
        engagement_id: str,
        run_id: str,
        max_evidence: int = MAX_EVIDENCE_PER_RUN,
    ):
        self.db = db
        self.engagement_id = engagement_id
        self.run_id = run_id
        self.max_evidence = max_evidence
        self.evidence_count = 0
        self.stats = StatsCounter()
        self._budget_warned = False

    def evidence(
        self,
        kind: str,
        source: str,
        locator: str,
        content: str | bytes,
        *,
        raw: bytes | None = None,
    ) -> str | None:
        if self.evidence_count >= self.max_evidence:
            if not self._budget_warned:
                self.db.add_event(
                    self.run_id,
                    self.engagement_id,
                    "evidence",
                    f"Evidence budget reached ({self.max_evidence}); further evidence is metadata-only",
                    level="warning",
                )
                self._budget_warned = True
            return None
        if isinstance(content, bytes):
            raw_bytes = raw if raw is not None else content
            text = content.decode("utf-8", "replace")
        else:
            text = content
            raw_bytes = raw if raw is not None else content.encode("utf-8", "replace")
        excerpt = redact_text(text)
        content_sha = hashlib.sha256(raw_bytes).hexdigest()
        evidence_id = self.db.add_evidence(
            engagement_id=self.engagement_id,
            run_id=self.run_id,
            kind=kind,
            source=source,
            locator=locator,
            content_sha256=content_sha,
            excerpt=excerpt,
        )
        self.evidence_count += 1
        self.stats.incr("evidence")
        return evidence_id

    def observation(
        self,
        *,
        asset_id: str | None,
        kind: str,
        source: str,
        data: dict[str, Any],
        evidence_id: str | None = None,
        confidence: float = 1.0,
        fingerprint: str | None = None,
    ) -> str:
        observation_id = self.db.add_observation(
            engagement_id=self.engagement_id,
            run_id=self.run_id,
            asset_id=asset_id,
            kind=kind,
            source=source,
            data=data,
            evidence_id=evidence_id,
            confidence=confidence,
            fingerprint=fingerprint,
        )
        self.stats.incr("observations")
        return observation_id

    def event(self, kind: str, message: str, level: str = "info", data: dict[str, Any] | None = None) -> None:
        self.db.add_event(self.run_id, self.engagement_id, kind, message, level=level, data=data)

    def asset(
        self,
        kind: str,
        value: str,
        *,
        host: str | None = None,
        port: int | None = None,
        scheme: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> str:
        asset_id = self.db.upsert_asset(
            self.engagement_id,
            kind,
            value,
            host=host,
            port=port,
            scheme=scheme,
            meta=meta or {},
        )
        self.stats.incr("assets")
        return asset_id


@dataclass
class CoverageTracker:
    expected: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    achieved: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    skipped: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    failures: list[str] = field(default_factory=list)
    weights: dict[str, float] = field(
        default_factory=lambda: {"dns": 0.15, "ports": 0.35, "http": 0.30, "content": 0.20}
    )

    def expect(self, category: str, count: int = 1) -> None:
        self.expected[category] += count

    def achieve(self, category: str, count: int = 1) -> None:
        self.achieved[category] += count

    def skip(self, category: str, reason: str, count: int = 1) -> None:
        self.skipped[category] += count
        self.failures.append(reason)

    def fail(self, category: str, reason: str, count: int = 1) -> None:
        self.skipped[category] += count
        self.failures.append(reason)

    def score(self) -> float:
        total_weight = 0.0
        score = 0.0
        for category, weight in self.weights.items():
            expected = self.expected.get(category, 0)
            if expected <= 0:
                continue
            total_weight += weight
            score += weight * min(1.0, self.achieved.get(category, 0) / expected)
        if total_weight <= 0:
            return 0.0
        return round(score / total_weight, 4)

    def to_dict(self) -> dict[str, Any]:
        categories = {}
        for category in self.weights:
            expected = self.expected.get(category, 0)
            if expected <= 0:
                continue
            categories[category] = {
                "expected": expected,
                "achieved": self.achieved.get(category, 0),
                "skipped": self.skipped.get(category, 0),
                "percent": round(100 * min(1.0, self.achieved.get(category, 0) / expected), 1),
            }
        return {
            "score": self.score(),
            "categories": categories,
            "warnings": self.failures[:40],
            "interpretation": "Coverage is the weighted success of planned probes, not proof that untested paths are safe.",
        }
