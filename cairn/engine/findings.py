from __future__ import annotations

from ..db import Database
from ..intel.confidence import ConfidenceEngine
from ..intel.features import build_features
from ..models import DetectorHit
from .recorder import RunRecorder


class FindingEmitter:
    def __init__(
        self,
        db: Database,
        recorder: RunRecorder,
        confidence: ConfidenceEngine,
        *,
        engagement_id: str,
        run_id: str,
    ):
        self.db = db
        self.recorder = recorder
        self.confidence = confidence
        self.engagement_id = engagement_id
        self.run_id = run_id
        self.created = 0
        self.updated = 0

    def emit(
        self,
        hit: DetectorHit,
        *,
        asset_id: str | None,
        asset_value: str,
        coverage: float = 0.7,
    ) -> str:
        evidence_ids = list(dict.fromkeys(hit.evidence_ids))
        for draft in hit.evidence:
            evidence_id = self.recorder.evidence(
                draft.get("kind", "detector"),
                draft.get("source", hit.detector),
                draft.get("locator", asset_value),
                draft.get("content", ""),
                raw=draft.get("raw"),
            )
            if evidence_id:
                evidence_ids.append(evidence_id)
        features = build_features(
            hit.detector,
            evidence_count=max(1, len(evidence_ids)),
            independent_sources=2 if len(evidence_ids) >= 2 else 1,
            coverage=coverage,
            overrides=hit.features,
        )
        probability, explain, model_version = self.confidence.score(features)
        hit.features = features
        finding_id, is_new = self.db.upsert_finding(
            engagement_id=self.engagement_id,
            run_id=self.run_id,
            asset_id=asset_id,
            hit=hit,
            asset_value=asset_value,
            confidence=probability,
            explain=explain,
            model_version=model_version,
            evidence_ids=evidence_ids,
        )
        self.db.record_probe(hit.detector, "detector", True, reward=1.0)
        if is_new:
            self.created += 1
            self.recorder.event(
                "finding",
                f"New {hit.severity} finding: {hit.title}",
                data={"finding_id": finding_id, "detector": hit.detector, "confidence": round(probability, 3)},
            )
        else:
            self.updated += 1
        return finding_id
