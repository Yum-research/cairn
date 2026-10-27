from __future__ import annotations

import json

import pytest

from cairn.db import Database
from cairn.intel.confidence import ConfidenceEngine, apply_calibration, isotonic
from cairn.intel.features import build_features
from cairn.intel.learning import (
    MIN_EVAL_FOR_PROMOTION,
    MIN_LABELS_FOR_ISOTONIC,
    learning_overview,
    train_confidence_model,
)
from cairn.models import DetectorHit

from .conftest import make_engagement


def seed_labels(db: Database, engagement_id: str, count: int) -> None:
    run_id = db.create_run(engagement_id, "standard", {"source": "test"})
    for index in range(count):
        strong = index % 2 == 0
        features = build_features(
            "web.exposed_env",
            evidence_count=3 if strong else 1,
            independent_sources=2 if strong else 0,
            specificity=0.95 if strong else 0.25,
            direct=1.0 if strong else 0.2,
            soft404_clear=0.98 if strong else 0.2,
            coverage=0.9 if strong else 0.5,
            scope_certainty=0.98,
        )
        hit = DetectorHit(
            detector="web.exposed_env",
            title=f"Exposed environment file #{index}",
            category="information_disclosure",
            severity="high" if strong else "low",
            description="A test fixture observation.",
            remediation="Rotate secrets and remove the file.",
            features=features,
            discriminator=f"/.env.{index}",
        )
        finding_id, _ = db.upsert_finding(
            engagement_id=engagement_id,
            run_id=run_id,
            asset_id=None,
            hit=hit,
            asset_value="127.0.0.1",
            confidence=0.8 if strong else 0.4,
            explain=[],
            model_version=None,
            evidence_ids=[],
        )
        db.add_feedback(
            finding_id,
            "confirmed" if strong else "false_positive",
            analyst="test",
            note="synthetic calibration fixture",
        )


def test_apply_calibration_is_bounded_and_monotone():
    points = [[0.0, 0.05], [0.5, 0.4], [1.0, 0.95]]
    assert apply_calibration(0.1, points) == pytest.approx(0.12)
    assert apply_calibration(-1.0, points) == pytest.approx(0.05)
    assert apply_calibration(2.0, points) == pytest.approx(0.95)
    assert apply_calibration(0.5, points) == pytest.approx(0.4)
    assert apply_calibration(0.9, points) == pytest.approx(0.84)


def test_isotonic_pooling_is_monotone_and_weighted():
    curve = isotonic([(0.1, 0.0), (0.2, 1.0), (0.3, 0.0)], [1.0, 3.0, 1.0])
    ys = [y for _, y in curve]
    assert ys == sorted(ys)
    assert all(0.0 <= y <= 1.0 for y in ys)
    assert curve[0][0] == pytest.approx(0.1)


def test_training_requires_both_classes_and_enough_labels(db):
    engagement = make_engagement(db)
    assert train_confidence_model(db)["status"] == "insufficient"
    seed_labels(db, engagement["id"], 4)
    result = train_confidence_model(db)
    assert result["status"] == "insufficient"


def test_small_sample_is_honest_and_blocked_from_promotion(db):
    engagement = make_engagement(db)
    seed_labels(db, engagement["id"], 16)
    result = train_confidence_model(db, include_weak=False)
    assert result["status"] == "challenger"
    assert result["promoted"] is False
    metrics = result["metrics"]
    assert metrics["n_eval"] == 16
    assert metrics["calibration_active"] is False
    assert metrics["calibration_method"].startswith("identity")
    assert metrics["brier"] == metrics["brier_uncalibrated"]
    assert any("held-out human labels" in reason for reason in metrics["promotion_blockers"])
    assert result["model_id"] == db.list_models()[0]["id"]


def test_enough_labels_activates_isotonic_and_can_promote(db):
    engagement = make_engagement(db)
    seed_labels(db, engagement["id"], MIN_LABELS_FOR_ISOTONIC)
    result = train_confidence_model(db, include_weak=False)
    metrics = result["metrics"]
    assert metrics["n_eval"] >= MIN_EVAL_FOR_PROMOTION
    assert metrics["calibration_active"] is True
    assert metrics["calibration_method"].startswith("isotonic")
    assert metrics["brier_calibrated"] <= metrics["brier_uncalibrated"] + 0.001
    # The synthetic fixture is deliberately separable, so this challenger
    # should clear every gate and become the first champion.
    assert result["promoted"] is True
    assert result["status"] == "champion"
    assert db.champion_model()["id"] == result["model_id"]
    overview = learning_overview(db)
    assert overview["thresholds"]["min_eval"] == MIN_EVAL_FOR_PROMOTION
    assert overview["next_promotion_at"] >= MIN_EVAL_FOR_PROMOTION


def test_champion_engine_applies_calibration_and_explains(db):
    champion_id = db.add_model(
        kind="confidence",
        status="champion",
        n_labels=30,
        metrics={"brier_calibrated": 0.12},
        weights={"intercept": 1.0, "prior_logit": 0.0, "direct": 0.0},
        calibration={"points": [[0.0, 0.0], [1.0, 1.0]], "method": "identity"},
        parent_id=None,
    )
    engine = ConfidenceEngine(db)
    probability, factors, model_id = engine.score({"direct": 1.0})
    assert model_id == champion_id
    assert probability == pytest.approx(0.7310585786, abs=1e-6)
    assert factors
    assert factors[0]["model_version"] == champion_id
    assert json.dumps(factors)
