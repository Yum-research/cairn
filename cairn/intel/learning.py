from __future__ import annotations

import json
import math
import random
from collections import defaultdict
from typing import Any

from ..db import Database
from ..models import band_for
from .confidence import ConfidenceEngine, isotonic
from .features import FEATURE_ORDER, detector_prior, logit, sigmoid, vectorize

MIN_LABELS_TO_PROMOTE = 15
MIN_EVAL_FOR_PROMOTION = 30
MIN_LABELS_FOR_ISOTONIC = 30
MAX_ECE_FOR_PROMOTION = 0.15
MIN_IMPROVEMENT = 0.005
BASELINE_MARGIN = 0.002


def train_confidence_model(
    db: Database,
    *,
    include_weak: bool = True,
    seed: int = 42,
    min_labels: int = MIN_LABELS_TO_PROMOTE,
) -> dict[str, Any]:
    """Train a challenger from analyst verdicts and promote only if it wins.

    Labels are human verdicts. A small, capped set of high-confidence,
    independently-corroborated findings may be used as weak positives (weight
    0.2) once there is enough human signal. Weak labels never appear in the
    evaluation set, so the reported metrics remain human-grounded.
    """

    human = db.feedback_training_rows()
    if len(human) < min_labels:
        return {
            "status": "insufficient",
            "reason": f"{len(human)} labels; {min_labels} required",
            "labels": len(human),
        }
    labeled: list[dict[str, Any]] = []
    for row in human:
        verdict = row["verdict"]
        label = 0 if verdict == "false_positive" else 1
        weight = 0.75 if verdict == "accepted_risk" else 1.0
        weight *= min(1.0, max(0.1, float(row.get("weight") or 1.0)))
        labeled.append(
            {
                "features": row["features"],
                "label": label,
                "weight": weight,
                "detector": row["detector"],
                "created_at": row["created_at"],
                "weak": False,
            }
        )
    weak_count = 0
    if include_weak and len(human) >= 10:
        weak_rows = db.query(
            "SELECT features_json, detector, first_seen FROM findings "
            "WHERE status='open' AND confidence>=0.92 "
            "AND NOT EXISTS(SELECT 1 FROM feedback fb WHERE fb.finding_id=findings.id) "
            "ORDER BY confidence DESC LIMIT ?",
            (max(2, len(human) // 3),),
        )
        for row in weak_rows:
            features = json.loads(row["features_json"] or "{}")
            if float(features.get("corroboration", 0)) < 0.66:
                continue
            if float(features.get("specificity", 0)) < 0.8:
                continue
            labeled.append(
                {
                    "features": features,
                    "label": 1,
                    "weight": 0.2,
                    "detector": row["detector"],
                    "created_at": row["first_seen"],
                    "weak": True,
                }
            )
            weak_count += 1
    if len(labeled) < min_labels:
        return {"status": "insufficient", "reason": "not enough usable labels", "labels": len(labeled)}

    labels = [row["label"] for row in labeled]
    if len(set(labels)) < 2:
        return {
            "status": "insufficient",
            "reason": "both confirmed and false-positive labels are required",
            "labels": len(labels),
        }

    rng = random.Random(seed)
    indices = list(range(len(labeled)))
    rng.shuffle(indices)
    folds = 5
    oof: list[float | None] = [None] * len(labeled)
    for fold in range(folds):
        val_idx = {idx for idx in indices if idx % folds == fold}
        if not val_idx or len(val_idx) >= len(labeled):
            continue
        train_idx = [idx for idx in range(len(labeled)) if idx not in val_idx]
        model = _fit_logistic([labeled[i] for i in train_idx])
        for i in val_idx:
            oof[i] = _predict(model, labeled[i]["features"])

    evaluable = [(i, p) for i, p in enumerate(oof) if p is not None]
    human_eval = [(i, p) for i, p in evaluable if not labeled[i]["weak"]]
    if len(human_eval) < 5:
        return {
            "status": "insufficient",
            "reason": "not enough human-labeled evaluation points",
            "labels": len(human),
        }
    human_labels = [labeled[i]["label"] for i, _ in human_eval]
    if len(set(human_labels)) < 2:
        return {
            "status": "insufficient",
            "reason": "evaluation split contains only one class",
            "labels": len(human),
        }
    oof_pairs = [(p, float(labeled[i]["label"])) for i, p in evaluable]
    oof_weights = [float(labeled[i].get("weight", 1.0)) for i, p in evaluable]
    use_isotonic = len(human) >= MIN_LABELS_FOR_ISOTONIC
    final_weights = _fit_logistic(labeled)
    base_rate = sum(human_labels) / len(human_labels)

    # Isotonic regression is high-variance below roughly 30 human labels, and
    # a calibrator fitted on the same out-of-fold points it is scored on would
    # leak information. Small samples therefore deploy the logistic score
    # as-is; once there is enough signal, evaluate each human label against a
    # calibrator fitted without that point.
    calibrated_eval: list[float] = []
    if use_isotonic:
        calibration = isotonic(oof_pairs, oof_weights)
        for held_out, raw_probability in human_eval:
            subset_pairs: list[tuple[float, float]] = []
            subset_weights: list[float] = []
            for index, probability in evaluable:
                if index == held_out:
                    continue
                subset_pairs.append((probability, float(labeled[index]["label"])))
                subset_weights.append(float(labeled[index].get("weight", 1.0)))
            points = isotonic(subset_pairs, subset_weights)
            calibrated_eval.append(_calibrate(raw_probability, points))
        calibration_meta = {"points": calibration, "method": "isotonic (PAV), leave-one-out evaluated"}
        calibration_method = "isotonic (leave-one-out evaluated)"
    else:
        calibrated_eval = [p for _, p in human_eval]
        calibration = [[0.0, 0.0], [1.0, 1.0]]
        calibration_meta = {
            "points": calibration,
            "method": (
                f"identity until {MIN_LABELS_FOR_ISOTONIC} human labels "
                f"(currently {len(human)}); avoids isotonic overfit"
            ),
        }
        calibration_method = f"identity (needs {MIN_LABELS_FOR_ISOTONIC} labels for isotonic)"

    metrics = _metrics(
        [p for _, p in human_eval],
        human_labels,
        calibrated_preds=calibrated_eval,
        base_rate=base_rate,
    )
    metrics.update(
        {
            "n_labels": len(labeled),
            "n_human": len(human),
            "n_weak": weak_count,
            "n_eval": len(human_eval),
            "features": list(FEATURE_ORDER),
            "baseline_brier": round(_brier([base_rate] * len(human_labels), human_labels), 4),
            "method": (
                "L2 logistic regression; 5-fold out-of-fold evaluation; " + calibration_method
            ),
            "calibration_method": calibration_method,
            "calibration_active": use_isotonic,
            "promotion_metric": "brier_calibrated",
            "promotion_gate": {
                "min_eval": MIN_EVAL_FOR_PROMOTION,
                "max_ece": MAX_ECE_FOR_PROMOTION,
                "baseline_margin": BASELINE_MARGIN,
                "champion_margin": MIN_IMPROVEMENT,
            },
        }
    )
    previous = db.champion_model("confidence")
    previous_metrics = previous.get("metrics", {}) if previous else {}
    previous_brier = (
        float(previous_metrics.get("brier_calibrated", previous_metrics.get("brier", 1.0)))
        if previous
        else None
    )

    blockers: list[str] = []
    if metrics["n_eval"] < MIN_EVAL_FOR_PROMOTION:
        blockers.append(
            f"needs {MIN_EVAL_FOR_PROMOTION} held-out human labels; has {metrics['n_eval']}"
        )
    if metrics["brier_calibrated"] >= metrics["baseline_brier"] - BASELINE_MARGIN:
        blockers.append(
            f"calibrated Brier {metrics['brier_calibrated']:.3f} does not beat "
            f"baseline {metrics['baseline_brier']:.3f} by {BASELINE_MARGIN}"
        )
    if metrics["ece"] > MAX_ECE_FOR_PROMOTION:
        blockers.append(
            f"ECE {metrics['ece']:.3f} exceeds the {MAX_ECE_FOR_PROMOTION:.2f} calibration gate"
        )
    if previous is not None and metrics["brier_calibrated"] >= float(previous_brier) - MIN_IMPROVEMENT:
        blockers.append(
            f"does not beat champion #{previous['id']} Brier {float(previous_brier):.3f} "
            f"by {MIN_IMPROVEMENT}"
        )
    promoted = not blockers
    status = "champion" if promoted else "challenger"
    metrics["promoted"] = promoted
    metrics["promotion_blockers"] = blockers
    if promoted:
        db.demote_champions("confidence")
    model_id = db.add_model(
        kind="confidence",
        status=status,
        n_labels=len(human),
        metrics=metrics,
        weights=final_weights,
        calibration=calibration_meta,
        parent_id=int(previous["id"]) if previous else None,
        notes=(
            "Weak labels are capped at weight 0.2 and excluded from evaluation. "
            f"Calibration: {calibration_method}. Promotion gates: at least "
            f"{MIN_EVAL_FOR_PROMOTION} held-out human labels, calibrated Brier "
            f"below baseline by {BASELINE_MARGIN}, ECE at most {MAX_ECE_FOR_PROMOTION}, "
            f"and a champion margin of {MIN_IMPROVEMENT}. Blockers are stored with the model."
        ),
    )
    if promoted:
        _rescore_open_findings(db, model_id)
    return {
        "status": status,
        "model_id": model_id,
        "promoted": promoted,
        "metrics": metrics,
        "promotion_blockers": blockers,
        "previous_brier": previous_brier,
        "labels": len(human),
        "weak_labels": weak_count,
    }


def maybe_retrain(db: Database, *, min_new: int = 8) -> dict[str, Any] | None:
    champion = db.champion_model("confidence")
    rows = db.feedback_training_rows()
    if champion:
        if len(rows) - int(champion["n_labels"]) < min_new:
            return None
    elif len(rows) < MIN_LABELS_TO_PROMOTE:
        return None
    return train_confidence_model(db)


def _fit_logistic(rows: list[dict[str, Any]], *, epochs: int = 450, lr: float = 0.12) -> dict[str, Any]:
    x = [vectorize(row["features"]) for row in rows]
    y = [float(row["label"]) for row in rows]
    w = [float(row.get("weight", 1.0)) for row in rows]
    positives = sum(y) or 1.0
    negatives = len(y) - sum(y)
    pos_weight = len(y) / (2.0 * positives)
    neg_weight = len(y) / (2.0 * max(negatives, 1.0))
    weights = [0.0] * len(FEATURE_ORDER)
    intercept = 0.0
    # Full-batch gradient descent is tiny here (<= 10 features) and stable.
    for epoch in range(epochs):
        grad = [0.0] * len(FEATURE_ORDER)
        grad_i = 0.0
        total = 0.0
        for xi, yi, wi in zip(x, y, w, strict=True):
            z = intercept + sum(a * b for a, b in zip(weights, xi, strict=True))
            p = sigmoid(z)
            class_weight = pos_weight if yi > 0.5 else neg_weight
            sample_weight = wi * class_weight
            error = (p - yi) * sample_weight
            grad_i += error
            for j in range(len(weights)):
                grad[j] += error * xi[j]
            total += sample_weight
        if total <= 0:
            break
        decay = 0.02 / (1.0 + epoch * 0.01)
        step = lr / (1.0 + epoch * 0.004)
        intercept -= step * grad_i / total
        for j in range(len(weights)):
            weights[j] -= step * (grad[j] / total + decay * weights[j])
    return {
        "intercept": round(intercept, 5),
        **{name: round(value, 5) for name, value in zip(FEATURE_ORDER, weights, strict=True)},
    }


def _predict(model: dict[str, Any], features: dict[str, float]) -> float:
    vector = vectorize(features)
    z = float(model.get("intercept", 0.0))
    z += sum(float(model.get(name, 0.0)) * value for name, value in zip(FEATURE_ORDER, vector, strict=True))
    return sigmoid(z)


def _brier(preds: list[float], labels: list[int]) -> float:
    if not preds:
        return 1.0
    return sum((p - y) ** 2 for p, y in zip(preds, labels, strict=True)) / len(preds)


def _metrics(
    preds: list[float],
    labels: list[int],
    *,
    calibrated_preds: list[float],
    base_rate: float,
) -> dict[str, Any]:
    brier = _brier(preds, labels)
    brier_cal = _brier(calibrated_preds, labels)
    eps = 1e-12
    log_loss = -sum(
        y * math.log(max(p, eps)) + (1 - y) * math.log(max(1 - p, eps))
        for p, y in zip(preds, labels, strict=True)
    ) / len(preds)
    log_loss_cal = -sum(
        y * math.log(max(p, eps)) + (1 - y) * math.log(max(1 - p, eps))
        for p, y in zip(calibrated_preds, labels, strict=True)
    ) / len(preds)
    ece, bins = _ece(calibrated_preds, labels)
    ece_raw, _ = _ece(preds, labels)
    tp = sum(1 for p, y in zip(calibrated_preds, labels, strict=True) if p >= 0.5 and y == 1)
    fp = sum(1 for p, y in zip(calibrated_preds, labels, strict=True) if p >= 0.5 and y == 0)
    fn = sum(1 for p, y in zip(calibrated_preds, labels, strict=True) if p < 0.5 and y == 1)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    accuracy = (
        sum(1 for p, y in zip(calibrated_preds, labels, strict=True) if (p >= 0.5) == bool(y))
        / len(preds)
    )
    return {
        # Headline Brier is for the deployed, calibrated score. The raw
        # out-of-fold score is retained for transparency.
        "brier": round(brier_cal, 4),
        "brier_calibrated": round(brier_cal, 4),
        "brier_uncalibrated": round(brier, 4),
        "log_loss": round(log_loss_cal, 4),
        "log_loss_uncalibrated": round(log_loss, 4),
        "ece": round(ece, 4),
        "ece_uncalibrated": round(ece_raw, 4),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "base_rate": round(base_rate, 4),
        "calibration_bins": bins,
        "n_eval": len(preds),
    }


def _ece(preds: list[float], labels: list[int], bins: int = 8) -> tuple[float, list[dict[str, Any]]]:
    total = len(preds)
    bucket: dict[int, list[tuple[float, int]]] = defaultdict(list)
    for p, y in zip(preds, labels, strict=True):
        idx = min(bins - 1, int(p * bins))
        bucket[idx].append((p, y))
    ece = 0.0
    out = []
    for idx in range(bins):
        values = bucket.get(idx, [])
        if not values:
            out.append({"bin": idx, "n": 0, "confidence": None, "accuracy": None})
            continue
        avg_conf = sum(p for p, _ in values) / len(values)
        avg_acc = sum(y for _, y in values) / len(values)
        ece += (len(values) / total) * abs(avg_conf - avg_acc)
        out.append(
            {
                "bin": idx,
                "n": len(values),
                "confidence": round(avg_conf, 3),
                "accuracy": round(avg_acc, 3),
            }
        )
    return ece, out


def _calibrate(probability: float, points: list[list[float]]) -> float:
    if not points:
        return probability
    if probability <= points[0][0]:
        return points[0][1]
    if probability >= points[-1][0]:
        return points[-1][1]
    for i in range(1, len(points)):
        if probability <= points[i][0]:
            span = points[i][0] - points[i - 1][0]
            if span <= 1e-12:
                return points[i][1]
            t = (probability - points[i - 1][0]) / span
            return points[i - 1][1] + t * (points[i][1] - points[i - 1][1])
    return probability


def _rescore_open_findings(db: Database, model_id: int) -> int:
    engine = ConfidenceEngine(db)
    engine.refresh()
    rows = db.query("SELECT id, features_json FROM findings")
    count = 0
    for row in rows:
        features = json.loads(row["features_json"] or "{}")
        probability, factors, _ = engine.score(features)
        db.execute(
            "UPDATE findings SET confidence=?, confidence_band=?, explain_json=?, model_version=? WHERE id=?",
            (round(probability, 4), band_for(probability), json.dumps(factors), model_id, row["id"]),
        )
        count += 1
    return count


def learning_overview(db: Database) -> dict[str, Any]:
    champion = db.champion_model("confidence")
    models = db.list_models("confidence", limit=20)
    counts = db.feedback_counts()
    labels = sum(counts.get(v, 0) for v in ("confirmed", "false_positive", "accepted_risk"))
    detector_rates = ConfidenceEngine(db).detector_reliability()
    path_stats = db.path_stats()
    probe_stats = db.probe_stats()
    return {
        "champion": champion,
        "models": models,
        "feedback_counts": counts,
        "human_labels": labels,
        "next_promotion_at": (
            max(MIN_EVAL_FOR_PROMOTION, int(champion["n_labels"]) + 8)
            if champion
            else MIN_EVAL_FOR_PROMOTION
        ),
        "detectors": detector_rates,
        "paths": path_stats[:50],
        "probes": probe_stats[:50],
        "active_learning": db.active_learning(limit=20),
        "thresholds": {
            "high": 0.85,
            "medium": 0.60,
            "min_eval": MIN_EVAL_FOR_PROMOTION,
            "max_ece": MAX_ECE_FOR_PROMOTION,
            "min_isotonic": MIN_LABELS_FOR_ISOTONIC,
            "baseline_margin": BASELINE_MARGIN,
            "promotion_improvement": MIN_IMPROVEMENT,
        },
    }


def detector_prior_for(detector: str) -> float:
    return detector_prior(detector)


__all__ = [
    "ConfidenceEngine",
    "train_confidence_model",
    "maybe_retrain",
    "learning_overview",
    "detector_prior_for",
    "logit",
    "band_for",
]
