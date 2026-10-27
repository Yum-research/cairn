from __future__ import annotations

import json
from typing import Any

from ..db import Database
from .features import DEFAULT_WEIGHTS, FEATURE_ORDER, explain, sigmoid, vectorize


class ConfidenceEngine:
    """Scores findings with a transparent baseline or a learned champion.

    Confidence is the calibrated probability that a finding is valid, not its
    severity. It is stored alongside its feature contributions so the UI can
    answer "why 0.87?" rather than presenting a black box.
    """

    def __init__(self, db: Database):
        self.db = db
        self._champion: dict[str, Any] | None = db.champion_model("confidence")

    def refresh(self) -> None:
        self._champion = self.db.champion_model("confidence")

    def score(self, features: dict[str, float]) -> tuple[float, list[dict[str, Any]], int | None]:
        weights = DEFAULT_WEIGHTS
        model_id: int | None = None
        calibrator: list[list[float]] = []
        if self._champion:
            model_id = int(self._champion["id"])
            weights = self._champion.get("weights", {})
            calibrator = self._champion.get("calibration", {}).get("points", [])
        vector = vectorize(features)
        raw_weights = [float(weights.get(name, 0.0)) for name in FEATURE_ORDER]
        z = float(weights.get("intercept", DEFAULT_WEIGHTS["intercept"]))
        z += sum(value * weight for value, weight in zip(vector, raw_weights, strict=True))
        probability = sigmoid(z)
        calibrated = apply_calibration(probability, calibrator)
        probability = min(0.995, max(0.02, calibrated))
        return probability, explain(features, weights, model_version=model_id), model_id

    def detector_reliability(self) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT f.detector, COUNT(*) AS n, "
            "SUM(CASE WHEN fb.verdict='confirmed' THEN 1.0 WHEN fb.verdict='accepted_risk' THEN 1.0 ELSE 0.0 END) "
            "AS positives FROM feedback fb JOIN findings f ON f.id=fb.finding_id "
            "WHERE fb.verdict IN ('confirmed','false_positive','accepted_risk') GROUP BY f.detector"
        )
        out = []
        for row in rows:
            n = int(row["n"])
            positives = float(row["positives"] or 0)
            # Laplace smoothing toward the prior.
            out.append(
                {
                    "detector": row["detector"],
                    "labels": n,
                    "confirmed": int(positives),
                    "rate": round((positives + 1) / (n + 2), 3),
                }
            )
        out.sort(key=lambda r: r["labels"], reverse=True)
        return out


def apply_calibration(probability: float, points: list[list[float]] | list[dict[str, float]]) -> float:
    """Monotone piecewise-linear interpolation over isotonic calibration points."""

    if not points:
        return probability
    xs: list[float] = []
    ys: list[float] = []
    for point in points:
        if isinstance(point, dict):
            xs.append(float(point["x"]))
            ys.append(float(point["y"]))
        else:
            xs.append(float(point[0]))
            ys.append(float(point[1]))
    if not xs:
        return probability
    if probability <= xs[0]:
        return min(max(ys[0], 0.0), 1.0)
    if probability >= xs[-1]:
        return min(max(ys[-1], 0.0), 1.0)
    for i in range(1, len(xs)):
        if probability <= xs[i]:
            span = xs[i] - xs[i - 1]
            if span <= 1e-12:
                return min(max(ys[i], 0.0), 1.0)
            t = (probability - xs[i - 1]) / span
            return min(max(ys[i - 1] + t * (ys[i] - ys[i - 1]), 0.0), 1.0)
    return probability


def isotonic(points: list[tuple[float, float]], weights: list[float] | None = None) -> list[list[float]]:
    """Pool-adjacent-violators with optional sample weights.

    Returns a compact monotone curve suitable for JSON storage.
    """

    if not points:
        return []
    data = sorted(points, key=lambda item: item[0])
    weight_list = weights or [1.0] * len(data)
    blocks: list[dict[str, float]] = []
    for (x, y), weight in zip(data, weight_list, strict=True):
        blocks.append({"sum_w": weight, "sum_wy": weight * y, "x": x, "y": y, "n": 1})
        while len(blocks) >= 2 and blocks[-2]["y"] > blocks[-1]["y"]:
            right = blocks.pop()
            left = blocks.pop()
            total_w = left["sum_w"] + right["sum_w"]
            blocks.append(
                {
                    "sum_w": total_w,
                    "sum_wy": left["sum_wy"] + right["sum_wy"],
                    "x": (left["x"] + right["x"]) / 2,
                    "y": (left["sum_wy"] + right["sum_wy"]) / total_w,
                    "n": left["n"] + right["n"],
                }
            )
    # Expand blocks back to input x positions, preserving monotonicity.
    out: list[list[float]] = []
    block_index = 0
    covered = 0
    for entry in blocks:
        count = int(entry["n"])
        for _ in range(count):
            out.append([round(data[covered][0], 4), round(entry["y"], 4)])
            covered += 1
        block_index += 1
    # Deduplicate adjacent equal x while keeping the last y.
    dedup: list[list[float]] = []
    for x, y in out:
        if dedup and abs(dedup[-1][0] - x) < 1e-9:
            dedup[-1][1] = y
        else:
            dedup.append([x, y])
    return dedup


def model_summary(model: dict[str, Any] | None) -> dict[str, Any]:
    if not model:
        return {
            "status": "heuristic",
            "model_version": None,
            "metrics": {},
            "calibration": [],
            "weights": DEFAULT_WEIGHTS,
        }
    return {
        "status": model["status"],
        "model_version": model["id"],
        "created_at": model["created_at"],
        "n_labels": model["n_labels"],
        "metrics": model.get("metrics", {}),
        "calibration": model.get("calibration", {}),
        "weights": model.get("weights", {}),
        "notes": model.get("notes", ""),
    }


def export_features(features: dict[str, float]) -> str:
    return json.dumps(features, sort_keys=True)
