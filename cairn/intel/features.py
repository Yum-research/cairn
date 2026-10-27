from __future__ import annotations

import math
from typing import Any

# The model deliberately starts with a small, inspectable feature set. Every
# feature is something an analyst can verify by looking at the evidence.
FEATURE_ORDER = (
    "prior_logit",
    "direct",
    "corroboration",
    "independent",
    "specificity",
    "soft404_clear",
    "coverage",
    "freshness",
    "scope_certainty",
)

FEATURE_LABELS = {
    "prior_logit": "detector base rate",
    "direct": "direct observation",
    "corroboration": "corroborating evidence",
    "independent": "independent sources",
    "specificity": "signature specificity",
    "soft404_clear": "soft-404 baseline",
    "coverage": "test coverage",
    "freshness": "evidence freshness",
    "scope_certainty": "scope certainty",
}

DEFAULT_WEIGHTS: dict[str, float] = {
    "intercept": -1.8,
    "prior_logit": 0.85,
    "direct": 1.0,
    "corroboration": 0.45,
    "independent": 0.55,
    "specificity": 0.95,
    "soft404_clear": 0.60,
    "coverage": 0.35,
    "freshness": 0.15,
    "scope_certainty": 0.50,
}

# Base rates are *detector reliability priors*, not vulnerability prevalence.
# They answer: "when this detector fires with a direct observation, how often
# has it historically been confirmed?" They are updated from feedback.
DETECTOR_PRIORS: dict[str, float] = {
    "web.exposed_git": 0.80,
    "web.exposed_env": 0.82,
    "web.exposed_backup": 0.72,
    "web.exposed_debug": 0.76,
    "web.exposed_source": 0.68,
    "web.exposed_config": 0.62,
    "web.directory_listing": 0.72,
    "web.admin_interface": 0.62,
    "web.api_docs": 0.75,
    "web.security_headers": 0.88,
    "web.cookie_flags": 0.86,
    "web.server_disclosure": 0.78,
    "web.technology_version": 0.62,
    "web.cors_credentials": 0.58,
    "web.robots_disclosure": 0.80,
    "web.security_txt": 0.80,
    "web.sitemap": 0.80,
    "tls.certificate_untrusted": 0.92,
    "tls.certificate_expiry": 0.95,
    "tls.protocol": 0.85,
    "dns.dangling_cname": 0.60,
    "dns.zone_transfer": 0.70,
    "port.exposed_service": 0.78,
    "port.sensitive_service": 0.65,
    "external.nuclei": 0.58,
    "external.nmap": 0.75,
}


def logit(probability: float) -> float:
    probability = min(max(probability, 0.001), 0.999)
    return math.log(probability / (1.0 - probability))


def sigmoid(value: float) -> float:
    if value >= 40:
        return 1.0
    if value <= -40:
        return 0.0
    return 1.0 / (1.0 + math.exp(-value))


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def detector_prior(detector: str) -> float:
    return DETECTOR_PRIORS.get(detector, 0.60)


def build_features(
    detector: str,
    *,
    evidence_count: int = 1,
    independent_sources: int = 1,
    specificity: float = 0.75,
    direct: float = 1.0,
    soft404_clear: float = 1.0,
    coverage: float = 0.8,
    freshness_days: float = 0.0,
    scope_certainty: float = 1.0,
    overrides: dict[str, float] | None = None,
) -> dict[str, float]:
    features = {
        "prior_logit": logit(detector_prior(detector)),
        "direct": clamp(direct),
        "corroboration": clamp(evidence_count / 3.0),
        "independent": clamp(independent_sources / 2.0),
        "specificity": clamp(specificity),
        "soft404_clear": clamp(soft404_clear),
        "coverage": clamp(coverage),
        "freshness": clamp(math.exp(-max(0.0, freshness_days) / 45.0)),
        "scope_certainty": clamp(scope_certainty),
    }
    for key, value in (overrides or {}).items():
        if key in FEATURE_ORDER:
            features[key] = clamp(float(value))
    return features


def feature_value(name: str, value: float) -> float:
    # prior_logit is a log-odds value, not a probability.
    if name == "prior_logit":
        return max(-4.0, min(4.0, float(value)))
    return clamp(float(value))


def vectorize(features: dict[str, float]) -> list[float]:
    return [feature_value(name, float(features.get(name, 0.0))) for name in FEATURE_ORDER]


def explain(
    features: dict[str, float],
    weights: dict[str, float] | None = None,
    *,
    model_version: int | None = None,
    limit: int = 5,
) -> list[dict[str, Any]]:
    weights = weights or DEFAULT_WEIGHTS
    contributions: list[dict[str, Any]] = []
    for name in FEATURE_ORDER:
        value = feature_value(name, float(features.get(name, 0.0)))
        weight = float(weights.get(name, 0.0))
        contribution = value * weight
        contributions.append(
            {
                "feature": name,
                "label": FEATURE_LABELS.get(name, name),
                "value": round(value, 3),
                "contribution": round(contribution, 3),
                "direction": "supports" if contribution >= 0 else "weakens",
            }
        )
    contributions.sort(key=lambda item: abs(item["contribution"]), reverse=True)
    top = contributions[:limit]
    if model_version:
        for item in top:
            item["model_version"] = model_version
    return top
