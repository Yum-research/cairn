from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CONFIDENCE_BANDS = ("low", "medium", "high")

VERDICTS = ("confirmed", "false_positive", "accepted_risk", "uncertain", "duplicate")
LABEL_VERDICTS = ("confirmed", "false_positive", "accepted_risk")


def band_for(confidence: float) -> str:
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.60:
        return "medium"
    return "low"


@dataclass
class DetectorHit:
    """A candidate finding produced by a detector.

    A hit is not a finding until the engine has coupled it to evidence and
    scored it. `features` may override or add to the extracted features.
    """

    detector: str
    title: str
    category: str
    severity: str
    description: str
    remediation: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    features: dict[str, float] = field(default_factory=dict)
    discriminator: str = ""
    confidence_hint: float | None = None

    def fingerprint_key(self, asset_value: str) -> str:
        return f"{self.detector}|{asset_value}|{self.discriminator}"


@dataclass
class ScopeSpec:
    kind: str  # domain | ip | cidr | url
    value: str
    include_subdomains: bool = False
    mode: str = "include"


@dataclass
class PreparedTarget:
    host: str
    url: str
    scheme: str
    port: int
    ip: str | None = None


class ScopeError(PermissionError):
    """Raised when an action is outside an active engagement's authorization."""


class SafetyError(RuntimeError):
    """Raised when a safety ceiling would be exceeded."""
