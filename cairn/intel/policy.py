from __future__ import annotations

import random
from typing import Any

from ..catalog import content_paths
from ..db import Database


def select_content_paths(
    db: Database,
    *,
    limit: int,
    deep: bool = False,
    seed: str = "cairn",
) -> list[dict[str, Any]]:
    """Mandatory high-signal probes plus Thompson-sampled exploration.

    Path yield from prior runs informs exploration, but mandatory probes are
    never starved. The policy is persisted and visible in the learning panel.
    """

    catalog = list(content_paths())
    if deep:
        return catalog
    mandatory = [entry for entry in catalog if entry.get("mandatory")]
    optional = [entry for entry in catalog if not entry.get("mandatory")]
    stats = {row["path"]: row for row in db.path_stats()}
    rng = random.Random(hash(seed) & 0xFFFFFFFF)
    ranked: list[tuple[float, dict[str, Any]]] = []
    for entry in optional:
        row = stats.get(entry["path"])
        trials = int(row["trials"]) if row else 0
        successes = int(row["successes"]) if row else 0
        alpha = 1 + successes
        beta = 1 + max(0, trials - successes)
        sample = rng.betavariate(alpha, beta)
        weight = float(entry.get("weight", 0.4))
        priority = 0.62 * sample + 0.38 * weight
        ranked.append((priority, entry))
    ranked.sort(key=lambda item: item[0], reverse=True)
    selected = mandatory + [entry for _, entry in ranked]
    # Deduplicate while preserving policy order.
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in selected:
        if entry["path"] in seen:
            continue
        seen.add(entry["path"])
        out.append(entry)
        if len(out) >= limit:
            break
    return out
