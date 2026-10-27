# Contributing

Thanks for helping improve Cairn. Contributions are welcome when they preserve
the project's two hard boundaries: **authorized scope** and **non-exploitative
observation**.

## Development setup

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -e ".[dev]"
```

Run the checks:

```bash
ruff check .
python -m compileall -q cairn scripts
node --check cairn/gui/app.js   # optional; requires Node
pytest -q
```

The suite starts a loopback-only HTTP fixture and performs a full scan. It does
not touch external hosts.

## What we look for

- **Scope invariants.** Every target must pass through `ScopeGuard`. Do not add
  raw socket, HTTP, or DNS calls in detectors. If you add a new network path,
  add a scope check and a test for denial.
- **Evidence integrity.** New collection paths must record redacted evidence
  with a content hash. Do not store full credentials.
- **Honest metrics.** Do not weaken the promotion gates or evaluate a calibrator
  on its own fit. Small-sample behavior must stay visible in the UI.
- **Small, testable detectors.** Detector functions should be pure and return
  `DetectorHit` objects. Add a fixture and a unit test.
- **No exploitation.** No authentication attempts, payload uploads, exploit
  code, persistence, lateral movement, or WAF bypass.
- **No surprise dependencies.** The core runtime is intentionally small
  (FastAPI, httpx, uvicorn). Discuss a new runtime dependency before adding one.

## Adding a detector

1. Add the detection logic to `cairn/engine/detectors.py` (or a new pure module).
2. Add a catalog entry to `cairn/data/content_paths.json` if a new path is
   needed. Keep the probe non-destructive.
3. Add a prior in `cairn/intel/features.py` if the detector is new.
4. Add a test with a representative response and a negative control.
5. Check the GUI and report rendering for the new category/title.

## Adding a model or calibration change

Include:

- the new objective and regularization,
- the evaluation protocol (out-of-fold, leave-one-out, or holdout),
- how small samples are handled,
- the promotion gates,
- before/after Brier, ECE, log loss, and sample count on a reproducible fixture.

Do not tune against the test labels. Do not add a model that cannot explain its
features in the finding drawer.

## Style

- Python 3.11+, `from __future__ import annotations`, type hints on public
  functions.
- Ruff with the repository configuration (`E`, `F`, `I`, `B`, `UP`).
- Keep comments about *why*, not *what*.
- Frontend is dependency-free ES2022. No build step. Use `esc()` for any string
  interpolated into HTML.
- Do not commit `.cairn/`, databases, tokens, certificates, or reports.

## Pull requests

- Describe the problem, the change, and the safety impact.
- Include tests and the commands you ran.
- Call out any change to scope enforcement, evidence handling, or promotion
  gates explicitly.
- Keep unrelated refactors in separate PRs.

By contributing, you agree that your contribution is licensed under
Apache-2.0 and that you have the right to submit it.
