# Architecture

Cairn is a local Python application with four layers: a scope-enforcing network
layer, a detection/recording engine, a calibrated learning layer, and a
token-authenticated read/write API that serves a dependency-free dashboard. The
database is the single source of truth for both the CLI and GUI.

```text
                 ┌──────────────────────────────┐
                 │  CLI (argparse)  │  GUI / API │
                 └───────────────┬──────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │      Orchestrator       │
                    │  DNS → ports → web     │
                    └───┬──────────┬──────────┘
                        │          │
          ┌─────────────▼──┐   ┌───▼─────────────┐
          │  ScopeGuard    │   │  FindingEmitter  │
          │  DNS re-check  │   │  evidence + hit  │
          └───────┬────────┘   └───┬─────────────┘
                  │                │
        ┌─────────▼─────┐   ┌──────▼──────────┐
        │ DNS / ports / │   │ ConfidenceEngine │
        │ HTTP / TLS    │   │ + calibration    │
        └───────────────┘   └──────┬──────────┘
                                   │
                          ┌────────▼────────┐
                          │ SQLite + chains │
                          └─────────────────┘
```

## Request path

Every network operation goes through `ScopeGuard`. There is no raw HTTP or
socket helper exposed to detectors.

1. `ScopeGuard` loads the engagement's include/exclude rules, allowed ports,
   and rate limits. It refuses to construct if the engagement is not active or
   its timestamps are invalid.
2. `prepare()` and `check_url()` normalize the host, reject credentials and
   malformed URLs, resolve DNS, and authorize the resolved address. A domain
   grant only authorizes public addresses; private/loopback targets require an
   explicit IP or CIDR rule. Metadata and link-local addresses are always
   denied.
3. The safe HTTP client re-checks every redirect target, applies a per-host
   token bucket, limits body size, and redacts response metadata before storage.
4. The TCP scanner re-resolves the host and checks the address and port before
   each connection. TLS capture uses the same guard.

This is a defense-in-depth design: even if a detector asks for an out-of-scope
URL, the network client refuses it.

## Run lifecycle

`execute_run()` is intentionally linear:

1. Load the run and engagement; construct the recorder, coverage tracker,
   guard, HTTP client, confidence engine, and finding emitter.
2. Collect seed hosts from scope. Resolve domains and record DNS evidence.
3. Optionally query passive sources: certificate transparency and RDAP. These
   requests go to third-party services, not the target, and are skipped with
   `--no-online-intel`.
4. Optionally enumerate subdomains for wildcard-scoped domains. Candidate names
   must resolve and pass the guard before they are added.
5. Probe TCP ports (top ports or explicit list). Web ports feed the web phase.
6. For each web endpoint: baseline a soft-404, fetch the root, parse headers and
   body, fetch robots/sitemap/security.txt, fingerprint technology, then probe
   the content-path catalog. Adaptive Thompson sampling orders paths based on
   stored yield statistics.
7. Detect candidate findings, attach evidence IDs, score confidence, upsert
   findings, update coverage, and emit run events.
8. Finish the run with status, stats, coverage, and a final audit event.

Cancellation is cooperative: a `CancellationToken` is checked between hosts,
requests, and redirects. The API marks a run `cancelling`, then `cancelled`.

## Scope model

A scope manifest is a single JSON object stored on the engagement:

```json
{
  "name": "Acme external surface",
  "client": "Acme",
  "authorized_by": "Security Director",
  "authorization_ref": "AUTH-2026-042",
  "starts_at": "2026-10-20T09:00:00+00:00",
  "expires_at": "2026-10-21T09:00:00+00:00",
  "scope": [
    {"kind": "domain", "value": "example.com", "mode": "include", "include_subdomains": true},
    {"kind": "cidr", "value": "203.0.113.0/24", "mode": "include", "include_subdomains": false}
  ],
  "limits": {
    "allowed_ports": [80, 443],
    "http_rate": 4.0,
    "port_rate": 250.0,
    "max_hosts": 256,
    "timeout": 8.0
  }
}
```

Validation rules:

- At least one include rule is required.
- Domain values are IDNA-normalized; wildcard `*.` implies subdomains.
- IPs and CIDRs are normalized. CIDRs above 65,536 addresses require an
  explicit smaller range; metadata, link-local, multicast, and reserved
  networks are rejected.
- URL rules must use HTTP(S), must not contain credentials, and preserve an
  explicit path prefix.
- The window must be in the future, at most 180 days, and not start more than
  ten minutes from now.
- The manifest's canonical JSON and SHA-256 are stored at creation. Scope
  revocation is immediate and audited.

`ScopeGuard` applies excludes first, then includes. URL matching compares
scheme, host, port, and path prefix. Domain matching is exact unless
`include_subdomains` is set.

## Evidence and findings

Evidence rows store:

- kind and source (`http`, `dns`, `tls`, `port`, `osint`),
- locator (URL, host, certificate subject),
- SHA-256 of the collected content,
- a redacted excerpt,
- collection timestamp, run/engagement IDs.

Each row also stores `prev_hash` and `hash`, where

```text
hash = SHA-256(prev_hash + canonical_json(payload))
```

The first row uses a genesis value. Verification recomputes the chain in row
order, so changing, deleting, or reordering a row is detectable. Audit events
use the same construction, with action, actor, target, decision, and details.

Findings are deduplicated by `SHA-256(detector | asset | discriminator)`.
`upsert_finding()` updates the existing row, increments occurrences only once
per run, and records the run linkage. Finding explanations are stored with the
model version so a later champion cannot retroactively rewrite why a finding
received its score.

## Detector design

Detectors are deterministic functions over an HTTP snapshot, DNS answer, port
result, or TLS metadata. They return a `DetectorHit` with a title, category,
severity, remediation, evidence IDs, and feature overrides. They do not perform
network I/O, which makes them easy to test and keeps scope enforcement in one
place.

A confidence hint is not trusted blindly. The emitter builds the feature vector,
scores it through `ConfidenceEngine`, and stores the result. Soft-404
observations reduce specificity and confidence rather than being silently
discarded.

## Learning loop

The learning layer is described in detail in [CONFIDENCE.md](CONFIDENCE.md). In
architectural terms:

- Feedback rows are immutable analyst verdicts linked to findings.
- `train_confidence_model()` builds weighted labels, adds a capped weak-label
  set (high-confidence, corroborated findings with no human verdict), performs
  5-fold out-of-fold logistic training, optionally fits isotonic calibration,
  evaluates calibration leave-one-out, and stores a challenger or champion in
  `models`.
- Promotion is gated; a challenger that loses remains queryable with its
  metrics and blockers.
- When a champion is promoted, open findings are rescored and the active model
  ID is written into each finding's explanation.
- `path_stats` and `probe_stats` accumulate yield/reward; the adaptive policy
  uses Thompson sampling to order future probes without starving untried paths.

## API and GUI

`create_app()` creates a FastAPI app with no OpenAPI/docs endpoints. The
middleware:

- validates the `Host` header against loopback names for `/api`,
- requires `X-Cairn-Token` for every API route except `/api/health`,
- compares tokens in constant time,
- sets `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy`, and `Cache-Control: no-store`.

The index page injects the token as a JSON string and a per-request nonce into a
nonce-authorized inline script. The CSP allows same-origin scripts and styles,
inline styles (used by the chart SVG), and data images; it forbids framing and
external connections.

The GUI is a single `app.js` module with hash routes for overview, findings,
learning, audit, and run detail. It uses `fetch` with the token header, polls run
events, and renders charts as SVG. No frontend framework or build step is
required.

## Storage

SQLite is used in WAL mode with foreign keys. Tables:

`engagements`, `scope_rules`, `runs`, `assets`, `evidence`, `observations`,
`findings`, `finding_runs`, `feedback`, `audit_events`, `models`, `probe_stats`,
`path_stats`, `events`, `meta`.

The database is local-only. `.cairn/` is ignored by Git because it contains
engagement data, evidence, demo certificates, and tokens.

## Extending Cairn

- **New detector:** add a pure function in `engine/detectors.py` returning
  `DetectorHit(s)`; add catalog entries if it needs new paths; add a prior in
  `intel/features.py`; add a fixture and test.
- **New passive source:** add a client method that respects the guard, records
  evidence, and emits observations rather than direct findings.
- **New report format:** add a renderer in `reporting.py` and a `--format`
  choice; keep redaction and evidence references intact.
- **New model family:** implement `fit`/`predict` behind the existing model
  contract, keep out-of-fold evaluation, and preserve the promotion gates.

Changes that bypass `ScopeGuard`, add exploitation behavior, or weaken the
promotion gates will not be accepted. See [CONTRIBUTING.md](CONTRIBUTING.md).
