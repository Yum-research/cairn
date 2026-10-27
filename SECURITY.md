# Security policy

Cairn is a local security tool. We take vulnerabilities in Cairn itself
seriously, especially anything that could cause it to leave an authorized scope,
leak evidence, or execute untrusted content.

## Reporting a vulnerability

Please **do not open a public issue** for a security vulnerability. Use the
repository's private security advisory feature (GitHub → Security → Advisories →
Report a vulnerability) so the maintainers can investigate and coordinate a fix.

Include:

- Cairn version and commit,
- operating system and Python version,
- a minimal reproduction or proof of concept,
- the impact you believe is possible,
- whether the issue affects scope enforcement, evidence confidentiality,
  authentication, or availability.

Do not include real customer data, live credentials, or evidence from a
third-party engagement. Redact hostnames and tokens in screenshots.

We aim to acknowledge reports within a few business days and to publish a
coordinated fix and advisory when appropriate. Please give us a reasonable
window before public disclosure.

## Supported versions

Cairn is pre-1.0. Security fixes are applied to the latest `main` and the most
recent tagged release. Older snapshots may not receive fixes.

## Threat model

Cairn assumes:

- the operator is authorized to test the declared scope;
- the local machine and database are trusted;
- the dashboard is bound to loopback and not exposed through a proxy or tunnel;
- scanned services are untrusted and may return malicious content.

Cairn defends against:

- accidental out-of-scope traffic (explicit manifests, default deny, redirect
  checks, DNS re-resolution);
- DNS rebinding into loopback, private, link-local, or metadata space (public
  domain grants do not authorize private resolved addresses);
- cloud metadata access (`169.254.169.254`, `169.254.170.2`,
  `100.100.100.200`, `fd00:ec2::254`);
- local API access from a malicious website or DNS-rebinding page (loopback
  `Host` validation, token check, CSP, no CORS);
- token leakage through HTML injection (JSON-escaped token, nonce-based CSP);
- secret persistence in evidence (pattern redaction, excerpt limits);
- evidence or audit tampering (SHA-256 hash chains, verification command);
- resource exhaustion (rate limits, host/evidence/body caps, redirect limits).

Cairn does **not** defend against:

- a malicious operator with local access to the database or process;
- a compromised Python environment or dependency;
- legal or contractual authorization failures;
- vulnerabilities in the targets it observes;
- denial of service caused by an authorized scan that exceeds the target's
  capacity (keep rates conservative).

## Operational guidance

- Run `cairn serve` on loopback only. Do not put it behind a public reverse
  proxy, ngrok, or a tunnel.
- Treat the printed access token as a secret. Do not share screenshots that
  include it.
- Keep `.cairn/` out of version control and backup systems unless the evidence
  is protected.
- Rotate the token if it is exposed; restarting `cairn serve` generates a new
  one unless `--token` is supplied.
- Verify the audit and evidence chains after importing or restoring a database:
  `cairn audit verify --engagement <id>`.
- Keep dependencies current. The runtime is small enough to audit.
