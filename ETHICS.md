# Ethics and authorized use

Cairn is a reconnaissance tool. Reconnaissance is not harmless by default: it
touches systems, consumes resources, and can reveal information the owner did
not intend to expose. Use it only where you have clear, documented permission.

## The non-negotiables

1. **Written authorization comes first.** Before you create an engagement, be
   able to name the person or organization that authorized the work and the
   ticket, contract, statement of work, or written approval that proves it.
   Cairn requires both fields in the manifest for a reason.
2. **Stay inside the declared scope.** A scope manifest is an authorization
   boundary, not a wish list. Do not add a domain, CIDR, port, or URL because it
   "looks related." If the engagement changes, create a new manifest with the
   correct authorization.
3. **Respect the expiry.** Manifests are capped at 180 days and should be as
   short as the work allows. An expired engagement is not permission to finish
   one last scan.
4. **Do not exploit.** Cairn does not and should not be extended to submit
   credentials, brute-force authentication, upload payloads, exploit a
   vulnerability, establish persistence, move laterally, or bypass controls.
   Finding an exposed admin panel is not permission to try to enter it.
5. **Minimize data.** Cairn redacts likely secrets, but you are still handling
   potentially sensitive metadata. Store the database securely, limit access,
   and delete it when the engagement ends.
6. **Respect rate limits and availability.** Keep the default per-host rates
   unless the owner explicitly approves more. A scan that degrades a production
   service is an incident, not a deliverable.
7. **Do not scan third parties through a target.** A redirect, CNAME, API
   reference, or shared hosting neighbor is not automatically in scope. Cairn
   re-checks redirects and resolved addresses for this reason.

## What Cairn deliberately does not do

- No exploitation or proof-of-concept payloads.
- No credential stuffing, password spraying, or authentication attempts.
- No destructive requests, file uploads, or state-changing operations.
- No evasion of WAFs, rate limits, or access controls.
- No hidden telemetry, cloud upload, or external call-home.
- No collection of full secret values; likely secrets are redacted before
  storage.

These are design boundaries, not missing features.

## Cloud metadata and private networks

Cloud instance metadata endpoints are a classic SSRF pivot. Cairn always denies
the well-known metadata addresses, blocks link-local and reserved ranges, and
requires explicit IP/CIDR scope before a domain can resolve into private or
loopback space. Do not weaken these checks to "make a scan work." If a target is
private by design, add its exact range to the manifest and get it authorized.

## Responsible disclosure

If Cairn reveals a real exposure during an authorized assessment, report it
through the asset owner's security contact or disclosure program. Do not publish
the finding, evidence, or affected hostname before the owner has had a
reasonable chance to remediate. Preserve only the evidence needed for the
report, and redact anything that is not necessary.

If you find a vulnerability in Cairn itself, follow [SECURITY.md](SECURITY.md).

## Legal and professional responsibility

Laws about unauthorized access, privacy, computer misuse, and data protection
vary by jurisdiction. A scope manifest does not replace legal review. If you are
unsure whether you have permission, stop and ask. The maintainers of Cairn
cannot authorize your engagement, and using Cairn does not transfer
responsibility for your actions.

By using Cairn you agree that you are responsible for the targets you select,
the traffic you generate, and the data you retain.
