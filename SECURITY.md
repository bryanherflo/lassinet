# Security policy

## Supported versions

The current release (`0.13.x` / `0.14.x` in this tree) receives security fixes.
Older releases may not; upgrade and run the test suite/CI before deploying.

## Reporting a vulnerability

Please use GitHub’s **private vulnerability reporting** for
`bryanherflo/lassinet` (Security → Advisories → Report a vulnerability). Do not
open a public issue with exploit details, tokens, real network captures or
personal data. If a private channel is unavailable, open an issue asking for a
private contact without technical details.

Include: version/commit, deployment mode, reproduction, impact, and whether
real networks/data are involved. Never test against a network you do not own
or lack written authorization to test.

## Scope

In scope: authentication/session handling, CSRF, authorization, audit log
integrity, firewall rule handling, scope guard bypass, path traversal in
backup/restore, arbitrary code execution, secret leakage, denial of service
that is cheap to trigger.

Out of scope: HA/gigabit/formal compliance claims (not provided), issues that
require a compromised root/sensor host or browser, social engineering, and
scans/attacks against third-party networks.

## Secure defaults

- Loopback bind (`LASSI_HOST=127.0.0.1`).
- `LASSI_LIVE_ALLOW` required for live; passive/dry-run available.
- Auto-block off in live; protected/trusted/router checks; TTL for auto-blocks.
- Optional operator/viewer tokens; server-side session expiry; CSRF for cookie
  writes; login throttle; CSP/XFO/headers.
- Hash-chained audit log + signed checkpoints; triage store; verified backups.
- Firewalls/proxies: never expose the dashboard directly to the internet; use
  TLS and, ideally, OIDC/VPN in front. Run monitor-only unless response is
  validated.

## Known limits

No HA, no gigabit capture, no formal compliance certification, no per-route
RBAC/SSO/MFA in the app, no hardened privileged firewall helper, and no
protection against a fully compromised sensor host. See
`docs/threat-model.md` and `docs/runbook.md`.
