# LassiNet — case study template

> Fill this **after** a real, authorized, monitor-only pilot. Anonymize IPs,
> device names, client names and signatures if needed. Ask for written
> permission before publishing a customer's data. Never publish real captures
> or tokens.

## Context

- Site type (home lab / small office / MSP client):
- Approximate size (devices, users, sites):
- Existing firewall/IDS (OPNsense, pfSense, nftables, Suricata, Windows):
- Why they wanted LassiNet:
- Who used it (role, not name):

## Scope and authorization

- Authorized by:
- CIDR(s) in `LASSI_LIVE_ALLOW`:
- Dates of the pilot:
- Mode: `live` + `LASSI_PASSIVE` / `LASSI_DRY_RUN` / mock
- Data handling/retention agreement:

## Setup

- LassiNet version/commit:
- Python/OS/hardware:
- Install method (`run.py`, service, other):
- Firewall provider during the pilot:
- Suricata/EVE/remote sensor:
- Webhook destination (Slack/Teams/generic):
- Backup created (yes/no, where, verified):

## Results

- Devices discovered:
- Unknown devices:
- Alerts total / per day:
- Severity distribution:
- Top 5 signatures/attacks:
- False positives:
- Triaged (ack/false positive/note):
- Webhook delivered/failed/dropped:
- `flows/s` and CPU/RAM:
- Disk/log rotation:
- Restarts/incidents:

## What changed

- Allowlist/scope:
- Trusted devices and `LASSI_PROTECT`:
- Names/types corrected:
- Triage/suppression decisions:
- Firewall response (none / manual block tested / real enforcement):
- Configuration changes after the pilot:

## Findings

- What worked:
- What was noisy or missing:
- Security concerns:
- Performance limits observed:
- Would they keep using it? Why?

## Honest limits

State explicitly when something was **not** tested: HA, gigabit, multi-site,
formal compliance, auto-block, real firewall enforcement, etc.

## Quote (optional, with permission)

> “…”

## Appendix

- Redacted `/api/v1/health`, `/readyz`, `/metrics` excerpts.
- Redacted alert/log sample.
- `python -m lassi.vet --json` summary (no secrets).
- Checkpoint/backup verification result (no key).
