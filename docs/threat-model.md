# Threat model (lightweight, STRIDE-ish)

This is a lab/small-office tool, not a certified security product. The model
lists the important assets and the controls that actually exist; residual risks
are explicit.

## Assets

- The LAN devices, their availability, and the firewall rules that can cut
  them off.
- Operator/viewer tokens, session secret, checkpoint HMAC key.
- Audit evidence (`logs/events.jsonl` + checkpoints) and triage notes.
- The sensor host and its capture/firewall privileges.
- Configuration (`.env`, `LASSI_*`), backups and the triage SQLite DB.

## Actors

- **Operator**: trusted to block/unblock/trust/rename/triage.
- **Viewer**: read-only dashboard/logs/metrics.
- **Unauthenticated local user / malicious web page**: may reach the port if
  the bind/proxy is misconfigured.
- **Compromised sensor process**: has the sensor's privileges and data.
- **External IDS/OPNsense**: supplies alert/log data; not trusted blindly.

## Trust boundaries

1. Browser ↔ FastAPI (HTTP/WebSocket).
2. Web process ↔ privileged firewall provider/helper.
3. Sensor ↔ capture interface/LAN.
4. Sensor ↔ Suricata EVE / OPNsense API.
5. Live log ↔ off-box checkpoint copy.

## Threats and controls

| Threat | Control | Residual risk |
|---|---|---|
| Stolen viewer cookie becomes operator | HMAC-signed role cookie, random/session key, configured-role check | Cookie theft gives read access until expiry; use TLS + short TTL |
| Replayed session after browser expiry | Server-side `exp` in the cookie | No per-session revocation beyond secret rotation |
| CSRF from a malicious page | `SameSite=Strict` + signed CSRF double-submit header | Same-site XSS/compromised browser remains |
| Password/token brute force | Login throttle per IP, high-entropy tokens | In-memory, resets on restart; proxy IP collapse |
| Log tampering | Hash chain + signed checkpoint + external copy | Deleted prefix/suffix or full rewrite with key compromise |
| Audit evidence lost on rotation | Count/age retention, export, checkpoints | External copy discipline is operator-owned |
| Accidental block of gateway/DNS | Protected/trusted/router checks, source-only, scope guard, dry-run | Wrong `LASSI_PROTECT`/trust configuration |
| Auto-block false positive | Off in live, external scope, TTL, protected list | Explicit opt-in with a bad model still risks a rule |
| Compromised web app runs firewall as root | systemd monitor-only unit; separate helper recommended | Not implemented as a hardened helper yet |
| Malicious EVE/OPNsense data | JSON parsing, no shell interpolation, no auto-block | Large/odd files can be noisy or cause parse skips |
| Unauthorized network sweep | `LASSI_LIVE_ALLOW`, passive mode, no live without scope | Explicit `LASSI_LIVE_ALLOW_ANY=1` override |
| Data leakage via internet exposure | Loopback default, tokens, CSP/XFO, TLS/OIDC guidance | Misconfigured `LASSI_HOST=0.0.0.0` without a proxy |
| Dependency compromise | Pinned-ish requirements, Dependabot, CI matrix | No SBOM/signing yet |
| Disk exhaustion | Log rotation/retention, bounded alerts | No global disk quota |
| Denial of service on the UI | Bounded feeds, auth, reverse proxy recommendation | No rate limiting on all APIs |

## Explicit assumptions

- The operator owns/authorizes the monitored LAN and does not run live mode
  on a school/customer network without permission.
- `LASSI_LIVE_ALLOW` is set for live deployments; `LASSI_LIVE_ALLOW_ANY=1` is
  a deliberate lab choice.
- The checkpoint key is stored off the sensor; a backup/checkpoint copy is
  kept elsewhere.
- TLS and OIDC are provided by a reverse proxy where the dashboard is not
  localhost.

## Out of scope

HA/clustering, gigabit line-rate capture, formal compliance (retention
certification, WORM storage, SIEM case management), per-route RBAC, SSO/MFA in
the app itself, and protection against a fully compromised root/sensor host.
