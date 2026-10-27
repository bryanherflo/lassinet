# LassiNet 0.16.1 — free and open source

> **Status: pre-release / beta.** Tests and demo are green, but this is not yet
> validated by a real 24–48 h pilot or an independent security review. Do not
treat it as production-certified.

LassiNet is a **free, MIT-licensed, self-hosted** network visibility and
response console for small LANs. No account, cloud, license key or telemetry.

## Highlights

- Topology map, flow view, ML/rules alerts and safe source-only blocking.
- Live mode with `LASSI_LIVE_ALLOW` scope guard, passive mode and dry-run.
- OPNsense, nftables, Windows Firewall; mock records only.
- Auth/RBAC, CSRF, server-side sessions, audit log + signed checkpoints.
- Alert triage in SQLite (ack/notes/false positive), webhooks, Prometheus.
- API v1, remote sensors (Suricata EVE), OIDC via a trusted reverse proxy.
- Preflight `python -m lassi.doctor`, verified backup/restore.
- 252 tests; CI on Ubuntu and Windows; Python 3.12.

## Install

```bash
git clone https://github.com/bryanherflo/lassinet.git
cd lassinet
python run.py
# demo: http://127.0.0.1:8000
```

Live monitor-only:

```bash
LASSI_MODE=live LASSI_LIVE_ALLOW=192.168.0.0/24 \
LASSI_DRY_RUN=1 LASSI_FW=mock LASSI_AUTO_BLOCK=0 \
python run.py --live
```

## Upgrade notes

- Dependencies are pinned to tested versions; Python 3.12+.
- numpy 2.5 requires Python 3.12+, so older Python 3.10/3.11 installs are no
  longer supported by the pinned requirements.
- GitHub Actions use checkout/setup-python v7.

## Support

Community, best effort, via GitHub Issues/Discussions. **No SLA, no paid
support, no warranty** beyond the MIT license. Security reports: see
[SECURITY.md](SECURITY.md).

## Documentation

- [Quick usage guide (Spanish)](GUIA_DE_USO.md)
- [Architecture](docs/architecture.md)
- [API v1](docs/api-v1.md)
- [Remote sensors](docs/remote-sensors.md)
- [OIDC / trusted proxy](docs/oidc.md)
- [Deployment](docs/deployment.md)
- [Runbook](docs/runbook.md)
- [Threat model](docs/threat-model.md)
- [Case study template](docs/case-study-template.md)
- [Roadmap](docs/ROADMAP.md)

## Limits

Not HA, not gigabit, not a formal compliance product, and not a replacement for
Suricata/Zeek. See `docs/benchmarks.md` and `docs/threat-model.md`.
