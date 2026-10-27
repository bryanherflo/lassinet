# Roadmap — free and open source

LassiNet is a **free, MIT-licensed, self-hosted** tool for small networks.
There is no paid tier, license key, cloud account or telemetry in this roadmap.

## Next (useful for real users)

1. **Real case studies** — authorized monitor-only deployments, published with
   permission and anonymized.
2. **OPNsense / Suricata polish** — EVE edge cases, alias read-back, sensor
   rotation, clearer compatibility docs.
3. **Reports and export** — daily/weekly summary, CSV of alerts/devices, a
   printable incident/response note.
4. **Install/release ergonomics** — one-click installers and the Android PWA
   are now included; remaining work is signed tags, a ZIP release, optional
   PyPI/pipx packaging and an optional TWA/APK if there is demand.
5. **Accessibility and onboarding** — first-run checklist, clearer empty
   states, Spanish/English UI strings where useful.
6. **Quality** — more pcap/UI tests, coverage report, SBOM, signed artifacts.

## Later (only if the community needs it)

- Multi-site/remote-sensor management without multi-tenancy.
- SQLite/Postgres history for devices/alerts (triage already uses SQLite).
- More firewall providers and a narrow, unprivileged firewall helper.
- Richer suppression/maintenance windows.
- HA documentation (not a promise of an HA product).

## Explicit non-goals

- SaaS/multi-tenant licensing, billing, entitlement or trials.
- Replacing Suricata/Zeek for signatures/DPI.
- Gigabit line-rate capture in Python.
- 24/7 SOC/SLA, formal compliance certification or per-route SSO/MFA in-app.
- Scanning networks without written authorization.

Priorities change with real feedback. Open a Discussion with a concrete
deployment, not just a feature list.
