# Remote sensors

LassiNet can run on several segments/hosts and send **alerts** to one central
dashboard. It forwards Suricata EVE alerts, not packets: the agent reads a
local `eve.json`, and the central receives JSON alerts.

This is the honest way to get multi-segment visibility without pretending the
Python sensor is a gigabit packet broker. Put Suricata + a SPAN/mirror on each
segment; run the agent next to its EVE file.

## Central configuration

```bash
LASSI_SENSOR_TOKEN=<long-random-token>   # required to enable ingest
LASSI_SENSOR_EVE=                     # not used on the central
```

- `POST /api/v1/ingest/alerts` accepts only this token.
- It cannot block, trust, rename, triage or read.
- Ingested cards have a `sensor` label and `engine` (usually `suricata`).
- **No auto-block**: the central operator reviews the card.
- The token is shared by all sensors; rotate it everywhere at once.

## Agent configuration

```bash
LASSI_SENSOR_URL=https://lassinet.example/api/v1/ingest/alerts
LASSI_SENSOR_TOKEN=<same long-random-token>
LASSI_SENSOR_ID=office-1
LASSI_SENSOR_EVE=/var/log/suricata/eve.json
LASSI_SENSOR_FROM_START=0
LASSI_SENSOR_MIN_SEVERITY=medium
LASSI_SENSOR_BATCH=20
LASSI_SENSOR_SPOOL=data/sensor_spool.jsonl
LASSI_SENSOR_VERIFY_TLS=1
# LASSI_SENSOR_ALLOW_HTTP=1   # localhost lab only
```

Run:

```bash
python -m lassi.sensor_agent          # tail and push
python -m lassi.sensor_agent --once   # current file, then exit
python scripts/sensor_agent.py
```

- The agent requires HTTPS unless `LASSI_SENSOR_ALLOW_HTTP=1`.
- If the central is down, alerts are appended to the spool and retried; the
  spool is bounded on read (last 5000).
- `--once` does not seek to the end; it reads the current file from the start.
- The agent does not capture, scan or apply firewall rules.

## Topology

```
segment A: Suricata EVE ── agent A ─┐
segment B: Suricata EVE ── agent B ─┼── HTTPS ── central LassiNet ── browser
segment C: Suricata EVE ── agent C ─┘                    (triage + audit)
```

## Security

- Use a **separate** `LASSI_SENSOR_TOKEN`; never reuse the operator token.
- TLS/VPN between agents and central; the token is a bearer secret.
- The central exposes the ingest path over the same port; bind loopback and
  publish only through the reverse proxy, or firewall the port to the sensors.
- Ingested fields are untrusted input; they are parsed and stored as alert
  data. No command is built from them.
- The central audit log records an `alert` event with `actor="sensor:<id>"`.
- The sensor can spoof source/destination fields; that is why a signature is
  evidence, not an automatic block.

## Limits

No packet forwarding, no distributed state/HA, one shared sensor token, no
per-sensor rate limit beyond the 100-alert batch cap, and no offline central
queue beyond the agent spool. For a full multi-gigabit deployment, use
Suricata/Zeek with a proper central SIEM; LassiNet is the response/triage
console.
