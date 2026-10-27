# API v1

The v1 API is the stable integration surface. The dashboard still uses the
older `/api/*` endpoints; they remain available for backward compatibility.

All v1 responses carry `X-LassiNet-API: 1`.

## Authentication

- **Operator/viewer**: `Authorization: Bearer <token>` for scripts. Browsers
  use the session cookie plus `X-CSRF-Token` (double-submit) for writes.
- **Remote sensors**: a separate `LASSI_SENSOR_TOKEN` is accepted **only** on
  `POST /api/v1/ingest/alerts`. It cannot read, block, trust, rename or triage.
- **OIDC**: when `LASSI_PROXY_AUTH=1`, the trusted reverse proxy injects the
  user/groups and a shared secret header; see `docs/oidc.md`.

## Reads

| Endpoint | Notes |
|---|---|
| `GET /api/v1/version` | API/version/name |
| `GET /api/v1/state` | Full snapshot (nodes, alerts, rules, stats, mode) |
| `GET /api/v1/alerts` | Paginated feed; filters below |
| `GET /api/v1/devices` | Paginated nodes; `role`, `kind`, `q` |
| `GET /api/v1/flows` | Paginated flow-history metadata; filters below |
| `GET /api/v1/flows/{id}` | One flow record (404 when expired/unknown) |
| `GET /api/v1/rules` | Active firewall blocks |
| `GET /api/v1/sensors` | Alert counts/last seen per remote sensor |
| `GET /api/v1/logs` | Newest log lines; `event` exact filter |
| `GET /api/v1/health` | Same data as `/health`, wrapped |
| `GET /api/v1/audit/verify` | Hash-chain verification result |

Pagination parameters: `limit` (max 200) and `offset`.

### Flow filters

`GET /api/v1/flows` reads the local flow-history SQLite store. Only completed
flow metadata is returned; packet payloads are never stored.

| Parameter | Meaning |
|---|---|
| `limit` / `offset` | Page size (max 500) / offset |
| `src` / `dst` | Exact source or destination IP |
| `attack` | Exact verdict (`benign`, `port_scan`, `brute_force`, …) |
| `kind` | `benign` or `attack` |
| `q` | Substring over IPs, names and verdict |

```json
{
  "ok": true,
  "flows": [
    {
      "id": 42, "ts": 1793107050.69,
      "src": "192.168.0.10", "dst": "203.0.113.5",
      "src_name": "laptop", "dst_name": "203.0.113.5",
      "pkts": 20, "bytes": 3200, "duration": 10.2,
      "dst_port_count": 2, "syn_ratio": 0.15,
      "mean_pkt_size": 160.0, "pkt_rate": 1.96,
      "attack": "benign", "severity": "low", "confidence": 0.92,
      "engine": "ml", "mode": "live (passive)"
    }
  ],
  "total": 1, "limit": 100, "offset": 0, "enabled": true
}
```

The dashboard uses `/api/flows` (same contract). Retention is controlled by
`LASSI_FLOW_RETENTION_HOURS` (72 h), `LASSI_FLOW_MAX_ROWS` (1,000,000) and
`LASSI_FLOW_DB` (`data/flows.db`).

### Alerts filters

`severity` (comma list: low/medium/high/critical), `status`
(open/ack/closed), `engine`, `sensor`, `q` (substring over attack/src/dst/
sensor/engine). Example:

```bash
curl -H "Authorization: Bearer $OPERATOR" \
  "http://127.0.0.1:8000/api/v1/alerts?severity=high,critical&status=open&limit=50"
```

Response:

```json
{
  "ok": true,
  "items": [
    {"severity": "high", "attack": "suricata: ET TEST", "src": "203.0.113.5",
     "dst": "192.168.0.2", "engine": "suricata", "sensor": "office-1",
     "triage": {"status": "ack", "assignee": "ana", "note": "reviewed"}}
  ],
  "pagination": {"limit": 50, "offset": 0, "total": 1}
}
```

## Writes

`POST` wrappers exist for:

- `/api/v1/firewall/block` and `/unblock` (`{"ip", "reason", "ttl_s"}`)
- `/api/v1/alerts/triage` (`key`, `status`, `assignee`, `note`, `false_positive`)
- `/api/v1/alerts/dismiss` (`key`)
- `/api/v1/devices/trust` (`ip`, `trusted`)
- `/api/v1/devices/rename` (`ip`, `name`)

They require an operator credential and the same CSRF header as the
dashboard when the cookie session is used. Read-only viewer tokens get 403.

## Remote sensor ingest

```http
POST /api/v1/ingest/alerts
Authorization: Bearer <LASSI_SENSOR_TOKEN>
Content-Type: application/json

{
  "sensor": "office-1",
  "alerts": [
    {"src": "203.0.113.5", "dst": "192.168.0.2", "attack": "suricata: ET TEST",
     "severity": "high", "engine": "suricata", "confidence": 1.0,
     "time": "12:00:00", "ports": 443, "event_id": "1234"}
  ]
}
```

- Max 100 alerts per batch.
- Invalid source/destination are rejected; the response lists counts.
- `event_id` is de-duplicated per sensor (last 5000 IDs in memory).
- **No auto-block** is triggered, ever. An operator decides.
- The sensor token is global to the deployment; rotate it on the central and
  all agents together. See `docs/remote-sensors.md`.

## Limits

No API version negotiation beyond v1, no OAuth scopes, no pagination cursor
beyond offset, no per-route RBAC. The alert feed is bounded (200 cards) and
the log read is capped at 5000 lines.
