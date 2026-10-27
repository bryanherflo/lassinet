# Runbook

Operate LassiNet as a monitor first. Every command assumes the project root
(or the service's `WorkingDirectory`).

## Before a real pilot

```bash
python -m lassi.vet
python -m lassi.vet --json --report pilot.md
```

Run this **before** live mode. It checks the local IP against
`LASSI_LIVE_ALLOW`, tokens, firewall readiness, Suricata path, webhook URL,
storage, audit chain and backups. It does not capture or scan. A FAIL means
stop; a warning is a conscious decision.

## Webhooks

- `LASSI_WEBHOOK_URL` + `LASSI_WEBHOOK_FORMAT` (`slack`, `teams`, `discord`,
  `generic`), default only `high`/`critical`; lower it only if the channel can
  take the volume.
- Only new cards are posted; collapsed repeats are skipped. The queue is
  bounded and a broken endpoint increments `lassinet_webhook_failed_total`.
- The URL is a secret; HTTPS is enforced unless `LASSI_WEBHOOK_ALLOW_HTTP=1`
  for a localhost lab. The alert payload contains internal IPs/signatures.
- Verify reachability with a real test alert; LassiVet validates the URL
  syntax but deliberately does not send one.

## API v1 and remote sensors

- API v1: `/api/v1/version`, `/state`, `/alerts`, `/devices`, `/rules`,
  `/sensors`, `/logs`, `/health`, `/audit/verify`; writes under
  `/api/v1/firewall/*`, `/api/v1/alerts/*`, `/api/v1/devices/*`.
- Ingest token: `LASSI_SENSOR_TOKEN`; only `POST /api/v1/ingest/alerts`.
  Rotate it on the central and every agent together.
- Agent: `python -m lassi.sensor_agent` (or `--once`); it tails
  `LASSI_SENSOR_EVE` and spools when the central is down.
- Ingested alerts are tagged `sensor:<id>`, go through triage, and are
  **never auto-blocked**.
- OIDC: `LASSI_PROXY_AUTH=1` + `LASSI_PROXY_AUTH_SECRET`; the proxy must send
  the secret/user/groups headers. See `docs/oidc.md`. Direct access without the
  secret is a 401.

## Start and stop

- Dev/demo: `python run.py` (loopback, no real network).
- Live monitor: set `LASSI_MODE=live`, `LASSI_LIVE_ALLOW=<your CIDR>`,
  `LASSI_FW=mock` or `opnsense`, and keep `LASSI_DRY_RUN=1` for the first run.
- Service: `sudo systemctl start|stop|restart lassinet` (Linux) or the
  Windows Task/NSSM service in `deploy/windows-service.md`.
- **Never** run live on an unauthorized network. The app refuses without
  `LASSI_LIVE_ALLOW` unless `LASSI_LIVE_ALLOW_ANY=1` is explicit.

## Health

```bash
curl -s http://127.0.0.1:8000/healthz
curl -s http://127.0.0.1:8000/readyz    # 503 when capture/model/Suricata is unhealthy
curl -s http://127.0.0.1:8000/health
```

If `readyz` is 503: read `capture_error`/`suricata_error`, check the interface
(`LASSI_IFACE`), Npcap/root/CAP_NET_RAW, and the EVE path/permissions.

## Block, unblock, trust

- Block only the **source** of an alert or a selected device. The router,
  Internet node, this host, `LASSI_PROTECT` and trusted devices are refused.
- `LASSI_DRY_RUN=1` records the action without a real rule; remove it only
  after validating detections.
- Programming a block calls the provider first, then state. If the provider
  fails, state is unchanged. Unblock removes the rule then state.
- Automatic blocks expire after `LASSI_AUTO_BLOCK_TTL` (default 1 h). Manual
  blocks are permanent unless `ttl_s` is supplied.
- If a firewall rule survives a crash, normal live startup reads it back and
  restores the card; an expired TTL rule is removed.

## False positive / triage

- Use **Ack**, **False positive**, **Reopen** or **Note** on a card. The
  JSONL audit log records `alert_triage` with the actor; the SQLite store
  (`LASSI_TRIAGE_DB`) survives restarts.
- Marking a false positive does **not** create an allowlist rule. If the source
  is infrastructure, mark the device **trusted** (server-enforced) instead.
- Triage is not a ticket system: no SLA, assignment notifications or history
  UI.

## Audit log

```bash
curl -s http://127.0.0.1:8000/api/logs/verify
curl -s -X POST -H "Authorization: Bearer <operator>" \
     http://127.0.0.1:8000/api/logs/checkpoint
curl -s -H "Authorization: Bearer <viewer>" \
     http://127.0.0.1:8000/api/logs/checkpoint
curl -OJ http://127.0.0.1:8000/api/logs/export
```

- `ok: false` means tampering, an invalid/partial line, or a checkpoint anchor
  that no longer exists (e.g. retention removed the prefix).
- A checkpoint is only meaningful if a **copy of `data/audit_checkpoint.json`
  is kept off-box**. The key is `LASSI_CHECKPOINT_KEY`; it must not be stored
  with the checkpoint.
- Retention (`LASSI_LOG_RETENTION_DAYS`) can delete the anchored prefix. Keep
  the checkpoint/export you need before lowering retention.
- A crash can leave a partial last line; inspect/export and repair/rotate
  deliberately, do not assume a clean chain.

## Backups and restore

```bash
python -m lassi.backup create                  # data/ + logs/, verified manifest
python -m lassi.backup verify backups/lassinet-....zip
python -m lassi.backup restore backups/....zip --target /tmp/restore-here
```

- Stop the service (or take a filesystem/SQLite snapshot) before a live
  backup if you need a consistent triage DB; the tool includes WAL files.
- `.env` is **not** included by default (`--include-env` is explicit) because
  it contains tokens.
- Restore into a new directory first; never overwrite the live install without
  a second copy and `--force`.

## Secrets and sessions

- Rotate `LASSI_TOKEN_OPERATOR`/`LASSI_TOKEN_VIEWER`, then restart. Existing
  cookies are invalid when the derived key changes (or when `LASSI_SECRET`
  changes).
- `LASSI_SECRET` makes sessions survive restart. Without it, the key is random
  per process and every restart logs users out.
- Rotate `LASSI_CHECKPOINT_KEY` only with a new checkpoint discipline: old
  signatures cannot be verified with the new key.
- Do not commit `.env`, backups or real logs.

## Suricata

- `LASSI_SURICATA_EVE=/var/log/suricata/eve.json`; optional
  `LASSI_SURICATA_FROM_START=1` replays old events.
- EVE alerts become cards with engine `suricata` and are **never**
  auto-blocked. The tail detects a shrinking file; replacing it with a larger
  file needs a restart.
- A bad/missing EVE path makes `/readyz` unhealthy and is visible in `/health`.

## Firewall provider outage

- If `block` returns an error: no state change; no false “blocked” card.
- If `unblock` fails: the card stays blocked; fix the provider and retry.
- OPNsense: check URL/key/secret/alias and API reachability. nftables: check
  table/chain and root. Windows: run elevated and check `netsh`.
- Never disable the protected/trusted lists to “make it work”.

## Emergency

1. Stop the service (or kill the process). Existing firewall rules persist.
2. Unblock the affected address with the provider's native tooling if the UI
   cannot reach it.
3. Export/copy the audit log and checkpoint before changing data.
4. Restore a known-good backup into a **new** directory, verify, then switch.
5. Document what happened in the triage notes/incident record.
