# Deployment

LassiNet is a single Python process. The professional minimum is **loopback +
TLS reverse proxy + named auth + backup + monitoring**, not “expose port 8000
to the LAN”.

## Linux (systemd)

```bash
sudo useradd --system --home /opt/lassinet --shell /usr/sbin/nologin lassinet
sudo mkdir -p /opt/lassinet /etc/lassinet
# copy the repo to /opt/lassinet, then:
cd /opt/lassinet
sudo -u lassinet python3.12 -m venv .venv
sudo -u lassinet .venv/bin/pip install -r requirements.txt
sudo -u lassinet .venv/bin/python -m pytest -q

sudo cp deploy/lassinet.service /etc/systemd/system/lassinet.service
sudo cp deploy/lassinet.env.example /etc/lassinet/lassinet.env
sudo chmod 600 /etc/lassinet/lassinet.env
sudo editor /etc/lassinet/lassinet.env      # tokens, CIDR, provider
sudo systemctl daemon-reload
sudo systemctl enable --now lassinet
curl -s http://127.0.0.1:8000/healthz
```

The unit grants `CAP_NET_RAW` only (capture). **nftables needs root**; do not
run the web UI as root just for that. Use OPNsense (API) or a separate narrow
helper, and keep the UI unit unprivileged. `ProtectSystem=strict` with
`ReadWritePaths` keeps `data/`, `logs/` and `models/` writable.

## Windows

See `deploy/windows-service.md` for Task Scheduler/NSSM. Real Windows Firewall
rules need elevation; monitor-only mode does not. Prefer a dedicated account,
`LASSI_FW=mock`/OPNsense, and a VPN/reverse proxy.

## Reverse proxy + TLS + OIDC

Keep `LASSI_HOST=127.0.0.1`. Terminate TLS at Caddy, Nginx, Traefik or a VPN.
If you need SSO, put Authelia/oauth2-proxy in front; LassiNet’s operator/viewer
tokens still apply behind it unless you consciously relax them.

Caddy (automatic TLS, local DNS name):

```caddy
lassinet.example.lan {
    reverse_proxy 127.0.0.1:8000
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
    }
}
```

Nginx:

```nginx
server {
    listen 443 ssl;
    server_name lassinet.example.lan;
    ssl_certificate     /etc/ssl/lassinet/fullchain.pem;
    ssl_certificate_key /etc/ssl/lassinet/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # WebSocket
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

**Login throttling is per client IP.** Behind a proxy, configure it to pass
`X-Forwarded-For`; Uvicorn proxy headers are enabled and trust only
`LASSI_FORWARDED_ALLOW_IPS` (default `127.0.0.1`). A remote proxy must be added
explicitly, never a whole network. Session cookies use `Secure` when the app
sees HTTPS via `X-Forwarded-Proto`; without it they may not be marked Secure
(still use TLS).

## Firewall / privilege model

- Monitor-only: `LASSI_FW=mock` or `LASSI_DRY_RUN=1`, no firewall privileges.
- OPNsense: API credentials, an alias, no local root.
- nftables/Windows: the web process needs root/admin today; that is a larger
  attack surface. For production, split a narrow privileged firewall helper
  with an allowlisted local API and mTLS; this repository does not ship that
  helper yet.
- Always set `LASSI_PROTECT` (DNS/DHCP/NAS/hypervisor) and keep the gateway
  protected.

## Remote sensors and OIDC

- Central: set a long `LASSI_SENSOR_TOKEN`; publish `/api/v1/ingest/alerts` only
  to sensor hosts (VPN/firewall/reverse proxy), never the open internet.
- Agent: see `docs/remote-sensors.md`; it reads a local Suricata EVE and pushes
  alerts; no packet forwarding and no auto-block.
- OIDC: run Authelia/oauth2-proxy, inject `X-LassiNet-Proxy-Secret`,
  `X-Auth-Request-User` and `X-Auth-Request-Groups`, and set
  `LASSI_PROXY_AUTH=1`; see `docs/oidc.md`. Keep the app on loopback.
- Proxy auth writes still require the CSRF double-submit cookie/header.

## Storage, retention, backup

- `logs/events.jsonl`: audit chain; rotate with `LASSI_LOG_MAX_BYTES` and
  retain by count/age.
- `data/triage.db`: SQLite; back up the DB + WAL consistently (stop or
  snapshot).
- `data/dismissed_alerts.json`, `trusted_devices.json`, `device_names.json`,
  `block_expiry.json`, `audit_checkpoint.json`.
- `python -m lassi.backup create` produces a verified zip; copy it off-box.
- Create a checkpoint and copy it elsewhere; retention can remove the anchored
  prefix.

## Monitoring

- `/healthz` liveness, `/readyz` readiness, `/metrics` Prometheus.
- Scrape `/metrics` with a Bearer **viewer** token when auth is enabled.
- Alert on: readiness 503, capture error, Suricata error, audit verification
  false, disk usage, process restart, firewall provider failure.
- Do not expose `/metrics` unauthenticated through the proxy.

## Upgrade

```bash
git pull
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q
sudo systemctl restart lassinet
```

Take a backup and checkpoint before changing versions. There are no database
migrations beyond SQLite `CREATE TABLE IF NOT EXISTS`; back up `data/` anyway.

## What this guide does not provide

High availability, clustering, gigabit line-rate capture, a hardened root
helper, SIEM case management or formal compliance. Those are separate projects;
do not claim them in a deployment.
