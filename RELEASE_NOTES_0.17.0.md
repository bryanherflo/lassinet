# LassiNet 0.17.0 — one-click install + Android PWA

> **Status: pre-release / beta.** Tests and the demo are green, but this is not
> yet validated by a real 24–48 h pilot or an independent security review. Do
> not treat it as production-certified.

LassiNet is a **free, MIT-licensed, self-hosted** network visibility and
response console for small LANs. No account, cloud, license key or telemetry.

## Highlights

- **One-click install** on Windows (`install.bat`) and Linux/macOS
  (`bash install.sh`). The installer creates a local `.env` with random
  operator/viewer tokens, a Windows desktop shortcut, and opens the dashboard
  when `/healthz` answers. Existing `.env` files are never overwritten.
- **Android PWA**: installable from Chrome, standalone display, maskable
  icons, safe-area/mobile layout and an **Install app** button. The sensor
  stays on the PC/Raspberry Pi; the phone is the client.
- **The service worker caches only the static shell.** API responses, alerts,
  logs, `/metrics` and the WebSocket are never cached. Plain HTTP on the LAN
  gives a home-screen shortcut; the full install prompt/service worker needs
  HTTPS (Tailscale/Cloudflare Tunnel or a trusted reverse proxy).
- UI cache is `v=3.52`.

## Install

Windows:

```powershell
git clone https://github.com/bryanherflo/lassinet.git
cd lassinet
.\install.bat
```

Linux / macOS:

```bash
git clone https://github.com/bryanherflo/lassinet.git
cd lassinet
bash install.sh
```

Manual, or if you prefer to manage the environment yourself:

```bash
python run.py
# demo: http://127.0.0.1:8000
```

The installer starts in demo mode with auto-block off. Live mode still requires
an authorized `LASSI_LIVE_ALLOW` scope and a conscious pilot.

## Android

There is **no Play Store APK** in this release. Android uses the PWA:

1. Keep the server on the PC/Raspberry Pi.
2. Open the dashboard in Chrome (same Wi-Fi with `LASSI_HOST=0.0.0.0`, or via
   Tailscale/Cloudflare Tunnel for HTTPS).
3. Sign in with the printed token.
4. Chrome menu → **Add to Home screen** / **Install app**.

See [docs/android.md](docs/android.md) for the HTTPS requirement, security
notes and limitations. A TWA/native APK would be a separate project.

## Security notes

- `LASSI_HOST=0.0.0.0` without tokens/TLS/VPN exposes firewall actions to the
  LAN. Set tokens and use a private tunnel or VPN.
- The PWA does not add offline live data or push notifications; the server
  remains the source of truth.
- No auto-block is enabled by the installer. Keep the 24–48 h monitor-only
  pilot before trusting live response.

## Tests

- **256 tests** pass; CI runs on Ubuntu and Windows with Python 3.12.
- New tests cover the manifest/icons, service-worker API exclusion, PWA wiring
  and first-run `.env` generation.
