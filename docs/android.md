# Android

LassiNet for Android is a **PWA (Progressive Web App)**: the sensor still runs
on a PC/Raspberry Pi (or a server), and the phone is the dashboard client.
There is no Play Store APK in this repository; a native/TWA wrapper is a
separate project.

## Quick path (same Wi-Fi, lab only)

1. Run the server on the PC:
   ```powershell
   python run.py
   ```
   By default it binds `127.0.0.1`. To reach it from the phone, bind the LAN:
   ```powershell
   $env:LASSI_HOST="0.0.0.0"
   $env:LASSI_TOKEN_OPERATOR="<long-random>"
   $env:LASSI_TOKEN_VIEWER="<long-random>"
   $env:LASSI_SECRET="<long-random>"
   python run.py
   ```
2. Allow TCP 8000 in the PC firewall **only for your LAN**.
3. Find the PC's LAN IP (`ipconfig` / the dashboard header).
4. On Android Chrome, open `http://<PC-IP>:8000`.
5. Sign in with the operator or viewer token.
6. Chrome menu → **Add to Home screen**. It becomes a shortcut/app icon.

Plain HTTP gives a home-screen shortcut, but **not** the full PWA install
prompt, service worker, or offline shell: browsers require a secure context.

## Full PWA (HTTPS, install prompt, offline shell)

Use a private tunnel/VPN rather than exposing the app directly:

- **Tailscale** on the server and phone, then use Tailscale Serve to publish
  `http://127.0.0.1:8000` over the tailnet HTTPS name. This keeps the app off
  the public internet and gives a trusted certificate. Check your Tailscale
  version's `serve` syntax.
- **Cloudflare Tunnel** (`cloudflared tunnel --url http://127.0.0.1:8000`) for
  a quick HTTPS URL; that URL is public, so keep tokens strong and rotate them.
  Do not use it for an unauthenticated instance.
- **Caddy/Nginx + TLS** on the LAN also works, but Android must trust the CA
  for a private CA; that is more work than Tailscale.

Once served over HTTPS, Chrome on Android shows **Install app** (and LassiNet’s
header button when the browser supports `beforeinstallprompt`). The service
worker caches only the static shell: **never** state, alerts, logs, metrics or
the WebSocket. If the server is offline, the shell may load but live data will
not.

## What works

- Map, alerts, triage, block/unblock, trust, rename, webhooks, API v1.
- Token login (operator/viewer) and OIDC via a trusted reverse proxy.
- Add to Home screen and standalone display.
- Mobile layout: stacked map/feeds, smaller header badges, safe-area insets.

## What does not work / limits

- The phone does not capture the LAN; it is only a client.
- No Play Store listing, push notifications or native background service.
- No offline live data; the shell is cached, not the API.
- Not an enterprise mobile management/SSO story; OIDC is via the proxy.
- Never use `LASSI_HOST=0.0.0.0` without tokens/TLS/VPN.

## Why not an APK?

An APK/TWA adds Android build tooling, signing keys, store review and a second
release pipeline. The PWA gives the same dashboard on Android today. A TWA can
be added later if the project needs Play Store distribution.
