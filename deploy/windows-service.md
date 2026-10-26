# Windows service / startup

There are two supported ways to keep LassiNet running on Windows. Both are
optional; `python run.py` is still the simplest interactive path.

## Option A — Task Scheduler (no extra software)

1. Create a dedicated local user (do **not** use your day-to-day admin).
2. Install to `C:\LassiNet`, create the virtualenv and run the tests:
   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe -m pytest -q
   ```
3. Create `C:\LassiNet\service.env` from `deploy\lassinet.env.example`.
4. Task Scheduler → **Create Task**:
   - Run whether the user is logged on or not.
   - Trigger: At startup.
   - Action: `C:\LassiNet\.venv\Scripts\python.exe`, arguments `app.py --port 8000`, start in `C:\LassiNet`.
   - Restart on failure: every 1 minute, 3 attempts.
5. For **real Windows Firewall blocks**, the task user must be an
   Administrator (or use a separate privileged helper); for monitor-only, use
   the normal user and keep `LASSI_FW=mock`/OPNsense.
6. Put Caddy/Nginx (or a VPN) in front if the dashboard is not localhost.
   Set tokens, `LASSI_LIVE_ALLOW`, and `LASSI_SECRET` in the service environment.

## Option B — NSSM

```powershell
nssm install LassiNet "C:\LassiNet\.venv\Scripts\python.exe" "app.py --port 8000"
nssm set LassiNet AppDirectory "C:\LassiNet"
nssm set LassiNet AppEnvironmentExtra LASSI_MODE=live LASSI_LIVE_ALLOW=192.168.0.0/24 LASSI_FW=mock
nssm set LassiNet AppStdout "C:\LassiNet\logs\service.out.log"
nssm set LassiNet AppStderr "C:\LassiNet\logs\service.err.log"
nssm set LassiNet AppExit Default Restart
nssm start LassiNet
```

NSSM runs as LocalSystem by default: that is enough for Npcap capture and
Windows Firewall, but it is **more privilege than needed**. Prefer a dedicated
account and a mock/OPNsense provider, or a narrow privileged helper.

## What a service does not solve

- It does not add high availability.
- It does not make the web UI safe to expose directly to the internet.
- It does not back up `data/` or `logs/`; use `python -m lassi.backup create`.
- Closing the interactive console still stops a foreground run; the service
  keeps running.
