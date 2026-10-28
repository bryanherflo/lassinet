# Local scheduled reports

`scripts/scheduled_report.py` writes a JSON snapshot and, with `--pdf`, a
native PDF. It reads the same `data/flows.db` as the dashboard, but it does not
start capture, open a port or contact any external service.

```bash
python scripts/scheduled_report.py --hours 24 --pdf
```

Output defaults to `data/reports/` (ignored by git because it is under
`data/`). `--keep 30` keeps the newest 30 report files; use `--keep 0` to keep
everything. The SQLite store clamps the window to seven days.

## Windows Task Scheduler

Create a task that runs daily while the PC is on:

1. Program: `C:\Users\<you>\Projects\AegisNet\.venv\Scripts\python.exe`
2. Arguments:
   `scripts\scheduled_report.py --hours 24 --pdf --keep 30`
3. Start in:
   `C:\Users\<you>\Projects\AegisNet`

Use the virtualenv interpreter; do not rely on a globally activated shell.
The task does not need administrator rights for a report, but the account must
be able to read `data/flows.db`. If the PC was asleep, the next run reports the
window that is still in SQLite; it does not invent missing coverage.

PowerShell one-liner (adjust the path/user):

```powershell
$action = New-ScheduledTaskAction -Execute "C:\Users\Usuario\Projects\AegisNet\.venv\Scripts\python.exe" `
  -Argument "scripts\scheduled_report.py --hours 24 --pdf --keep 30" `
  -WorkingDirectory "C:\Users\Usuario\Projects\AegisNet"
$trigger = New-ScheduledTaskTrigger -Daily -At 8am
Register-ScheduledTask -TaskName "LassiNet daily report" -Action $action -Trigger $trigger
```

## cron (Linux/macOS)

```cron
0 8 * * * cd /opt/lassinet && .venv/bin/python scripts/scheduled_report.py --hours 24 --pdf --keep 30 >> logs/reports.log 2>&1
```

`logs/` and `data/` are local runtime directories. Keep their permissions
restrictive: reports contain IP addresses and device names.

## systemd timer

`/etc/systemd/system/lassinet-report.service`:

```ini
[Unit]
Description=LassiNet daily local report
After=lassinet.service

[Service]
Type=oneshot
User=lassinet
WorkingDirectory=/opt/lassinet
ExecStart=/opt/lassinet/.venv/bin/python scripts/scheduled_report.py --hours 24 --pdf --keep 30
```

`/etc/systemd/system/lassinet-report.timer`:

```ini
[Unit]
Description=Run the LassiNet report every day

[Timer]
OnCalendar=*-*-* 08:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Then `sudo systemctl daemon-reload && sudo systemctl enable --now lassinet-report.timer`.

## What is not included

- Email, SMTP, cloud upload or webhook delivery. Use your own local tooling and
  treat the report as sensitive network metadata.
- A scheduler inside the web process. Keeping it external means a report never
  competes with capture and survives a dashboard restart.
- Backfilled coverage for periods when the PC was off. The report states the
  actual SQLite window.
