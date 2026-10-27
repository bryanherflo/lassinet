# LassiNet 0.20.1 — timeline backfill safety

> **Status: pre-release / beta.** Small follow-up to the 0.20.0 durable timeline.

## Fixed

- The one-time timeline backfill now uses the **current mode family**:
  - a live run includes prior live sessions, including passive/dry-run;
  - demo, fallback-demo and synthetic test sessions are skipped.
- Block events inherit the mode of the preceding `startup` audit event, so
  synthetic demo blocks cannot leak into a live 24 h timeline.
- 266 tests; UI cache stays at **`v=3.63`**.

## Update

```powershell
git pull
# Ctrl+C the running server, then restart with your monitor-only block:
python run.py --live --fw mock
```
