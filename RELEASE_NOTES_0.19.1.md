# LassiNet 0.19.1 — audit fixes for flow analytics

> **Status: pre-release / beta.** Bug-fix release after the 0.19.0 flow
> analytics work.

## Fixed

- Test suite isolation: the global flow store is now pointed at a throwaway
  SQLite file before `app` is imported. A plain `pytest` run can no longer
  write synthetic demo flows into the operator's real `data/flows.db`.
- Timeline alert markers now keep the newest alerts; the previous slice could
  return the oldest tail of the newest-first alert deque.
- PWA cache reset no longer reloads a fresh browser that has neither a service
  worker nor CacheStorage entries.
- Export CSV is hidden on the Top talkers and Timeline tabs, where the flow
  filters do not apply.
- `data/flows.db` is created with owner-only permissions on POSIX.
- UI cache is **`v=3.62`**.

## Tests

**264 tests** pass; CI on Ubuntu and Windows.

## Update

```powershell
git pull
# Ctrl+C the running server, then restart with your monitor-only block:
python run.py --live --fw mock
```

The first load after the update may clear the previous PWA cache once.
