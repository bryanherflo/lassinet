"""Keep the test suite out of the real runtime files.

The API tests exercise the block/trust/alert endpoints, and those audit to the
same `logs/events.jsonl` and `data/*.json` that a running sensor uses. Without
this fixture, `python -m pytest` injects fake events (10.0.0.9, 8.8.8.8,
203.0.113.90, "a" -> "b") and fake trusted devices into the operator's real
audit log, where `/api/logs` serves them as if they had happened.

Found in 0.4.26 while verifying a live run: nine fixture alerts (12:42:04 to
12:42:08) landed in logs/events.jsonl from a plain test run.

The network is part of the isolation too: enrichment (DNS + port fingerprint)
is switched off for the whole suite, so a test that reaches `discover()` can
never probe the machine's real LAN.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# app.py constructs the flow history store at import time. Point it at a
# throwaway SQLite file before any test module imports app, or a plain
# `pytest` run writes synthetic demo flows into the operator's real DB.
os.environ.setdefault(
    "LASSI_FLOW_DB",
    str(Path(tempfile.mkdtemp(prefix="lassinet-test-flows-")) / "flows.db"),
)


@pytest.fixture(scope="session", autouse=True)
def _isolated_runtime_files(tmp_path_factory):
    import lassi.discovery as discovery
    import lassi.state as state
    import lassi.triage as triage

    tmp = tmp_path_factory.mktemp("runtime")
    names = ("EVENTS_LOG_PATH", "ALIAS_PATH", "TRUSTED_PATH", "DISMISSED_PATH",
             "BLOCK_EXPIRY_PATH", "CHECKPOINT_PATH")
    saved = {name: getattr(state, name) for name in names}
    state.EVENTS_LOG_PATH = tmp / "events.jsonl"
    state.ALIAS_PATH = tmp / "device_names.json"
    state.TRUSTED_PATH = tmp / "trusted_devices.json"
    state.DISMISSED_PATH = tmp / "dismissed_alerts.json"
    state.BLOCK_EXPIRY_PATH = tmp / "block_expiry.json"
    state.CHECKPOINT_PATH = tmp / "audit_checkpoint.json"
    discovery.CACHE_PATH = tmp / "device_cache.json"
    triage.TRIAGE_DB_PATH = tmp / "triage.db"
    # app.state was constructed when app.py was imported (before this fixture),
    # so it may have read the real block_expiry.json. Clear it explicitly.
    app_module = sys.modules.get("app")
    if app_module is not None:
        app_module.state.block_expiry.clear()

    # A test run must never probe the local network: discovery tests opt back
    # in explicitly and stub every probe.
    saved_enrich = os.environ.get("LASSI_ENRICH")
    os.environ["LASSI_ENRICH"] = "0"
    yield tmp
    for name, value in saved.items():
        setattr(state, name, value)
    if saved_enrich is None:
        os.environ.pop("LASSI_ENRICH", None)
    else:
        os.environ["LASSI_ENRICH"] = saved_enrich
