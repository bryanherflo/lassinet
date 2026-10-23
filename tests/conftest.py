"""Keep the test suite out of the real runtime files.

The API tests exercise the block/trust/alert endpoints, and those audit to the
same `logs/events.jsonl` and `data/*.json` that a running sensor uses. Without
this fixture, `python -m pytest` injects fake events (10.0.0.9, 8.8.8.8,
203.0.113.90, "a" -> "b") and fake trusted devices into the operator's real
audit log, where `/api/logs` serves them as if they had happened.

Found in 0.4.26 while verifying a live run: nine fixture alerts (12:42:04 to
12:42:08) landed in logs/events.jsonl from a plain test run.
"""

import pytest


@pytest.fixture(scope="session", autouse=True)
def _isolated_runtime_files(tmp_path_factory):
    import lassi.state as state

    tmp = tmp_path_factory.mktemp("runtime")
    names = ("EVENTS_LOG_PATH", "ALIAS_PATH", "TRUSTED_PATH")
    saved = {name: getattr(state, name) for name in names}
    state.EVENTS_LOG_PATH = tmp / "events.jsonl"
    state.ALIAS_PATH = tmp / "device_names.json"
    state.TRUSTED_PATH = tmp / "trusted_devices.json"
    yield tmp
    for name, value in saved.items():
        setattr(state, name, value)
