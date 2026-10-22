"""Windows Firewall tests.

Two of them need an **elevated** shell: the GitHub Windows runner is
administrator, so the real round trip runs there; on a normal machine they are
skipped unless the shell was elevated ("Run as administrator").

The third one needs the opposite — a **non-elevated** shell — and checks the
honest-failure path: `netsh` is rejected, so the provider must return False and
leave no rule behind instead of pretending the source is blocked.

The address used is 203.0.113.5 (TEST-NET-3): it is reserved for
documentation, so the rule can never affect real traffic.
"""

import ctypes
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.firewall import Firewall  # noqa: E402

ADDRESS = "203.0.113.5"


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


requires_admin = pytest.mark.skipif(
    os.name != "nt" or not _is_admin(),
    reason="needs Windows and an elevated shell (administrator)",
)

requires_no_admin = pytest.mark.skipif(
    os.name != "nt" or _is_admin(),
    reason="needs Windows without elevation (it tests the refusal)",
)


@requires_admin
def test_windows_firewall_rule_round_trip(monkeypatch) -> None:
    """block -> the rule exists in the firewall -> unblock -> it is gone."""
    monkeypatch.delenv("LASSI_FW", raising=False)
    fw = Firewall(provider="windows")
    try:
        assert fw.block(ADDRESS, reason="integration test") is True
        assert ADDRESS in (fw.active_blocks() or set())

        assert fw.unblock(ADDRESS) is True
        assert ADDRESS not in (fw.active_blocks() or set())
    finally:
        # Never leave a rule behind, whatever happened above.
        fw.unblock(ADDRESS)


@requires_admin
def test_windows_unblock_is_idempotent_for_a_missing_rule(monkeypatch) -> None:
    """A rule that was never created (or was deleted by hand) must not leave
    the dashboard stuck on "still blocked"."""
    monkeypatch.delenv("LASSI_FW", raising=False)
    fw = Firewall(provider="windows")
    fw.unblock(ADDRESS)                 # make sure it does not exist
    assert fw.unblock(ADDRESS) is True


@requires_no_admin
def test_windows_block_without_administrator_fails_honestly(monkeypatch) -> None:
    """`netsh` needs elevation: the provider must say so instead of claiming a
    block that never happened, and it must not leave a half-created rule."""
    monkeypatch.delenv("LASSI_FW", raising=False)
    fw = Firewall(provider="windows")
    assert fw.block(ADDRESS, reason="not elevated") is False
    assert ADDRESS not in (fw.active_blocks() or set())

