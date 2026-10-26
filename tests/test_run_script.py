import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import run  # noqa: E402


def test_venv_python_matches_the_platform() -> None:
    python = run.venv_python()
    if os.name == "nt":
        assert python.parent.name == "Scripts"
        assert python.name == "python.exe"
    else:
        assert python.parent.name == "bin"
        assert python.name == "python"


def test_requirements_hash_is_stable_and_short() -> None:
    first = run.requirements_hash()
    assert len(first) == 16
    assert first == run.requirements_hash()


def test_firewall_choices_match_the_providers() -> None:
    assert set(run.FIREWALLS) == {"mock", "windows", "nftables", "opnsense", "pfsense"}
