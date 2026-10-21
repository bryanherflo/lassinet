"""Static checks for the zero-build dashboard assets.

The frontend has no bundler, so nothing would catch a typo that breaks
`app.js` at parse time (that exact bug shipped in 0.4.6 and left a blank
dashboard). These tests are cheap guards: syntax check with Node when
available, cache-buster consistency, and app.js -> index.html id wiring.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DASH = ROOT / "dashboard"


def test_app_js_parses_with_node() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed; skipping JavaScript syntax check")
    result = subprocess.run(
        [node, "--check", str(DASH / "app.js")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_cache_busters_match() -> None:
    html = (DASH / "index.html").read_text(encoding="utf-8")
    css = re.search(r"style\.css\?v=([\w.]+)", html)
    js = re.search(r"app\.js\?v=([\w.]+)", html)
    vendor = re.search(r"vendor/vis-network\.min\.js\?v=([\w.]+)", html)
    assert css and js and vendor, "index.html must version every bundled asset"
    assert css.group(1) == js.group(1) == vendor.group(1), \
        "style.css, app.js and the bundled map library must share the same ?v= value"


def test_dashboard_loads_the_bundled_map_library_only() -> None:
    html = (DASH / "index.html").read_text(encoding="utf-8")
    assert "vendor/vis-network.min.js" in html
    assert "unpkg.com" not in html, "the dashboard must stay usable offline and without a CDN"


def test_static_element_ids_exist() -> None:
    html = (DASH / "index.html").read_text(encoding="utf-8")
    js = (DASH / "app.js").read_text(encoding="utf-8")
    ids = set(re.findall(r'getElementById\("([^"]+)"\)', js))
    runtime_created = {"trust-menu", "attack-banner"}
    missing = sorted(i for i in ids - runtime_created if f'id="{i}"' not in html)
    assert not missing, f"app.js references element ids missing from index.html: {missing}"
