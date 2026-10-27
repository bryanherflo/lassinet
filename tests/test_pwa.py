"""PWA assets and first-run .env generator; no browser/network required."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def test_manifest_and_icons_are_installable() -> None:
    manifest = json.loads((ROOT / "dashboard" / "manifest.webmanifest")
                          .read_text(encoding="utf-8"))
    assert manifest["name"] == "LassiNet"
    assert manifest["display"] == "standalone"
    assert manifest["start_url"] == "/"
    sizes = {icon["sizes"] for icon in manifest["icons"]}
    assert "192x192" in sizes and "512x512" in sizes
    assert any(icon.get("purpose") == "maskable" for icon in manifest["icons"])
    for icon in manifest["icons"]:
        path = ROOT / "dashboard" / icon["src"]
        assert path.is_file()
        assert path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_service_worker_never_caches_api_or_websocket() -> None:
    sw = (ROOT / "dashboard" / "sw.js").read_text(encoding="utf-8")
    assert "lassinet-shell-3.57" in sw
    assert "STATIC_PATHS" in sw
    assert 'url.pathname.startsWith("/api/")' in sw
    assert 'url.pathname === "/ws"' in sw
    assert 'url.pathname === "/metrics"' in sw


def test_index_registers_pwa_and_install_button() -> None:
    index = (ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
    app = (ROOT / "dashboard" / "app.js").read_text(encoding="utf-8")
    assert "manifest.webmanifest" in index
    assert 'id="btn-install"' in index
    assert "beforeinstallprompt" in app
    assert "serviceWorker.register" in app


def test_setup_env_creates_credentials_once(tmp_path) -> None:
    from lassi.setup_env import create_env

    path = tmp_path / ".env"
    first = create_env(path)
    assert first["created"] is True
    assert first["operator"] and first["viewer"]
    content = path.read_text(encoding="utf-8")
    assert "LASSI_MODE=demo" in content
    assert f"LASSI_TOKEN_OPERATOR={first['operator']}" in content

    second = create_env(path)
    assert second["created"] is False
    assert path.read_text(encoding="utf-8") == content
