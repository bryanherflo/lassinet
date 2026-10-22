"""Integration test for the OPNsense provider over a real network connection.

The unit test replaces `urlopen` and therefore proves nothing about the wire
format. This test starts a real HTTP server that speaks the OPNsense
`alias_util` contract (Basic auth, JSON body, `{"status":"done"}`) and drives
the provider against it, so the URL, the method, the headers, the body and
the response parsing are exercised over a socket.

The TLS case reproduces a lab firewall with a self-signed certificate:
`OPNSENSE_VERIFY_TLS=0` must let the provider through, while the default
(verification on) must refuse it instead of silently trusting it.
"""

import base64
import json
import shutil
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.firewall import Firewall  # noqa: E402

KEY = "testkey"
SECRET = "testsecret"
ALIAS = "lassinet_blocked"
ADDRESS = "203.0.113.5"


class AliasState:
    """The state of the fake firewall: the addresses of the alias."""

    def __init__(self) -> None:
        self.addresses: list[str] = []
        self.requests: list[dict] = []


def _handler_for(state: AliasState, expected_auth: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:      # keep the test output clean
            pass

        def _reply(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:                 # noqa: N802 (http.server API)
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            state.requests.append({
                "path": self.path,
                "method": self.command,
                "auth": self.headers.get("Authorization", ""),
                "content_type": self.headers.get("Content-Type", ""),
                "body": raw.decode("utf-8", "replace"),
            })
            if self.headers.get("Authorization", "") != f"Basic {expected_auth}":
                self._reply(401, {"status": "error", "message": "authentication failed"})
                return
            parts = [p for p in self.path.split("/") if p]
            if len(parts) != 5 or parts[:3] != ["api", "firewall", "alias_util"]:
                self._reply(404, {"status": "error", "message": "no such endpoint"})
                return
            action, alias = parts[3], parts[4]
            try:
                address = json.loads(raw.decode("utf-8")).get("address", "")
            except ValueError:
                self._reply(400, {"status": "error", "message": "invalid json"})
                return
            if alias != ALIAS:
                self._reply(404, {"status": "error", "message": "alias not found"})
                return
            if action == "add":
                if address not in state.addresses:
                    state.addresses.append(address)
            elif action == "delete":
                if address not in state.addresses:
                    self._reply(400, {"status": "error", "message": "not in alias"})
                    return
                state.addresses.remove(address)
            else:
                self._reply(404, {"status": "error", "message": "no such action"})
                return
            self._reply(200, {"status": "done"})

    return Handler


def _start_server(state: AliasState, expected_auth: str, certfile: str | None = None,
                  keyfile: str | None = None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(state, expected_auth))
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.fixture
def opnsense(monkeypatch):
    state = AliasState()
    expected_auth = base64.b64encode(f"{KEY}:{SECRET}".encode()).decode()
    server = _start_server(state, expected_auth)
    url = f"http://127.0.0.1:{server.server_address[1]}"
    monkeypatch.setenv("LASSI_FW", "opnsense")
    monkeypatch.setenv("OPNSENSE_URL", url)
    monkeypatch.setenv("OPNSENSE_KEY", KEY)
    monkeypatch.setenv("OPNSENSE_SECRET", SECRET)
    monkeypatch.setenv("OPNSENSE_ALIAS", ALIAS)
    monkeypatch.setenv("OPNSENSE_VERIFY_TLS", "1")
    try:
        yield server, state, url
    finally:
        server.shutdown()
        server.server_close()


def test_opnsense_block_and_unblock_over_a_real_connection(opnsense) -> None:
    server, state, url = opnsense
    fw = Firewall(provider="opnsense")

    assert fw.block(ADDRESS, reason="integration test") is True
    assert state.addresses == [ADDRESS]
    request = state.requests[-1]
    assert request["method"] == "POST"
    assert request["path"] == f"/api/firewall/alias_util/add/{ALIAS}"
    assert request["content_type"] == "application/json"
    assert json.loads(request["body"]) == {"address": ADDRESS}
    expected_auth = base64.b64encode(f"{KEY}:{SECRET}".encode()).decode()
    assert request["auth"] == f"Basic {expected_auth}"

    assert fw.unblock(ADDRESS) is True
    assert state.addresses == []
    assert state.requests[-1]["path"] == f"/api/firewall/alias_util/delete/{ALIAS}"


def test_opnsense_reports_a_rejected_operation(opnsense, monkeypatch) -> None:
    server, state, url = opnsense
    monkeypatch.setenv("OPNSENSE_KEY", "wrong-key")
    fw = Firewall(provider="opnsense")
    assert fw.block(ADDRESS) is False           # 401 -> honest failure
    assert state.addresses == []


def test_opnsense_reports_a_missing_alias(opnsense, monkeypatch) -> None:
    server, state, url = opnsense
    monkeypatch.setenv("OPNSENSE_ALIAS", "does_not_exist")
    fw = Firewall(provider="opnsense")
    assert fw.block(ADDRESS) is False           # 404 -> honest failure
    assert state.addresses == []


def _find_openssl() -> str | None:
    """Locate the openssl CLI.

    `shutil.which` only sees PATH: on Windows the binary usually ships with
    Git for Windows and is *not* exported, so the TLS test used to skip on a
    perfectly capable machine. Look in the usual install locations too.
    """
    found = shutil.which("openssl")
    if found:
        return found
    candidates = [
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
        r"C:\Program Files (x86)\Git\usr\bin\openssl.exe",
        "/usr/bin/openssl",
        "/usr/local/bin/openssl",
        "/opt/homebrew/bin/openssl",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return None


def _self_signed_cert(tmp_path: Path) -> tuple[str, str] | None:
    """Generate a throwaway certificate for 127.0.0.1 (needs the openssl CLI)."""
    openssl = _find_openssl()
    if openssl is None:
        return None
    certfile = tmp_path / "cert.pem"
    keyfile = tmp_path / "key.pem"
    result = subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(keyfile), "-out", str(certfile), "-days", "2",
         "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    return str(certfile), str(keyfile)


def test_opnsense_tls_against_a_self_signed_lab_firewall(tmp_path, monkeypatch) -> None:
    cert = _self_signed_cert(tmp_path)
    if cert is None:
        pytest.skip("openssl is not available to generate a test certificate")
    certfile, keyfile = cert
    state = AliasState()
    expected_auth = base64.b64encode(f"{KEY}:{SECRET}".encode()).decode()
    server = _start_server(state, expected_auth, certfile=certfile, keyfile=keyfile)
    url = f"https://127.0.0.1:{server.server_address[1]}"
    monkeypatch.setenv("LASSI_FW", "opnsense")
    monkeypatch.setenv("OPNSENSE_URL", url)
    monkeypatch.setenv("OPNSENSE_KEY", KEY)
    monkeypatch.setenv("OPNSENSE_SECRET", SECRET)
    monkeypatch.setenv("OPNSENSE_ALIAS", ALIAS)
    try:
        # A lab firewall with a self-signed certificate: verification off is
        # the documented way to use it, and it must actually work.
        monkeypatch.setenv("OPNSENSE_VERIFY_TLS", "0")
        fw = Firewall(provider="opnsense")
        assert fw.block(ADDRESS) is True
        assert state.addresses == [ADDRESS]

        # With verification on, the same certificate must be refused.
        monkeypatch.setenv("OPNSENSE_VERIFY_TLS", "1")
        strict = Firewall(provider="opnsense")
        assert strict.block("203.0.113.6") is False
    finally:
        server.shutdown()
        server.server_close()
