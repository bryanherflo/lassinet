"""Native PDF report renderer and HTTP download."""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as lassi_app  # noqa: E402
from lassi.pdf_report import render_report_pdf  # noqa: E402


def _sample() -> dict:
    return {
        "hours": 24,
        "since": 1_700_000_000,
        "until": 1_700_086_400,
        "flows": 42,
        "bytes": 123456,
        "packets": 789,
        "alerts": [{
            "kind": "alert", "at": 1_700_000_100, "attack": "port_scan",
            "src": "192.0.2.10", "dst": "198.51.100.20", "severity": "medium",
        }],
        "blocks": [{
            "kind": "block", "at": 1_700_000_200, "ip": "192.0.2.10",
            "reason": "manual",
        }],
        "ports": [{"port": "443", "count": 12}],
        "top": [{
            "ip": "192.0.2.10", "name": "laptop",
            "bytes_out": 1000, "bytes_in": 2000, "flows": 3,
        }],
        "sensitivity": "balanced",
        "suppress": ["192.0.2.0/24"],
        "blocked": 1,
        "trusted": 2,
    }


def test_pdf_renderer_returns_a_pdf_document() -> None:
    payload = render_report_pdf(_sample())
    assert payload.startswith(b"%PDF")
    assert len(payload) > 1000


def test_report_pdf_endpoint_downloads_attachment() -> None:
    with TestClient(lassi_app.app) as client:
        response = client.get("/api/report.pdf?hours=24")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert "attachment" in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF")
