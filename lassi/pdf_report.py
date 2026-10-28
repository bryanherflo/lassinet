"""Native PDF report rendering with the optional fpdf2 dependency.

The PDF is intentionally a snapshot of the same data used by the HTML report:
aggregate counters, top devices, recent alert/block events and top ports. It
does not fetch anything and never includes packet payloads.
"""

from __future__ import annotations

import time
from typing import Any


class PDFReportError(RuntimeError):
    """The PDF renderer is unavailable or the input cannot be rendered."""


def _ascii(value: object, limit: int = 200) -> str:
    """Core PDF fonts are Latin-1; avoid crashing on arrows/emoji."""
    text = str(value if value is not None else "")
    replacements = {
        "\u2192": "->", "\u2190": "<-", "\u00b7": "-", "\u2022": "-",
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2013": "-", "\u2014": "-", "\u2026": "...", "\u00a0": " ",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    text = text.encode("latin-1", "replace").decode("latin-1")
    return text[:limit]


def _bytes(value: object) -> str:
    try:
        number = float(str(value or 0))
    except (TypeError, ValueError):
        number = 0.0
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    index = 0
    while number >= 1024 and index < len(units) - 1:
        number /= 1024.0
        index += 1
    if index == 0:
        return f"{int(number)} {units[index]}"
    return f"{number:.1f} {units[index]}"


def _clock(value: object) -> str:
    try:
        stamp = float(str(value or 0))
    except (TypeError, ValueError):
        stamp = 0.0
    if stamp <= 0:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stamp))


def _table(pdf: Any, widths: list[float], cells: list[str], *, bold: bool = False) -> None:
    pdf.set_font("Helvetica", "B" if bold else "", 8)
    for width, cell in zip(widths, cells, strict=False):
        pdf.cell(width, 6, _ascii(cell, 120), border=1)
    pdf.ln(6)


def render_report_pdf(data: dict[str, Any]) -> bytes:
    """Render a report dict from FlowStore.report() into PDF bytes."""
    try:
        from fpdf import FPDF
    except ImportError as exc:  # pragma: no cover - dependency is in requirements
        raise PDFReportError(
            "native PDF export needs fpdf2: pip install -r requirements.txt"
        ) from exc

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_title("LassiNet report")
    pdf.set_author("LassiNet")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "LassiNet report")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 9)
    hours = data.get("hours", 24)
    since = data.get("since")
    until = data.get("until")
    generated = _clock(time.time())
    pdf.cell(0, 5, _ascii(
        f"Window: last {hours} h | {_clock(since)} to {_clock(until)} | generated {generated}"
    ))
    pdf.ln(5)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(0, 5, "Metadata only: no packet payloads are stored or included.")
    pdf.ln(8)
    pdf.set_text_color(0, 0, 0)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, "Summary")
    pdf.ln(7)
    pdf.set_font("Helvetica", "", 9)
    summary = [
        ("Flows", f"{int(data.get('flows') or 0):,}"),
        ("Bytes", _bytes(data.get("bytes"))),
        ("Packets", f"{int(data.get('packets') or 0):,}"),
        ("Alert events", str(len(data.get("alerts") or []))),
        ("Block events", str(len(data.get("blocks") or []))),
        ("Sensitivity", str(data.get("sensitivity") or "not available offline")),
        ("Suppression", ", ".join(data.get("suppress") or []) or "none"),
        ("Blocked now", str(data.get("blocked", "-"))),
        ("Trusted", str(data.get("trusted", "-"))),
    ]
    for label, value in summary:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(38, 5, _ascii(label))
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, _ascii(value))
        pdf.ln(5)
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, "Top devices")
    pdf.ln(7)
    top = data.get("top") or []
    if top:
        _table(pdf, [72, 36, 36, 36], ["Device", "Out", "In", "Flows"], bold=True)
        for item in top[:10]:
            _table(pdf, [72, 36, 36, 36], [
                item.get("name") or item.get("ip") or "?",
                _bytes(item.get("bytes_out")),
                _bytes(item.get("bytes_in")),
                str(item.get("flows", 0)),
            ])
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, "No flows in this window.")
        pdf.ln(5)
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, "Alerts and blocks")
    pdf.ln(7)
    events = list(data.get("alerts") or []) + list(data.get("blocks") or [])
    events.sort(key=lambda event: float(event.get("at") or 0))
    if events:
        _table(pdf, [38, 18, 124], ["Time", "Kind", "Detail"], bold=True)
        for event in events[-50:]:
            if event.get("kind") == "block":
                detail = f"{event.get('ip', '?')} - {event.get('reason', '')}"
                kind = "block"
            else:
                detail = (f"{event.get('attack', 'alert')} | "
                          f"{event.get('src', '?')} -> {event.get('dst', '?')}")
                kind = "alert"
            _table(pdf, [38, 18, 124], [_clock(event.get("at")), kind, detail])
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, "No alert/block events in this window.")
        pdf.ln(5)
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, "Top destination ports")
    pdf.ln(7)
    ports = data.get("ports") or []
    pdf.set_font("Helvetica", "", 9)
    if ports:
        text = ", ".join(f"{item.get('port', '?')} ({item.get('count', 0)})"
                         for item in ports[:15])
        pdf.multi_cell(0, 5, _ascii(text, 1000))
    else:
        pdf.cell(0, 5, "No port samples in this window.")
        pdf.ln(5)
    pdf.ln(4)

    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(90, 90, 90)
    pdf.multi_cell(0, 4, _ascii(
        "LassiNet is a free, MIT-licensed self-hosted tool. This report is an "
        "operational snapshot, not a compliance certification or a guarantee "
        "that the network is free of compromise."
    ))

    payload = bytes(pdf.output())
    if not payload.startswith(b"%PDF"):
        raise PDFReportError("PDF renderer returned an invalid document")
    return payload
