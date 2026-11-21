"""Self-contained SVG badge (no external service). Flat style, like shields.io."""
from __future__ import annotations

from html import escape

from coticula.model import Report


def _w(s: str) -> int:
    return int(len(s) * 6.6) + 12


def svg(label: str, message: str, color: str) -> str:
    lw, mw = _w(label), _w(message)
    total = lw + mw
    l, m = escape(label), escape(message)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{l}: {m}">'
        f"<title>{l}: {m}</title>"
        f'<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#2b2f36"/><rect x="{lw}" width="{mw}" height="20" fill="{color}"/>'
        f'<rect width="{total}" height="20" fill="url(#s)"/></g>'
        f'<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw / 2:.1f}" y="15" fill="#010101" fill-opacity=".3">{l}</text><text x="{lw / 2:.1f}" y="14">{l}</text>'
        f'<text x="{lw + mw / 2:.1f}" y="15" fill="#010101" fill-opacity=".3">{m}</text><text x="{lw + mw / 2:.1f}" y="14">{m}</text></g></svg>'
    )


def for_report(report: Report) -> str:
    if report.tier() == "scanned":
        return svg("coticula", f"scanned · {report.quality_score}", "#3f8f5f" if report.quality_score >= 70 else "#b08a2e")
    return svg("coticula", "issues found", "#b5473a")
