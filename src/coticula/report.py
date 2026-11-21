from __future__ import annotations

import json
import os
import sys
from typing import List

from coticula.model import Finding, Report, sev_rank

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
RESET, BOLD, GREEN, RED, DIM = "\033[0m", "\033[1m", "\033[32m", "\033[31m", "\033[2m"


def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")


def _sorted(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-sev_rank(f.severity), f.check, f.path, f.line))


def text(report: Report, fail_on: str, show_info: bool = False, stream=None) -> str:
    stream = stream or sys.stdout
    c = _use_color(stream)

    def col(s, code):
        return f"{code}{s}{RESET}" if c else s

    lines = [col("Coticula", BOLD) + f" {report.version} · scanned {report.files_scanned} files in {report.root}", ""]
    shown = [f for f in _sorted(report.findings) if show_info or f.severity != "info"]
    for f in shown:
        loc = f.path + (f":{f.line}" if f.line else "") if f.path else "(project)"
        lines.append(f"{col(f.severity.upper().ljust(8), COLORS[f.severity])} {f.check}/{f.rule}  {col(loc, DIM)}")
        lines.append(f"         {f.message}")
        if f.snippet:
            lines.append(f"         {col('> ' + f.snippet, DIM)}")
        if f.fix:
            lines.append(f"         fix: {f.fix}")
    if not shown:
        lines.append("No issues found.")
    counts = report.counts()
    lines += ["", "Summary: " + "  ".join(f"{k} {counts[k]}" for k in ("critical", "high", "medium", "low", "info")),
              f"Quality score: {report.quality_score}/100"]
    if report.capabilities:
        lines.append("Capabilities detected: " + ", ".join(k.replace("_", " ") for k in report.capabilities))
    verdict = report.passed(fail_on)
    tier = "Scanned ✓" if report.tier() == "scanned" else "not eligible (high/critical findings)"
    lines.append(f"Badge tier: {tier}")
    lines.append(col(f"PASS (fail-on: {fail_on})", GREEN) if verdict else col(f"FAIL (fail-on: {fail_on})", RED))
    return "\n".join(lines) + "\n"


def to_json(report: Report, fail_on: str) -> str:
    return json.dumps(report.to_dict(fail_on), indent=2) + "\n"


def markdown(report: Report, fail_on: str) -> str:
    counts = report.counts()
    ok = report.passed(fail_on)
    out = [f"## Coticula scan: {'✅ pass' if ok else '❌ fail'} (fail-on: `{fail_on}`)", "",
           f"Files scanned: **{report.files_scanned}** · Quality score: **{report.quality_score}/100** · "
           f"Tier: **{'Scanned' if report.tier() == 'scanned' else 'not eligible'}**", "",
           "| Critical | High | Medium | Low |", "|---|---|---|---|",
           f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |", ""]
    rows = [f for f in _sorted(report.findings) if f.severity != "info"]
    if rows:
        out += ["| Severity | Check | Location | Finding |", "|---|---|---|---|"]
        for f in rows[:100]:
            loc = f"`{f.path}:{f.line}`" if f.path and f.line else (f"`{f.path}`" if f.path else "project")
            msg = f.message.replace("|", "\\|")
            out.append(f"| {f.severity} | {f.check}/{f.rule} | {loc} | {msg} |")
        if len(rows) > 100:
            out.append(f"\n…and {len(rows) - 100} more. Run `coticula scan` locally for the full list.")
    else:
        out.append("No issues found.")
    return "\n".join(out) + "\n"
