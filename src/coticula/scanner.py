from __future__ import annotations

import os
from typing import Iterable, Optional

from coticula import __version__
from coticula.checks import ai, deps, manifest, quality, secrets
from coticula.model import Report
from coticula.walker import collect

ALL_CHECKS = ("secrets", "deps", "ai", "manifest", "quality")


def run(root: str, excludes: Iterable[str] = (), only: Optional[Iterable[str]] = None, offline: bool = False) -> Report:
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise FileNotFoundError(f"Not a directory: {root}")
    man, _ = manifest.load_manifest(root)
    excludes = list(excludes) + list((man or {}).get("ignore") or [])
    files = collect(root, excludes)
    checks = [c for c in ALL_CHECKS if not only or c in set(only)]

    report = Report(root=root, version=__version__, files_scanned=len(files), checks_run=checks)
    if "secrets" in checks:
        report.findings += secrets.scan(files)
    if "deps" in checks:
        report.findings += deps.scan(files, offline=offline)
    if "ai" in checks:
        report.findings += ai.scan(files)
    if "manifest" in checks:
        found, caps = manifest.scan(files, root)
        report.findings += found
        report.capabilities = caps
    if "quality" in checks:
        found, score = quality.scan(files)
        report.findings += found
        report.quality_score = score
    return report
