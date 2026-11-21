"""Dependencies: known vulnerabilities via the OSV.dev database, plus unpinned versions."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Dict, List, Tuple

from coticula.model import Finding

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
TIMEOUT = 20
MAX_DETAIL = 60

Pkg = Tuple[str, str, str, str, int]  # ecosystem, name, version, file, line

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(==|>=|~=|<=|>|<|!=)?\s*([^;#\s,]*)")


def _parse_requirements(f) -> Tuple[List[Pkg], List[Finding]]:
    pkgs, findings = [], []
    for i, raw in enumerate(f.lines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = REQ_LINE.match(line)
        if not m:
            continue
        name, op, ver = m.group(1), m.group(3), m.group(4)
        if op == "==" and ver:
            pkgs.append(("PyPI", name, ver, f.rel, i))
        else:
            findings.append(Finding("deps", "unpinned-dependency", "low",
                                    f"'{name}' is not pinned to an exact version, so builds can change underneath you.",
                                    f.rel, i, line, "Pin with == (or use a lock file) so the scanned version is the one you ship."))
    return pkgs, findings


def _parse_pyproject(f) -> List[Pkg]:
    try:
        import tomllib  # type: ignore
    except ImportError:  # Python < 3.11
        return []
    try:
        data = tomllib.loads(f.text)
    except Exception:
        return []
    pkgs = []
    for spec in data.get("project", {}).get("dependencies", []) or []:
        m = REQ_LINE.match(spec)
        if m and m.group(3) == "==" and m.group(4):
            pkgs.append(("PyPI", m.group(1), m.group(4), f.rel, 0))
    return pkgs


def _parse_package_lock(f) -> List[Pkg]:
    try:
        data = json.loads(f.text)
    except ValueError:
        return []
    pkgs = []
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict) or not meta.get("version"):
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        pkgs.append(("npm", name, meta["version"], f.rel, 0))
    if not pkgs:  # lockfile v1
        for name, meta in (data.get("dependencies") or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                pkgs.append(("npm", name, meta["version"], f.rel, 0))
    return pkgs


def _parse_package_json(f) -> Tuple[List[Pkg], List[Finding]]:
    try:
        data = json.loads(f.text)
    except ValueError:
        return [], []
    pkgs, findings = [], []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?", spec):
                pkgs.append(("npm", name, spec, f.rel, 0))
            elif spec in ("*", "latest") or spec.startswith(("http", "git", "file:")):
                findings.append(Finding("deps", "unpinned-dependency", "low",
                                        f"'{name}' uses '{spec}', which is not a fixed version.", f.rel, 0,
                                        fix="Use a version range plus a committed package-lock.json."))
    return pkgs, findings


def _post(url: str, body: Dict) -> Dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", "User-Agent": "coticula"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode())


def _get(url: str) -> Dict:
    req = urllib.request.Request(url, headers={"User-Agent": "coticula"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode())


SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _severity(vuln: Dict) -> str:
    sev = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(sev, str) and sev.upper() in SEV_MAP:
        return SEV_MAP[sev.upper()]
    for aff in vuln.get("affected") or []:
        s = (aff.get("ecosystem_specific") or {}).get("severity")
        if isinstance(s, str) and s.upper() in SEV_MAP:
            return SEV_MAP[s.upper()]
    return "high"  # unknown severity: treat as serious until reviewed


def collect_packages(files) -> Tuple[List[Pkg], List[Finding]]:
    pkgs: List[Pkg] = []
    findings: List[Finding] = []
    has_lock = {f.rel.rsplit("/", 1)[0] if "/" in f.rel else "" for f in files if f.name == "package-lock.json"}
    for f in files:
        n = f.name.lower()
        if n.startswith("requirements") and n.endswith(".txt"):
            p, fi = _parse_requirements(f)
            pkgs += p
            findings += fi
        elif n == "pyproject.toml":
            pkgs += _parse_pyproject(f)
        elif n == "package-lock.json":
            pkgs += _parse_package_lock(f)
        elif n == "package.json":
            folder = f.rel.rsplit("/", 1)[0] if "/" in f.rel else ""
            p, fi = _parse_package_json(f)
            findings += fi
            if folder not in has_lock:
                pkgs += p
    # de-duplicate
    uniq, seen = [], set()
    for p in pkgs:
        key = (p[0], p[1].lower(), p[2])
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq, findings


def scan(files, offline: bool = False) -> List[Finding]:
    pkgs, findings = collect_packages(files)
    if not pkgs:
        return findings
    if offline:
        findings.append(Finding("deps", "osv-skipped", "info", f"{len(pkgs)} pinned packages found; vulnerability lookup skipped (--offline)."))
        return findings
    try:
        results = []
        for i in range(0, len(pkgs), 500):
            chunk = pkgs[i:i + 500]
            resp = _post(OSV_BATCH, {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v, _, _ in chunk]})
            results += resp.get("results", [])
    except (urllib.error.URLError, OSError, ValueError) as exc:
        findings.append(Finding("deps", "osv-unreachable", "info", f"Could not reach OSV.dev ({exc.__class__.__name__}); dependency vulnerabilities were not checked."))
        return findings

    details: Dict[str, Dict] = {}
    fetched = 0
    for (eco, name, ver, rel, ln), res in zip(pkgs, results):
        for v in res.get("vulns") or []:
            vid = v.get("id", "")
            if vid not in details and fetched < MAX_DETAIL:
                fetched += 1
                try:
                    details[vid] = _get(OSV_VULN + vid)
                except (urllib.error.URLError, OSError, ValueError):
                    details[vid] = {}
            d = details.get(vid, {})
            summary = d.get("summary") or "Known vulnerability"
            findings.append(Finding("deps", "known-vulnerability", _severity(d) if d else "high",
                                    f"{name} {ver} ({eco}): {vid} — {summary}", rel, ln, f"{name}=={ver}",
                                    f"Upgrade {name}; see https://osv.dev/vulnerability/{vid}"))
    return findings
