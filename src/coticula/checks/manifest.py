"""Permission manifest: what a component says it touches vs. what its code actually uses.

A project declares its capabilities in coticula.json:

    {
      "name": "my-mcp-server",
      "permissions": {
        "network": ["api.github.com"],   # true / false / list of hosts
        "filesystem": "read",            # "none" | "read" | "write"
        "env": ["GITHUB_TOKEN"],         # true / false / list of variable names
        "subprocess": false
      },
      "ignore": ["tests/fixtures/**"]
    }

v1 detection is static (pattern-based). Sandboxed runtime verification comes later.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from coticula.checks import clip, get_line, ignored, line_of
from coticula.model import Finding

MANIFEST_NAME = "coticula.json"

DETECTORS: Dict[str, List[Tuple[str, re.Pattern]]] = {
    "network": [
        ("py", re.compile(r"^\s*(?:from\s+|import\s+(?:[\w.]+\s*,\s*)*)(?:requests|httpx|urllib\.request|urllib3|aiohttp|socket|http\.client|websockets|paramiko|ftplib|smtplib)\b", re.M)),
        ("js", re.compile(r"(?:require\(\s*['\"]|from\s+['\"])(?:axios|node-fetch|undici|got|ws|https?|net|dgram|tls)['\"]")),
        ("js", re.compile(r"\bfetch\s*\(")),
        ("sh", re.compile(r"\b(?:curl|wget|nc|ssh|scp)\s")),
    ],
    "subprocess": [
        ("py", re.compile(r"\b(?:subprocess\.\w+|os\.system|os\.popen|os\.exec\w*|pty\.spawn|asyncio\.create_subprocess_\w+)\s*\(")),
        ("js", re.compile(r"(?:require\(\s*['\"]|from\s+['\"])(?:node:)?child_process['\"]|\bexeca\b|\bBun\.spawn\b|\bDeno\.Command\b")),
    ],
    "env": [
        ("py", re.compile(r"\bos\.(?:environ|getenv)\b")),
        ("js", re.compile(r"\bprocess\.env\b|\bDeno\.env\b|\bBun\.env\b")),
    ],
    "filesystem_write": [
        ("py", re.compile(r"\bopen\([^)\n]*,\s*['\"][rb]*[wax]\+?b?['\"]|\.write_(?:text|bytes)\(|\bshutil\.(?:rmtree|move|copy\w*)\(|\bos\.(?:remove|unlink|rename|makedirs|mkdir|rmdir)\(")),
        ("js", re.compile(r"\bfs(?:\.promises)?\.(?:writeFile|appendFile|rm|rmSync|unlink|mkdir|rename|copyFile|writeFileSync|appendFileSync|unlinkSync|mkdirSync)\b")),
    ],
}
DYNAMIC_CODE = [
    ("py", re.compile(r"(?<![\w.])(?:eval|exec)\s*\(|\b__import__\s*\(|\bpickle\.loads?\s*\(|\bmarshal\.loads\s*\(")),
    ("js", re.compile(r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.runIn\w+Context\s*\(")),
]
LANG = {".py": "py", ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js", ".jsx": "js", ".sh": "sh", ".bash": "sh", ".zsh": "sh"}


def load_manifest(root: str) -> Tuple[Optional[Dict], Optional[str]]:
    path = os.path.join(root, MANIFEST_NAME)
    if not os.path.exists(path):
        return None, None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), None
    except (OSError, ValueError) as exc:
        return None, str(exc)


def detect(files) -> Dict[str, List[Tuple[str, int, str]]]:
    found: Dict[str, List[Tuple[str, int, str]]] = {k: [] for k in DETECTORS}
    found["dynamic_code"] = []
    for f in files:
        lang = LANG.get(f.ext)
        if not lang or f.is_test:
            continue
        for cap, rules in list(DETECTORS.items()) + [("dynamic_code", DYNAMIC_CODE)]:
            for rlang, rx in rules:
                if rlang != lang:
                    continue
                for m in rx.finditer(f.text):
                    ln = line_of(f.text, m.start())
                    if not ignored(f.text, ln):
                        found[cap].append((f.rel, ln, clip(get_line(f.text, ln))))
    return found


def _declared(perms: Dict, cap: str) -> bool:
    if cap == "filesystem_write":
        return str(perms.get("filesystem", "none")).lower() == "write"
    v = perms.get(cap, False)
    return bool(v)


def scan(files, root: str) -> Tuple[List[Finding], Dict[str, List[str]]]:
    out: List[Finding] = []
    found = detect(files)
    summary = {cap: sorted({f"{p}:{ln}" for p, ln, _ in hits})[:10] for cap, hits in found.items() if hits}

    for p, ln, snip in found["dynamic_code"][:20]:
        out.append(Finding("manifest", "dynamic-code-execution", "medium",
                           "Runs code built at runtime (eval/exec/unsafe deserialisation); hard to review and easy to abuse.",
                           p, ln, snip, "Replace with explicit logic, or document why it is safe and add coticula:ignore."))

    manifest, err = load_manifest(root)
    caps = [c for c in DETECTORS if found[c]]
    if err:
        out.append(Finding("manifest", "manifest-invalid", "high", f"{MANIFEST_NAME} could not be parsed: {err}", MANIFEST_NAME, 1))
        return out, summary
    if manifest is None:
        uses = ", ".join(c.replace("_", " ") for c in caps) or "nothing detected"
        out.append(Finding("manifest", "manifest-missing", "medium",
                           f"No {MANIFEST_NAME} permission manifest. Detected capabilities: {uses}.",
                           fix="Run `coticula init` to generate one from what was detected, then review it."))
        return out, summary

    perms = manifest.get("permissions") or {}
    for cap in caps:
        if not _declared(perms, cap):
            p, ln, snip = found[cap][0]
            more = len(found[cap]) - 1
            out.append(Finding("manifest", f"undeclared-{cap.replace('_', '-')}", "high",
                               f"Code uses {cap.replace('_', ' ')} but the manifest does not declare it"
                               + (f" (+{more} more place{'s' if more != 1 else ''})." if more else "."),
                               p, ln, snip, f"Declare it in {MANIFEST_NAME} or remove the code path."))
    for cap in DETECTORS:
        if _declared(perms, cap) and not found[cap]:
            out.append(Finding("manifest", f"unused-{cap.replace('_', '-')}", "info",
                               f"Manifest declares {cap.replace('_', ' ')} but no use was detected; consider narrowing it.", MANIFEST_NAME, 0))
    return out, summary


def generate(files) -> Dict:
    found = detect(files)
    return {
        "name": "",
        "description": "",
        "permissions": {
            "network": bool(found["network"]),
            "filesystem": "write" if found["filesystem_write"] else "read",
            "env": bool(found["env"]),
            "subprocess": bool(found["subprocess"]),
        },
        "ignore": [],
    }
