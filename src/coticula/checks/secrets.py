"""Leaked credentials: well-known token formats, private keys, committed .env files,
and high-entropy values assigned to secret-looking names."""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import List

from coticula.checks import ignored, line_of
from coticula.model import Finding

RULES = [
    ("anthropic-key", "critical", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai-key", "critical", r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{32,}"),
    ("aws-access-key", "critical", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github-token", "critical", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
    ("github-fine-grained-token", "critical", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    ("slack-token", "critical", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    ("stripe-live-key", "critical", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"),
    ("google-api-key", "high", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("private-key", "critical", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
]
COMPILED = [(rid, sev, re.compile(rx)) for rid, sev, rx in RULES]

GENERIC = re.compile(
    r"""(?ix)\b(api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|token|passwd|password|client[_-]?secret)\b
    \s*[:=]\s*['"]([^'"\s]{12,})['"]"""
)
PLACEHOLDER = re.compile(r"(?i)(example|sample|dummy|placeholder|your[_-]|changeme|xxxx|<[^>]+>|\$\{|\{\{|redacted|test|fake|\*\*\*)")


def entropy(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def redact(value: str) -> str:
    return value[:6] + "…" + f"({len(value)} chars)"


def scan(files) -> List[Finding]:
    out: List[Finding] = []
    for f in files:
        name = f.name.lower()
        if name == ".env" or (name.startswith(".env.") and not any(k in name for k in ("example", "sample", "template"))):
            out.append(Finding("secrets", "env-file-committed", "high",
                               "Environment file is part of the project; these usually hold real credentials.",
                               f.rel, 1, fix="Remove it from the repo, rotate anything in it, and add it to .gitignore. Ship a .env.example instead."))
        seen = set()
        for rid, sev, rx in COMPILED:
            for m in rx.finditer(f.text):
                ln = line_of(f.text, m.start())
                if ignored(f.text, ln) or (ln, m.group(0)) in seen:
                    continue
                if PLACEHOLDER.search(m.group(0)):
                    continue
                seen.add((ln, m.group(0)))
                out.append(Finding("secrets", rid, sev, f"Possible {rid.replace('-', ' ')} in source.", f.rel, ln,
                                   redact(m.group(0)), "Revoke/rotate the credential, remove it from history, load it from the environment instead."))
        for m in GENERIC.finditer(f.text):
            value = m.group(2)
            ln = line_of(f.text, m.start())
            if ignored(f.text, ln) or PLACEHOLDER.search(value) or any(value == s[1] for s in seen):
                continue
            if entropy(value) < 3.5 or value.isalpha():
                continue
            out.append(Finding("secrets", "hardcoded-secret", "high",
                               f"High-entropy value assigned to '{m.group(1)}'.", f.rel, ln, redact(value),
                               "Move the value to an environment variable or secret manager."))
    return out
