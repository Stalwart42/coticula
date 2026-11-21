from __future__ import annotations

import re


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def get_line(text: str, lineno: int) -> str:
    lines = text.splitlines()
    return lines[lineno - 1] if 0 < lineno <= len(lines) else ""


def ignored(text: str, lineno: int) -> bool:
    from coticula.walker import IGNORE_MARKER
    return IGNORE_MARKER in get_line(text, lineno)


def clip(s: str, n: int = 120) -> str:
    s = s.strip()
    return s if len(s) <= n else s[: n - 1] + "…"


WORD = re.compile(r"\w+")
