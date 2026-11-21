"""Quality / anti-slop signals. Not a judgement of taste: things a reviewer would
reject on sight — missing tests and docs, tests that test nothing, placeholders,
swallowed errors."""
from __future__ import annotations

import re
from typing import List, Tuple

from coticula.checks import clip, get_line, ignored, line_of
from coticula.model import Finding

FAKE_TEST_PY = re.compile(r"^[ \t]*def\s+test_\w*\s*\([^)]*\)\s*(?:->\s*\w+\s*)?:\s*\n(?:[ \t]*(?:#.*|\"\"\".*\"\"\")?\n)*[ \t]*(?:pass|assert\s+True|\.\.\.)\s*$", re.M)
FAKE_TEST_JS = re.compile(r"expect\(\s*(?:true|1)\s*\)\.(?:toBe|toEqual)\(\s*(?:true|1)\s*\)|assert\.ok\(\s*true\s*\)|it\(\s*['\"][^'\"]*['\"]\s*,\s*(?:async\s*)?\(\)\s*=>\s*\{\s*\}\s*\)")
PLACEHOLDER = re.compile(r"(?i)lorem ipsum|TODO:?\s*implement|not\s+implemented\s+yet|raise\s+NotImplementedError|throw\s+new\s+Error\(\s*['\"]not implemented")  # coticula:ignore
SWALLOW_PY = re.compile(r"^[ \t]*except(?:\s+(?:Exception|BaseException))?\s*:\s*\n[ \t]*pass\b", re.M)
SWALLOW_JS = re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}")
TODO = re.compile(r"\b(?:TODO|FIXME|XXX|HACK)\b")


def _has(files, pred) -> bool:
    return any(pred(f) for f in files)


def scan(files) -> Tuple[List[Finding], int]:
    out: List[Finding] = []
    penalty = 0
    code = [f for f in files if f.is_code and not f.is_test]
    tests = [f for f in files if f.is_test and f.is_code]

    readme = next((f for f in files if f.rel.lower() in ("readme.md", "readme.rst", "readme.txt", "readme")), None)
    if readme is None:
        out.append(Finding("quality", "no-readme", "medium", "No README at the project root.", fix="Explain what it does, how to install it and how to use it."))
        penalty += 15
    elif len(readme.text.strip()) < 300:
        out.append(Finding("quality", "thin-readme", "low", "README is very short.", readme.rel, 1, fix="Add install, usage and an example."))
        penalty += 5
    if not _has(files, lambda f: f.rel.lower().split(".")[0] in ("license", "licence", "copying")):
        out.append(Finding("quality", "no-license", "low", "No LICENSE file; others can't safely reuse it.", fix="Add a license (e.g. MIT or Apache-2.0)."))
        penalty += 5
    if code and not tests:
        out.append(Finding("quality", "no-tests", "medium", f"{len(code)} source files but no tests found.", fix="Add tests that exercise real behaviour."))
        penalty += 25

    fake = 0
    for f in tests:
        for rx in (FAKE_TEST_PY, FAKE_TEST_JS):
            for m in rx.finditer(f.text):
                ln = line_of(f.text, m.start())
                if ignored(f.text, ln):
                    continue
                fake += 1
                out.append(Finding("quality", "empty-test", "medium", "Test that can't fail (empty body or asserts a constant).",
                                   f.rel, ln, clip(get_line(f.text, ln)), "Assert on real output, or delete the test."))
    penalty += min(20, fake * 5)

    ph = sw = big = 0
    todo_count = total_lines = 0
    for f in code:
        lines = f.lines()
        total_lines += len(lines)
        todo_count += len(TODO.findall(f.text))
        for m in PLACEHOLDER.finditer(f.text):
            ln = line_of(f.text, m.start())
            if not ignored(f.text, ln) and ph < 15:
                ph += 1
                out.append(Finding("quality", "placeholder", "low", "Placeholder or unimplemented code.", f.rel, ln, clip(get_line(f.text, ln))))
        for rx in (SWALLOW_PY, SWALLOW_JS):
            for m in rx.finditer(f.text):
                ln = line_of(f.text, m.start())
                if not ignored(f.text, ln) and sw < 15:
                    sw += 1
                    out.append(Finding("quality", "swallowed-error", "low", "Error is caught and silently ignored.",
                                       f.rel, ln, clip(get_line(f.text, ln)), "Handle it, log it, or let it propagate."))
        if len(lines) > 1500:
            big += 1
            out.append(Finding("quality", "very-large-file", "low", f"{len(lines)} lines in one file; hard to review.", f.rel, 0))
    penalty += min(10, ph * 2) + min(10, sw * 2) + min(10, big * 5)
    if total_lines and todo_count * 100 / total_lines > 1.0:
        out.append(Finding("quality", "todo-density", "low", f"{todo_count} TODO/FIXME markers in {total_lines} lines of code."))
        penalty += 5

    score = max(0, 100 - penalty)
    out.append(Finding("quality", "quality-score", "info", f"Quality score {score}/100."))
    return out, score
