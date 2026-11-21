from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from typing import Iterable, List

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    "dist", "build", ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".next", ".nuxt", "target", ".idea", ".vscode", ".terraform", "vendor", ".cache",
}
MAX_BYTES = 1_000_000
IGNORE_MARKER = "coticula:ignore"

CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh", ".rb", ".go", ".rs", ".php"}
DOC_EXT = {".md", ".mdx", ".txt", ".prompt", ".rst"}
CONFIG_EXT = {".json", ".yaml", ".yml", ".toml"}


@dataclass
class SourceFile:
    rel: str
    path: str
    text: str

    @property
    def name(self) -> str:
        return os.path.basename(self.rel)

    @property
    def ext(self) -> str:
        n = self.name.lower()
        if n.endswith(".prompt.md"):
            return ".prompt"
        return os.path.splitext(n)[1]

    @property
    def is_code(self) -> bool:
        return self.ext in CODE_EXT

    @property
    def is_doc(self) -> bool:
        return self.ext in DOC_EXT

    @property
    def is_test(self) -> bool:
        r = self.rel.replace("\\", "/").lower()
        n = self.name.lower()
        return (
            "/tests/" in "/" + r
            or "/test/" in "/" + r
            or "/__tests__/" in "/" + r
            or n.startswith("test_")
            or n.endswith("_test.py")
            or ".test." in n
            or ".spec." in n
        )

    def lines(self) -> List[str]:
        return self.text.splitlines()


def _excluded(rel: str, excludes: Iterable[str]) -> bool:
    rel = rel.replace("\\", "/")
    for pat in excludes:
        pat = pat.rstrip("/")
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*") or rel.startswith(pat + "/"):
            return True
    return False


def collect(root: str, excludes: Iterable[str] = ()) -> List[SourceFile]:
    excludes = list(excludes)
    files: List[SourceFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not _excluded(os.path.normpath(os.path.join(rel_dir, d)), excludes)
        )
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.normpath(os.path.relpath(full, root)).replace("\\", "/")
            if _excluded(rel, excludes) or os.path.islink(full):
                continue
            try:
                if os.path.getsize(full) > MAX_BYTES:
                    continue
                with open(full, "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue
            if b"\x00" in raw[:8192]:
                continue  # binary
            files.append(SourceFile(rel=rel, path=full, text=raw.decode("utf-8", errors="replace")))
    return files
