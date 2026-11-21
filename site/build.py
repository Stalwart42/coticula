"""Bundle the site into a single Cloudflare Worker module (site/dist/worker.js).

Usage:  python site/build.py            (run from the repo root after `python -m build --wheel`)
Deploy: wrangler deploy (see site/wrangler.toml) or the Cloudflare API.
"""
from __future__ import annotations

import base64
import glob
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from coticula import __version__  # noqa: E402
from coticula.badge import svg  # noqa: E402


def read(name: str) -> str:
    with open(os.path.join(HERE, "src", name), encoding="utf-8") as fh:
        return fh.read()


def main() -> None:
    wheels = sorted(glob.glob(os.path.join(ROOT, "dist", f"coticula-{__version__}-py3-none-any.whl")))
    if not wheels:
        sys.exit(f"Build the wheel first: python -m build --wheel  (looking for coticula-{__version__})")
    wheel_path = wheels[-1]
    wheel_name = os.path.basename(wheel_path)
    wheel = open(wheel_path, "rb").read()
    sha = hashlib.sha256(wheel).hexdigest()

    subs = {
        "__VERSION__": __version__,
        "__SHA256__": sha,
        "__BADGE_OK__": svg("coticula", "scanned · 95", "#3f8f5f"),
        "__BADGE_BAD__": svg("coticula", "issues found", "#b5473a"),
    }

    def fill(s: str) -> str:
        for k, v in subs.items():
            s = s.replace(k, v)
        return s

    assets = {
        "index": fill(read("index.html")),
        "docs": fill(read("docs.html")),
        "css": read("style.css"),
        "js": read("app.js"),
        "install": fill(read("install.sh")),
    }
    worker = fill(read("worker.template.js"))
    worker = worker.replace("__ASSETS__", json.dumps(assets))
    worker = worker.replace("__WHEEL_NAME__", json.dumps(wheel_name))
    worker = worker.replace("__WHEEL_B64__", json.dumps(base64.b64encode(wheel).decode()))
    worker = worker.replace("__SUMS__", json.dumps(f"{sha}  {wheel_name}\n"))

    os.makedirs(os.path.join(HERE, "dist"), exist_ok=True)
    out = os.path.join(HERE, "dist", "worker.js")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(worker)
    print(f"wrote {out} ({len(worker) // 1024} KB) · wheel {wheel_name} sha256 {sha}")


if __name__ == "__main__":
    main()
