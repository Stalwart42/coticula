from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from coticula import __version__, badge, report as rep
from coticula.checks import manifest
from coticula.model import SEVERITIES
from coticula.scanner import ALL_CHECKS, run
from coticula.walker import collect

EPILOG = """examples:
  coticula scan .                       scan the current project
  coticula scan . --format json -o report.json
  coticula scan . --fail-on medium      stricter CI gate
  coticula init                         write a coticula.json permission manifest
  coticula badge . -o coticula.svg      write a README badge

exit codes: 0 pass · 1 findings at/above --fail-on · 2 usage or runtime error
docs: https://coticula.kineticdevops.com/docs"""


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="coticula", description="Coticula — test before you trust.",
                                epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"coticula {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan a project directory")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    s.add_argument("-o", "--output", help="write the report to a file")
    s.add_argument("--fail-on", choices=SEVERITIES[1:], default="high", help="lowest severity that fails the scan (default: high)")
    s.add_argument("--only", action="append", choices=ALL_CHECKS, help="run only these checks (repeatable)")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching GLOB (repeatable)")
    s.add_argument("--offline", action="store_true", help="skip the OSV.dev vulnerability lookup")
    s.add_argument("--show-info", action="store_true", help="include informational findings in text output")
    s.add_argument("--badge", metavar="FILE", help="also write an SVG badge")

    i = sub.add_parser("init", help="create coticula.json from detected capabilities")
    i.add_argument("path", nargs="?", default=".")
    i.add_argument("--force", action="store_true")

    b = sub.add_parser("badge", help="scan and write an SVG badge")
    b.add_argument("path", nargs="?", default=".")
    b.add_argument("-o", "--output", default="coticula-badge.svg")
    b.add_argument("--offline", action="store_true")
    return p


def _scan(args) -> int:
    r = run(args.path, excludes=args.exclude, only=args.only, offline=args.offline)
    if args.format == "json":
        out = rep.to_json(r, args.fail_on)
    elif args.format == "markdown":
        out = rep.markdown(r, args.fail_on)
    else:
        out = rep.text(r, args.fail_on, show_info=args.show_info, stream=sys.stdout if not args.output else None)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Report written to {args.output} ({'PASS' if r.passed(args.fail_on) else 'FAIL'})", file=sys.stderr)
    else:
        sys.stdout.write(out)
    if args.badge:
        with open(args.badge, "w", encoding="utf-8") as fh:
            fh.write(badge.for_report(r))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(rep.markdown(r, args.fail_on))
        except OSError:
            pass
    return 0 if r.passed(args.fail_on) else 1


def _init(args) -> int:
    target = os.path.join(args.path, manifest.MANIFEST_NAME)
    if os.path.exists(target) and not args.force:
        print(f"{target} already exists (use --force to overwrite).", file=sys.stderr)
        return 2
    data = manifest.generate(collect(os.path.abspath(args.path)))
    data["name"] = os.path.basename(os.path.abspath(args.path))
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    print(f"Wrote {target}. Review it: narrow 'network' to a list of hosts and 'env' to variable names where you can.")
    return 0


def _badge(args) -> int:
    r = run(args.path, offline=args.offline)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(badge.for_report(r))
    print(f"Wrote {args.output} ({r.tier()}). Add to your README: ![Coticula]({args.output})")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in ("scan", "init", "badge", "-h", "--help", "--version"):
        argv = ["scan"] + argv  # `coticula .` == `coticula scan .`
    if not argv:
        argv = ["scan", "."]
    args = _parser().parse_args(argv)
    try:
        if args.cmd == "scan":
            return _scan(args)
        if args.cmd == "init":
            return _init(args)
        if args.cmd == "badge":
            return _badge(args)
    except FileNotFoundError as exc:
        print(f"coticula: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 2
    _parser().print_help()
    return 2
