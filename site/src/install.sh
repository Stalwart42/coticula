#!/bin/sh
# Coticula installer — https://coticula.kineticdevops.com
# Downloads the wheel, verifies its SHA-256, installs with pipx (preferred) or pip --user.
# Read before you run: curl -fsSL https://coticula.kineticdevops.com/install.sh | less
set -eu

VERSION="__VERSION__"
WHEEL="coticula-${VERSION}-py3-none-any.whl"
URL="https://coticula.kineticdevops.com/dl/${WHEEL}"
SHA256="__SHA256__"

say() { printf '%s\n' "coticula: $*"; }
die() { printf '%s\n' "coticula: $*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.9+ first."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || die "Python 3.9+ required (found $(python3 -V 2>&1))."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM
say "downloading ${WHEEL}"
if command -v curl >/dev/null 2>&1; then curl -fsSL "$URL" -o "$TMP/$WHEEL"
elif command -v wget >/dev/null 2>&1; then wget -q "$URL" -O "$TMP/$WHEEL"
else die "need curl or wget"; fi

if command -v shasum >/dev/null 2>&1; then GOT="$(shasum -a 256 "$TMP/$WHEEL" | cut -d' ' -f1)"
elif command -v sha256sum >/dev/null 2>&1; then GOT="$(sha256sum "$TMP/$WHEEL" | cut -d' ' -f1)"
else die "need shasum or sha256sum to verify the download"; fi
[ "$GOT" = "$SHA256" ] || die "checksum mismatch (expected $SHA256, got $GOT). Not installing."
say "checksum verified"

if command -v pipx >/dev/null 2>&1; then
  pipx install --force "$TMP/$WHEEL"
else
  say "pipx not found; using pip --user (tip: brew install pipx)"
  python3 -m pip install --user --upgrade "$TMP/$WHEEL" || die "pip install failed. On macOS/Homebrew Python, install pipx and re-run."
fi

if command -v coticula >/dev/null 2>&1; then
  say "installed $(coticula --version). Try: coticula scan ."
else
  say "installed. If 'coticula' isn't found, add your user bin directory to PATH (pipx ensurepath)."
fi
