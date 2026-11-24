#!/usr/bin/env bash
# Install the latest keepassxc-mcp release binary for this machine.
#
# What it does: picks the right Release asset for your OS/arch, downloads it
# and SHA256SUMS.txt from https://github.com/michaeltg17/keepassxc-mcp/releases/latest,
# verifies the checksum, and installs the single binary into $PREFIX/bin
# (default ~/.local/bin). It does NOT install keepassxc-cli — that is KeePassXC's
# own binary and this tool refuses to run without it (see the wiki: Setup-and-Use).
#
# Pre-releases (beta verification builds) are NOT installed by default — the
# "latest" endpoint excludes them. To install the newest beta on purpose:
#   KEEPASSXC_MCP_PRERELEASE=1 curl -fsSL https://raw.githubusercontent.com/michaeltg17/keepassxc-mcp/main/install.sh | bash
#
# Usage:  curl -fsSL https://raw.githubusercontent.com/michaeltg17/keepassxc-mcp/main/install.sh | bash
#     or: ./install.sh            (from a clone)
#     or: PREFIX=/usr/local ./install.sh
set -euo pipefail

REPO="michaeltg17/keepassxc-mcp"
PREFIX="${PREFIX:-$HOME/.local}"
BINDIR="$PREFIX/bin"

os="$(uname -s)"
case "$os" in
  Linux)  platform=linux ;;
  Darwin) platform=osx ;;
  *) echo "Unsupported OS: $os (on Windows use install.ps1)" >&2; exit 1 ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  archid=x64 ;;
  aarch64|arm64) archid=arm64 ;;
  *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
esac

rid="$platform-$archid"
if [ "${KEEPASSXC_MCP_PRERELEASE:-0}" = "1" ]; then
  # Newest prerelease (GitHub's JSON is pretty-printed one field per line).
  tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=30" | awk '
    /"tag_name":/ { t=$0; sub(/.*"tag_name": *"/,"",t); sub(/".*/,"",t); tag=t }
    /"prerelease": true/ { if (tag != "") { print tag; exit } }')"
  channel="PRERELEASE"
else
  tag="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')"
  channel="release"
fi
[ -n "$tag" ] || { echo "Could not determine the latest $channel tag." >&2; exit 1; }

ver="${tag#v}"
asset="keepassxc-mcp-${ver}-$rid.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Latest $channel: $tag"
if ! curl -fsSL -o "$tmp/$asset" "$base/$asset"; then
  # Releases before v0.2.2 used unversioned asset names.
  asset="keepassxc-mcp-$rid.tar.gz"
  curl -fsSL -o "$tmp/$asset" "$base/$asset"
fi
curl -fsSL -o "$tmp/SHA256SUMS.txt" "$base/SHA256SUMS.txt"

echo "Verifying checksum..."
if ! (cd "$tmp" && grep " $asset\$" SHA256SUMS.txt | sha256sum -c -); then
  echo "Checksum verification FAILED. Nothing installed." >&2
  exit 1
fi

mkdir -p "$BINDIR"
tar -xzf "$tmp/$asset" -C "$BINDIR" keepassxc-mcp
chmod +x "$BINDIR/keepassxc-mcp"

echo "Installed: $BINDIR/keepassxc-mcp"
case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) echo "Note: $BINDIR is not on your PATH. Add it, e.g.:"
     echo "  export PATH=\"\$BINDIR:\$PATH\"  # put in your shell profile" ;;
esac

if ! command -v keepassxc-cli >/dev/null 2>&1; then
  echo
  echo "WARNING: keepassxc-cli was not found on your PATH. keepassxc-mcp needs it"
  echo "(it is part of KeePassXC: apt install keepassxc / brew install keepassxc)."
fi
