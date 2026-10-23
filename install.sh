#!/bin/sh
# rcu installer (macOS / Linux).
#   curl -fsSL https://raw.githubusercontent.com/Jay-Hyun/remote-computer-use/main/install.sh | sh
#
# Env: RCU_VERSION (default: latest), RCU_INSTALL_DIR (default: ~/.local/bin),
#      RCU_SKIP_SKILLS=1 (binary only), RCU_BASE_URL / RCU_SKILL_URL (testing).
set -eu

REPO="Jay-Hyun/remote-computer-use"
VERSION="${RCU_VERSION:-latest}"
DEST="${RCU_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

if [ -n "${RCU_BASE_URL:-}" ]; then
  BASE="$RCU_BASE_URL"
elif [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/$REPO/releases/latest/download"
else
  BASE="https://github.com/$REPO/releases/download/$VERSION"
fi

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  target="aarch64-apple-darwin" ;;
  Darwin-x86_64) target="x86_64-apple-darwin" ;;
  Linux-x86_64)  target="x86_64-unknown-linux-musl" ;;
  *) die "unsupported platform: $(uname -s) $(uname -m)" ;;
esac

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar  >/dev/null 2>&1 || die "tar is required"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

asset="rcu-$target.tar.gz"
say "Downloading $asset ($VERSION)..."
curl -fsSL "$BASE/$asset" -o "$tmp/$asset" || die "download failed: $BASE/$asset"
curl -fsSL "$BASE/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "download failed: $BASE/SHA256SUMS"

expected="$(grep "  $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1 || true)"
[ -n "$expected" ] || die "no checksum for $asset in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$asset" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)"
else
  die "need sha256sum or shasum to verify the download"
fi
[ "$expected" = "$actual" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"

tar -xzf "$tmp/$asset" -C "$tmp"
[ -f "$tmp/rcu" ] || die "archive did not contain rcu"
mkdir -p "$DEST"
install -m 755 "$tmp/rcu" "$DEST/rcu"
say "Installed $DEST/rcu"

case ":$PATH:" in
  *":$DEST:"*) ;;
  *) say "Note: $DEST is not on your PATH. Add:  export PATH=\"$DEST:\$PATH\"" ;;
esac

"$DEST/rcu" init || say "Note: could not create the default policy; run 'rcu init' yourself."

if [ "${RCU_SKIP_SKILLS:-0}" != "1" ]; then
  # Claude Code plugin
  if command -v claude >/dev/null 2>&1; then
    if claude plugin marketplace add "$REPO" >/dev/null 2>&1 &&
       claude plugin install remote-computer-use@remote-computer-use >/dev/null 2>&1; then
      say "Installed the Claude Code plugin."
    else
      say "Note: could not install the Claude Code plugin automatically. In Claude Code run:"
      say "  /plugin marketplace add $REPO"
      say "  /plugin install remote-computer-use@remote-computer-use"
    fi
  fi
  # Codex skill (same SKILL.md)
  codex_home="${CODEX_HOME:-$HOME/.codex}"
  if command -v codex >/dev/null 2>&1 || [ -d "$codex_home" ]; then
    if [ -n "${RCU_SKILL_URL:-}" ]; then
      skill_url="$RCU_SKILL_URL"
    else
      ref="main"; [ "$VERSION" = "latest" ] || ref="$VERSION"
      skill_url="https://raw.githubusercontent.com/$REPO/$ref/plugin/skills/remote-computer-use/SKILL.md"
    fi
    mkdir -p "$codex_home/skills/remote-computer-use"
    if curl -fsSL "$skill_url" -o "$codex_home/skills/remote-computer-use/SKILL.md"; then
      say "Installed the Codex skill."
    else
      say "Note: could not download the Codex skill from $skill_url"
    fi
  fi
fi

say ""
say "Next:"
say "  - Edit the policy printed above (everything is off by default), then:  rcu policy-check"
say "  - On the PC you want to control:  rcu serve      (needs Tailscale; keep the terminal open to approve)"
say "  - On this PC:                     rcu pair <name> <ip:port> <code>"
