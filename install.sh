#!/bin/sh
# rcu installer (macOS / Linux).
#   curl -fsSL https://raw.githubusercontent.com/Jay-Hyun/remote-computer-use/main/install.sh | sh
#
# Env: RCU_VERSION (default: latest), RCU_INSTALL_DIR (default: ~/.local/bin),
#      RCU_SKIP_SKILLS=1 (binary only),
#      RCU_BASE_URL (mirror/testing; must be https:// unless RCU_ALLOW_INSECURE=1).
#
# Everything is wrapped in main() so a truncated download cannot run half a script.
set -eu

REPO="Jay-Hyun/remote-computer-use"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

main() {
  VERSION="${RCU_VERSION:-latest}"
  DEST="${RCU_INSTALL_DIR:-$HOME/.local/bin}"
  INSECURE="${RCU_ALLOW_INSECURE:-0}"

  if [ -n "${RCU_BASE_URL:-}" ]; then
    BASE="$RCU_BASE_URL"
    case "$BASE" in
      https://*) ;;
      *)
        [ "$INSECURE" = "1" ] || die "RCU_BASE_URL must start with https:// (set RCU_ALLOW_INSECURE=1 only for local testing)"
        say "WARNING: using a non-https base URL; checksums fetched from it prove nothing." >&2
        ;;
    esac
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

  fetch() {
    if [ "$INSECURE" = "1" ]; then
      curl -fsSL "$1" -o "$2"
    else
      curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"
    fi
  }

  sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
      shasum -a 256 "$1" | cut -d' ' -f1
    else
      die "need sha256sum or shasum to verify downloads"
    fi
  }

  # Download $1 into $tmp and verify it against SHA256SUMS. Fails closed.
  fetch_verified() {
    name="$1"
    fetch "$BASE/$name" "$tmp/$name" || die "download failed: $BASE/$name"
    expected="$(grep "  $name\$" "$tmp/SHA256SUMS" | cut -d' ' -f1 || true)"
    [ -n "$expected" ] || die "no checksum for $name in SHA256SUMS"
    [ "$(printf '%s\n' "$expected" | wc -l | tr -d ' ')" = "1" ] || die "duplicate checksum entries for $name"
    actual="$(sha256_of "$tmp/$name")"
    [ "$expected" = "$actual" ] || die "checksum mismatch for $name (expected $expected, got $actual)"
  }

  say "Downloading rcu ($VERSION)..."
  fetch "$BASE/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $BASE/SHA256SUMS"
  asset="rcu-$target.tar.gz"
  fetch_verified "$asset"

  # Extract only the binary and refuse anything that is not a plain file.
  tar -xzf "$tmp/$asset" -C "$tmp" rcu
  if [ ! -f "$tmp/rcu" ] || [ -L "$tmp/rcu" ]; then
    die "archive did not contain a regular file named rcu"
  fi
  mkdir -p "$DEST"
  install -m 755 "$tmp/rcu" "$DEST/rcu"
  say "Installed $DEST/rcu"

  case ":$PATH:" in
    *":$DEST:"*) ;;
    *) say "Note: $DEST is not on your PATH. Add:  export PATH=\"$DEST:\$PATH\"" ;;
  esac

  "$DEST/rcu" init || say "Note: could not create the default policy; run 'rcu init' yourself."

  if [ "${RCU_SKIP_SKILLS:-0}" != "1" ]; then
    # Claude Code plugin. NOTE: this tracks the repository's default branch, not this release.
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
    # Codex skill: the same SKILL.md, shipped with the release and verified like the binary.
    codex_home="${CODEX_HOME:-$HOME/.codex}"
    if command -v codex >/dev/null 2>&1 || [ -d "$codex_home" ]; then
      if grep -q "  SKILL.md\$" "$tmp/SHA256SUMS"; then
        fetch_verified "SKILL.md"
        skill_dir="$codex_home/skills/remote-computer-use"
        mkdir -p "$skill_dir"
        cp "$tmp/SKILL.md" "$skill_dir/SKILL.md.part" && mv "$skill_dir/SKILL.md.part" "$skill_dir/SKILL.md"
        say "Installed the Codex skill."
      else
        say "Note: this release has no SKILL.md asset; skipping the Codex skill."
      fi
    fi
  fi

  say ""
  say "Next:"
  say "  - Edit the policy printed above (everything is off by default), then:  rcu policy-check"
  say "  - On the PC you want to control:  rcu serve      (needs Tailscale; approve in the terminal or the dialog)"
  say "    or start it at every login:     rcu service install"
  say "  - On this PC:                     rcu pair <name> <ip:port> <code>"
  say "  - After upgrading a PC that runs the service: rcu service install   (restarts it with the new binary)"
}

main "$@"
