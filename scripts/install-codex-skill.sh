#!/bin/sh
# Codex 용: 같은 SKILL.md 를 ~/.codex/skills/remote-computer-use/ 에 복사한다.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
dest="${CODEX_HOME:-$HOME/.codex}/skills/remote-computer-use"
mkdir -p "$dest"
cp "$here/plugin/skills/remote-computer-use/SKILL.md" "$dest/SKILL.md"
echo "installed: $dest/SKILL.md"
