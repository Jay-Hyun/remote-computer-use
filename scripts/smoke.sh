#!/bin/bash
# End-to-end smoke test of a built `rcu` binary on this machine (macOS / Linux).
# Starts a node on 127.0.0.1, pairs a controller, and runs exec / read / write / revoke
# with approvals answered through the node's stdin. Exits non-zero on any failure.
#
#   scripts/smoke.sh [path/to/rcu]
set -euo pipefail

RCU="$(cd "$(dirname "${1:-target/debug/rcu}")" && pwd)/$(basename "${1:-target/debug/rcu}")"
[ -x "$RCU" ] || { echo "no such binary: $RCU" >&2; exit 2; }

tmp="$(mktemp -d)"
NODE_HOME="$tmp/node"
CTL_HOME="$tmp/ctl"
WORK="$tmp/work"
mkdir -p "$NODE_HOME" "$CTL_HOME" "$WORK"
echo "hello from the node" > "$WORK/a.txt"

pid=""
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  exec 3>&- 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'SMOKE FAILED: %s\n' "$*" >&2; echo "--- node log"; cat "$tmp/node.log" 2>/dev/null || true; exit 1; }

node() { RCU_HOME="$NODE_HOME" "$RCU" "$@"; }
ctl() { RCU_HOME="$CTL_HOME" RCU_TOKEN_SMOKE="${TOKEN:-}" "$RCU" "$@"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }

port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
ADDR="127.0.0.1:$port"
ECHO="$(command -v echo)"
[ -x /bin/echo ] && ECHO=/bin/echo

step "rcu init"
node init | json 'd["created"]' | grep -q True || fail "init did not create a policy"
node init | json 'd["created"]' | grep -q False || fail "second init must not overwrite"

step "write policy"
cat > "$NODE_HOME/policy.toml" <<POLICY
[node]
name = "smoke-node"
[capabilities]
exec = true
fs_read = true
fs_write = true
[fs]
roots = ["$WORK"]
[approval]
ui = "terminal"
[[exec.allow]]
program = "$ECHO"
args = ["**"]
risk = "read"
POLICY
node policy-check | json 'd["ok"]' | grep -q True || fail "policy-check"

step "start node on $ADDR"
mkfifo "$tmp/in"
exec 3<>"$tmp/in"
RCU_HOME="$NODE_HOME" "$RCU" serve --bind "$ADDR" < "$tmp/in" > "$tmp/node.log" 2>&1 &
pid=$!
for _ in $(seq 1 100); do grep -q "pairing code" "$tmp/node.log" 2>/dev/null && break; sleep 0.1; done
CODE="$(grep -o 'pairing code (5 min): [A-Z0-9]*' "$tmp/node.log" | head -1 | awk '{print $NF}')"
[ -n "$CODE" ] || fail "node never printed a pairing code"
for _ in $(seq 1 50); do (exec 4<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break; sleep 0.1; done

step "pair"
OUT="$(RCU_HOME="$CTL_HOME" "$RCU" pair smoke "$ADDR" "$CODE" --print-token)"
TOKEN="$(echo "$OUT" | json 'd["token"]')"
[ -n "$TOKEN" ] || fail "no token"
export TOKEN

step "info"
ctl info smoke | json '",".join(d["capabilities"])' | grep -q "exec,fs.read,fs.write" || fail "capabilities"

# Run a controller command that needs approval, answer it on the node, print its output.
approved() {
  local answer="$1"; shift
  local before; before="$(grep -c '^\[approval [0-9a-f]*\] [a-z.]* (' "$tmp/node.log" || true)"
  rm -f "$tmp/rc"
  # 백그라운드에서는 표준 입력이 /dev/null 이 되므로 필요한 경우 파일로 넘긴다.
  ( set +e; ctl "$@" < "${STDIN_FILE:-/dev/null}" > "$tmp/out.json" 2> "$tmp/err.txt"; echo $? > "$tmp/rc" ) &
  local job=$!
  local id=""
  for _ in $(seq 1 100); do
    # 이번 요청의 질문 줄 = 시작 전 질문 수 + 1 번째 줄
    id="$(grep -o '^\[approval [0-9a-f]*\] [a-z.]* (' "$tmp/node.log" | sed -n "$((before + 1))p" | awk '{print $2}' | tr -d ']' || true)"
    [ -n "$id" ] && break
    sleep 0.1
  done
  [ -n "$id" ] || fail "node never asked about: $*"
  echo "$answer $id" >&3
  wait "$job" || true
}

step "exec through approval"
approved y exec smoke -- "$ECHO" hi there
[ "$(cat "$tmp/rc")" = 0 ] || fail "exec exit code $(cat "$tmp/rc"): $(cat "$tmp/out.json")"
json 'd["stdout"]' < "$tmp/out.json" | grep -q "hi there" || fail "exec output: $(cat "$tmp/out.json")"

step "denied approval"
approved n exec smoke -- "$ECHO" nope
[ "$(cat "$tmp/rc")" = 2 ] || fail "denied exec must exit 2, got $(cat "$tmp/rc")"

step "write then read"
echo "written by smoke" > "$tmp/payload"
STDIN_FILE="$tmp/payload" approved y write smoke "$WORK/new.txt"
[ "$(cat "$tmp/rc")" = 0 ] || fail "write: $(cat "$tmp/out.json")"
[ "$(cat "$WORK/new.txt")" = "written by smoke" ] || fail "file content on node"
approved y read smoke "$WORK/new.txt"
json 'd["text"].strip()' < "$tmp/out.json" | grep -q "written by smoke" || fail "read back: $(cat "$tmp/out.json")"

step "policy denials never ask"
set +e
ctl exec smoke -- /bin/sh -c id > "$tmp/o" 2>&1; rc=$?
set -e
[ "$rc" = 2 ] || fail "shell must be denied with exit 2, got $rc"
set +e
ctl read smoke "$tmp/ctl/../node/policy.toml" > "$tmp/o" 2>&1; rc=$?
set -e
[ "$rc" = 2 ] || fail "path outside roots must exit 2, got $rc"

step "revoke"
node revoke --all | json 'd["revoked"]' | grep -q 1 || fail "revoke count"
set +e
ctl info smoke > "$tmp/o" 2>&1; rc=$?
set -e
[ "$rc" = 4 ] || fail "revoked token must exit 4, got $rc"

step "service files (no start)"
HOME_BACKUP="${HOME:-}"
export HOME="$tmp/home"; mkdir -p "$HOME"
XDG_BACKUP="${XDG_CONFIG_HOME:-}"
export XDG_CONFIG_HOME="$HOME/.config"
RCU_HOME="$NODE_HOME" "$RCU" service install --no-start | json 'd["unit"]' | grep -q "$HOME" || fail "service unit must be under the user's home"
RCU_HOME="$NODE_HOME" "$RCU" service uninstall > /dev/null
export HOME="$HOME_BACKUP"
if [ -n "$XDG_BACKUP" ]; then export XDG_CONFIG_HOME="$XDG_BACKUP"; else unset XDG_CONFIG_HOME; fi

printf '\nSMOKE OK (%s)\n' "$("$RCU" --version)"
