# remote-computer-use

Let an AI session (Claude Code, Codex, or a cloud session) run commands and read/write files on **another of your PCs** (Mac / Windows / Linux) — with the other PC deciding what is allowed.

- **One small binary, `rcu`.** `rcu serve` makes a PC a *node*; the other `rcu` commands are the *controller*. Every PC can be both.
- **No MCP.** The agent calls `rcu` through its shell tool; a skill (`SKILL.md`) teaches it the commands and the rules. Same skill for Claude Code and Codex.
- **Tailscale only.** The node refuses to listen on anything but loopback or your tailnet, and the controller refuses to send credentials anywhere else.
- **The node is in charge.** Default deny. A policy file lists the exact programs, folders and sizes allowed. The first request of each kind — and every overwrite or destructive command — waits for a human `y`/`n` in the node's terminal.

Status: **v0.3** — commands, files, approvals, and (off by default) screen capture and input. See [DESIGN.md](DESIGN.md) (Korean) and [SECURITY.md](SECURITY.md).

[한국어 README](README.ko.md)

## Install

Needs [Tailscale](https://tailscale.com) on both PCs.

```sh
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/Jay-Hyun/remote-computer-use/main/install.sh | sh
```
```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/Jay-Hyun/remote-computer-use/main/install.ps1 | iex
```

The script downloads the release binary, **verifies its SHA-256**, puts `rcu` on your PATH, creates a policy with everything switched off, and installs the Claude Code plugin / Codex skill if those tools are present. Read it first if you like: [install.sh](install.sh), [install.ps1](install.ps1). Or build it yourself: `cargo install --path .`.

## Use

**On the PC to be controlled (the node)**

```sh
rcu init            # writes a policy with everything off; edit it (see examples/policy.toml)
rcu policy-check
rcu serve           # prints a pairing code; approve requests in this terminal or in the dialog that pops up
```

To have the node start at login (no sudo; approvals then come as dialogs):

```sh
rcu service install     # launchd (macOS), systemd --user (Linux), scheduled task (Windows)
rcu pair-code           # prints a fresh pairing code from the running node
rcu service uninstall
```

**On the PC the agent runs on (the controller)**

```sh
rcu pair work-mac 100.101.102.103:7443 ABCD-1234   # node names: lowercase letters, digits, hyphens
rcu info work-mac
rcu exec work-mac -- /usr/bin/git status
rcu read work-mac /Users/me/work/notes.md
rcu screen work-mac --out /tmp/shot.png      # needs `screen = true` in the node's policy
rcu click work-mac 640 360                    # needs `input = true`; the node approves each action
echo "hello" | rcu write work-mac /Users/me/work/new.txt
```

Then just ask your agent: *"check git status on work-mac"*. The skill makes it use `rcu`, and you approve on the node.

Output is always one JSON object. Exit codes: `0` ok · `2` denied by the node's policy · `3` waiting for your approval (`rcu wait`) · `4` auth · `5` can't reach the node. Details: [proto/errors.md](proto/errors.md).

## Policy in 20 seconds

```toml
[capabilities]
exec = true
fs_read = true

[fs]
roots = ["~/work"]
deny  = ["**/.env", "**/.ssh/**"]

[[exec.allow]]
program = "/usr/bin/git"      # absolute path; shells and wrappers (sh, cmd, env, sudo…) are refused
args    = ["status", "*"]
risk    = "read"              # read | write | destructive | external
```

Anything not listed is denied. Risk is decided by *your* policy, never by what the controller claims.

## Cloud sessions as controller

A cloud container can control your PCs if it joins your tailnet (`tailscaled --tun=userspace-networking`) and gets its token from an environment secret (`RCU_TOKEN_<NODE>`). Get the token yourself with `rcu pair … --print-token`. Point `RCU_PROXY=socks5://localhost:1055` at tailscaled's SOCKS5 server (loopback proxies only) and use the node's tailnet IP. See [DESIGN.md §17.8](DESIGN.md).

## Limits you should know

- Without `rcu service install`, `rcu serve` must stay open in a terminal. As a service, approvals use an OS dialog (macOS/Windows; Linux needs a display and `zenity`).
- Traffic is plain HTTP inside Tailscale's WireGuard tunnel. Restrict the port with Tailscale ACLs if your tailnet has other people.
- An allow-listed program that can run other programs (`python`, `node`, `find -exec`…) is as powerful as a shell, and exec arguments are not checked against `fs.roots`. Keep patterns narrow; `rcu policy-check` warns about risky entries.
- Windows: builds and runs, but path hardening against races is not done yet; treat Windows nodes as experimental.
- Screen and input are best-effort on macOS/Windows (they use `screencapture`/`osascript`/PowerShell and need the usual OS permissions) and unsupported on Linux. A controller with `input` can press any button on the node's screen, including approval windows, so only enable it on nodes whose users read each prompt.
- Release binaries are not code-signed.

## Develop

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

See [CONTRIBUTING.md](CONTRIBUTING.md). License: GPL-3.0-or-later ([LICENSE](LICENSE)).
