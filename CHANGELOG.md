# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versions follow SemVer (0.x: breaking changes possible).

## [Unreleased]

### Added
- `rcu service install|uninstall`: start the node at login (launchd / systemd --user / Windows scheduled task), no sudo.
- OS approval dialogs (macOS `osascript`, Windows MessageBox, Linux `zenity`); `approval.ui = auto | terminal | dialog`. Terminal and dialog work together, first answer wins.
- `rcu pair-code`: fresh pairing code from a running (service) node.
- `RCU_PROXY=socks5://localhost:PORT` for controllers behind tailscaled's userspace SOCKS5 (loopback proxies only).

## [0.2.0]

### Added
- `rcu exec`, `rcu read`, `rcu write`, `rcu wait` and the matching node endpoints.
- Node-side approval in the terminal (`y` once / `a` for a period / `n`), per-token grants, always-ask for destructive actions, 5-minute timeout.
- Rate limits (per token per minute, per node per day), command timeout and output caps, file size caps, overwrite backups (`.rcu-bak`).
- `rcu init` (safe default policy), `rcu serve` auto-detects the Tailscale address.
- Installers (`install.sh`, `install.ps1`) with SHA-256 verification; release and CI workflows; Claude Code marketplace and Codex skill.

### Security
- File access verifies the opened file's real path (Linux/macOS) and refuses symlinks at the final component.
- Child processes get a minimal environment.

## [0.1.0]
- Node skeleton: `/v1/info`, `/v1/pair`, policy parser, token hashing, audit log, tailnet-only bind, `rcu pair|info|nodes|revoke|policy-check`.
