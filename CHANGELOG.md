# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versions follow SemVer (0.x: breaking changes possible).

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
