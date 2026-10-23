# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versions follow SemVer (0.x: breaking changes possible).

## [0.3.0]

### Added
- `rcu doctor`: one-shot health check of the node and controller sides with a suggested fix for each problem.
- `rcu tokens` and `rcu revoke <id>` (one controller instead of all), `[auth] token_days` for expiring tokens, `rcu unpair <node>`, `rcu completions <shell>`.
- `rcu info` warns when a node answers under a different name than it had when paired.
- Slowloris protection: the server closes connections that do not finish their request headers within 10 s and caps open connections at 256.
- Windows hardening: opened-file path check (`GetFinalPathNameByHandle`), hardlink check, refusal of alternate data streams, device names (`CON`, `NUL`, `COM1`…), trailing dots/spaces and 8.3 short names; Windows-only tests run on the Windows CI job.
- Release workflow smoke-tests each binary on its own platform before publishing; weekly `cargo audit`.
- CI runs on every branch push, with a real node/controller smoke test (`scripts/smoke.sh`, `scripts/smoke.ps1`) on Linux, macOS and Windows runners.

### Added (screen and input)
- Screen capture and input (off by default): `rcu screen --out`, `rcu click`, `rcu type`, `rcu key`; policy `capabilities.screen/input`, `[screen] max_width, grant`, `[input] max_text`, `limits.input_per_minute`. Capture is approved every time unless `screen.grant = true`; input is always approved one action at a time. macOS (`screencapture`, `osascript`, optional `cliclick`) and Windows (PowerShell) backends; Linux reports `UNSUPPORTED`. Typed text and images are never logged or written to the node's disk.

### Security (from an independent code review)
- An approval is bound to the risk that was shown: if the target changed while waiting (e.g. a file appeared so "create" became "overwrite"), the request is refused with `STATE_CHANGED`.
- Approval text is never truncated: arguments are quoted individually, invisible/bidi characters are shown as `\u{..}`, symlinks show their real target, and requests too long to show are refused (`TOO_LARGE`). zenity backslash unescaping can no longer fake lines.
- Overwrites: the file is opened and verified before anything is changed; the backup is made from the verified file with `create_new`/`O_NOFOLLOW`, never replaces an older backup (`.rcu-bak`, `.rcu-bak.1`, …) and never follows links; hardlinked files are refused; FIFOs/special files no longer hang a worker.
- Built-in deny list (shell startup files, `.ssh`, `.aws`, autostart/LaunchAgents, …) that no policy can lift; deny globs are case-insensitive and also match through symlinked prefixes; relative or unexpandable deny patterns are rejected; the node's own config/state directory is unreachable through file access.
- More shells/wrappers cannot be allow-listed (busybox, timeout, nsenter, …); `rcu policy-check` and `rcu serve` warn about interpreter-like allow entries, programs inside `fs.roots`, and the fact that exec arguments bypass `fs` rules.
- Commands run in their own process group and the whole group is killed on timeout; at most 8 run at once (`BUSY`); partial output is kept.
- File size limits are clamped to 64 MiB.
- Installers: https enforced (`RCU_ALLOW_INSECURE=1` for local testing), `SKILL.md` ships as a checksummed release asset, extraction limited to the binary, script wrapped in `main()`; Windows installer extracts only `rcu.exe` and keeps `%VAR%` PATH entries.
- Release workflow: only a pushed tag publishes (not a manual run), `release` environment, build provenance attestation, versions of tag / Cargo.toml / plugin.json must agree.
- systemd unit escapes `%`/`$`, refuses newlines in paths, sets `NoNewPrivileges=yes`.
- `RCU_PROXY` is parsed strictly (no `user@host`, paths, ports out of range, unbracketed IPv6): `socks5://localhost:80@evil.example` used to send the token to `evil.example`. HTTP redirects are no longer followed.
- Every executed request writes a `START` audit record first and is refused (`AUDIT_FAILED`) if that fails; the run continues and is logged even if the client disconnects.
- Terminal approvals are bound to a request id (`y 763eb30c`); a bare `y` works only when exactly one request waits and it has been on screen for 1.5 s. Max 5 pending requests per token and 20 per node (`BUSY`).
- Revoking tokens (`rcu revoke --all`) drops their grants, denies their waiting requests, and stops requests that were already approved; token store updates are file-locked; token ids are 64-bit.
- Grants are scoped by risk (a grant for a `read` command does not cover `write` commands).
- Authentication happens before the request body is read; failed-auth floods are throttled per source (30/min) and logged at most once a second; pairing failures are counted per source so a peer cannot lock the owner out; request/connection timeouts and a concurrency cap.
- Windows approval dialog is a form with labelled buttons (no more "No = grant" surprise).
- Secret files are created 0600 / directories 0700 from the start (`config::write_private`, `create_private_dir`), audit log included; the node's `--bind` must be this PC's Tailscale address when it can be determined.
- Node names are limited to lowercase letters, digits and hyphens so token environment variable names cannot collide.

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
