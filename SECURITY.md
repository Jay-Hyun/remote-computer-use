# Security

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting:
<https://github.com/Jay-Hyun/remote-computer-use/security/advisories/new>

Include the version (`rcu --version`), OS, and steps to reproduce. Do not include real tokens or private files. You will get a first reply within a few days; fixes ship as a new release with a changelog note.

## What this tool is for

A node lets another machine you own run a **narrow, allow-listed** set of commands and read/write files inside **folders you name**. It is built so that a stolen token, a compromised tailnet account, or a prompt-injected agent is stopped by the node, not trusted by it.

## Model (summary — full text in DESIGN.md §5, §8, §17)

| Threat | Defence |
|---|---|
| Prompt injection in files or command output | The skill tells agents to treat node data as data; every action still goes through policy and node-side approval |
| Stolen controller token | Per-node tokens stored hashed on the node, in the OS secure store on the controller; `rcu revoke --all` on the node; first request of each kind and every destructive action still needs a human at the node |
| Tailnet account compromise | Pairing code (8 chars, 5 min, 5 tries) required per controller; approval at the node; rate limits |
| Command injection | No shell ever; argument arrays; absolute-path allow list with arg patterns; shells and wrappers can't be allow-listed |
| Path tricks | Absolute paths only, `..` rejected, symlinks resolved then checked against roots and deny globs, `O_NOFOLLOW` and opened-path verification (Linux/macOS) |
| Runaway use | Per-token per-minute and per-node daily caps; command timeout and output caps |
| Secrets in logs | Tokens are redacted; audit log never stores file contents or command output |
| Terminal spoofing via request text | Approval prompts strip control characters and truncate |

## Known limits (not vulnerabilities)

- **Exec arguments are not checked against `fs.roots`/`deny`.** An allow-listed program can read or write anywhere its user can. Allow-list exact commands with narrow argument patterns; `rcu policy-check` warns about risky entries.
- Installing the Claude Code plugin tracks the repository's default branch, not a release tag. The Codex skill and the binary are pinned to the release and checksummed.
- Release assets carry a build-provenance attestation (`gh attestation verify <file> --repo Jay-Hyun/remote-computer-use`); the installer's SHA-256 check alone protects against corruption, not a compromised release.
- A built-in deny list (shell startup files, `.ssh`, `.aws`, autostart locations) always applies, whatever the policy says.

- Transport is HTTP over Tailscale's WireGuard tunnel. Use Tailscale ACLs to limit who can reach the node's port.
- You decide what to allow-list. Allowing an interpreter or a program with an "execute" feature is equivalent to allowing a shell.
- Approvals happen in the node's terminal; anyone with that terminal can approve.
- Windows nodes lack the opened-path race check (planned).
- Release binaries are unsigned; the installer verifies SHA-256 from the same release, which protects against corruption, not against a compromised release.
