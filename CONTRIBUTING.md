# Contributing

Thanks for helping. This project is security-sensitive, so a few rules:

1. **Default deny.** Changes that make a node allow more (paths, programs, approval shortcuts, bind addresses) need a test that fails without the change and a note in DESIGN.md.
2. **Tests first for policy.** Policy code lives in `src/policy.rs`, `src/fsops.rs`, `src/exec.rs`; tests in `tests/`.
3. **Never log or print secrets** (tokens, pairing codes after use, file contents). `src/audit.rs` redacts; keep it that way.
4. **Docs move with behavior:** `DESIGN.md` (§17 is the source of truth), `plugin/skills/remote-computer-use/SKILL.md`, `proto/errors.md`, `examples/policy.toml`.

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Windows tests are being ported (see the `#![cfg(unix)]` headers); contributions welcome. By contributing you agree your work is licensed under GPL-3.0-or-later.
