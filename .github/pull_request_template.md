## What and why

## Checks

- [ ] `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
- [ ] Anything that widens what a node allows (policy, paths, exec, approval) has a test that fails without it
- [ ] DESIGN.md / SKILL.md / proto/errors.md updated if behavior or error codes changed
