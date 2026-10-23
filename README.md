# remote-computer-use

Mac/Windows PC 사이에서 AI 세션(Claude Code, Codex, 클라우드 세션)이 다른 PC의 명령·파일을 다루게 하는 도구. 설계는 [DESIGN.md](DESIGN.md).

- `rcu`: Rust 단일 실행 파일. `rcu serve`로 노드, 나머지 명령으로 컨트롤러.
- 테일스케일 위에서만 동작. 노드가 정책(`policy.toml`)과 승인으로 모든 것을 결정한다.
- MCP 없음. 스킬이 에이전트에게 `rcu` 사용법과 규칙을 가르친다.

## 설치 (M1)

```sh
cargo install --path .                      # rcu
# Claude Code
/plugin marketplace add jay-hyun/remote-computer-use
/plugin install remote-computer-use@remote-computer-use
# Codex
scripts/install-codex-skill.sh
```

## 쓰기

노드 PC: `examples/policy.toml`을 `rcu policy-check`가 알려 주는 위치에 두고 `rcu serve --bind <테일스케일 IP>:7443`. 화면의 코드를 컨트롤러에서 `rcu pair <이름> <IP>:7443 <코드>`.

## 개발

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```
