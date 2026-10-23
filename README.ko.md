# remote-computer-use

AI 세션(Claude Code, Codex, 클라우드 세션)이 **내 다른 PC**(맥·윈도우·리눅스)에서 명령을 실행하고 파일을 읽고 쓰게 합니다. 무엇을 허용할지는 **그 PC가** 정합니다.

- 작은 실행 파일 하나, `rcu`. `rcu serve`로 노드가 되고, 나머지 명령은 컨트롤러입니다. 모든 PC가 둘 다 될 수 있습니다.
- MCP 없음. 에이전트가 셸로 `rcu`를 부르고, 스킬(`SKILL.md`)이 사용법과 규칙을 가르칩니다. Claude Code와 Codex가 같은 스킬을 씁니다.
- 테일스케일 안에서만. 노드는 루프백·테일넷 주소에서만 듣고, 컨트롤러는 그 밖으로 토큰을 보내지 않습니다.
- 기본은 거부. 정책 파일에 적은 프로그램·폴더·크기만 허용하고, 종류별 첫 요청과 모든 덮어쓰기·파괴적 명령은 노드 터미널에서 사람이 `y`/`n`으로 승인합니다.

상태: **v0.2** (명령·파일·승인). 화면·입력은 예정. 설계는 [DESIGN.md](DESIGN.md), 보안은 [SECURITY.md](SECURITY.md).

## 설치

양쪽 PC에 [Tailscale](https://tailscale.com)이 필요합니다.

```sh
# 맥 / 리눅스
curl -fsSL https://raw.githubusercontent.com/Jay-Hyun/remote-computer-use/main/install.sh | sh
```
```powershell
# 윈도우 (PowerShell)
irm https://raw.githubusercontent.com/Jay-Hyun/remote-computer-use/main/install.ps1 | iex
```

릴리스 바이너리를 받아 SHA-256을 검증하고, PATH에 `rcu`를 두고, 모든 능력이 꺼진 정책을 만들고, Claude Code 플러그인·Codex 스킬이 있으면 함께 설치합니다.

## 사용

노드(조작당하는 PC):
```sh
rcu init          # 모든 능력이 꺼진 정책 생성. examples/policy.toml 참고해 필요한 것만 켠다
rcu policy-check
rcu serve         # 페어링 코드가 나온다. 이 터미널이나 뜨는 대화상자에서 요청을 승인한다
```

로그인할 때 자동으로 띄우려면(sudo 불필요):
```sh
rcu service install   # 맥 launchd / 리눅스 systemd --user / 윈도우 예약 작업
rcu pair-code         # 실행 중인 노드에서 새 페어링 코드를 받는다
rcu service uninstall
```

컨트롤러(에이전트가 도는 PC):
```sh
rcu pair work-mac 100.101.102.103:7443 ABCD-1234
rcu exec work-mac -- /usr/bin/git status
rcu read work-mac /Users/me/work/notes.md
echo "hello" | rcu write work-mac /Users/me/work/new.txt
```

이후에는 에이전트에게 "work-mac에서 git status 확인해줘"라고 하면 됩니다. 승인은 노드에서 합니다.

## 알아둘 한계
- `rcu service install`을 쓰지 않으면 `rcu serve`를 터미널에 띄워 둬야 합니다. 서비스로 돌 때는 승인이 OS 대화상자로 뜹니다(맥·윈도우, 리눅스는 디스플레이와 `zenity` 필요).
- 테일스케일 안에서는 평문 HTTP입니다(WireGuard가 암호화). 다른 사람이 있는 tailnet이면 ACL로 포트를 제한하세요.
- `python`·`node`처럼 다른 프로그램을 실행할 수 있는 프로그램을 허용하면 셸과 같습니다. 인자 패턴을 좁게 쓰세요.
- 윈도우는 실험적입니다. 릴리스 바이너리는 서명되어 있지 않습니다.
