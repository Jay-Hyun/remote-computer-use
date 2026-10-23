# 오류 코드

본문은 `{"code": "...", "message": "..."}`. 메시지에 비밀값과 경로 전체를 넣지 않는다.
CLI는 같은 객체를 `{"error": {...}}`로 감싸 stdout에 내보낸다.

| code | HTTP | CLI exit | 뜻 |
|---|---|---|---|
| UNAUTHORIZED | 401 | 4 | 토큰이 없거나 발급된 것이 아님 |
| PAIR_WRONG | 403 | 4 | 페어링 코드 틀림 |
| PAIR_LOCKED | 429 | 4 | 5번 틀려 잠김, 또는 코드가 이미 쓰임. 노드에서 새 코드 필요 |
| PAIR_EXPIRED | 410 | 4 | 코드 5분 지남 |
| CAPABILITY_OFF | 403 | 2 | 노드에서 해당 능력이 꺼져 있음 |
| PATH_DENIED | 403 | 2 | 허용 루트 밖, `..`, 거부 패턴 |
| COMMAND_DENIED | 403 | 2 | 허용 목록에 없음 |
| SHELL_DENIED | 403 | 2 | 셸 실행 시도 |
| APPROVAL_PENDING | 202 | 3 | 노드 사용자 승인 대기, `approval_id` 포함. 요청은 대기열에 있고 승인되면 한 번 실행된다. `rcu wait` 로 이어서 기다린다 |
| APPROVAL_DENIED | 403 | 2 | 노드 사용자가 거부 |
| APPROVAL_TIMEOUT | 403 | 2 | 5분 안에 아무도 승인하지 않음 |
| ADDRESS_DENIED | - | 2 | 컨트롤러가 비허용 주소로 접속을 거부(클라이언트 전용) |
| NETWORK_ERROR | - | 5 | 노드에 닿지 않음(클라이언트 전용) |
| UNKNOWN_NODE | - | 1 | `nodes.toml`에 없는 노드 이름 |
| UNKNOWN_APPROVAL | 404 | 1 | 없는 approval id, 또는 다른 토큰이 연 요청 |
| EXISTS | 409 | 1 | 파일이 이미 있음(`--overwrite` 필요) |
| TOO_LARGE | 413 | 1 | 노드의 읽기·쓰기 크기 상한 초과 |
| NOT_A_FILE | 400 | 1 | 일반 파일이 아님 |
| EXEC_FAILED | 422 | 1 | 프로그램을 시작하지 못함 |
| RATE_LIMITED | 429 | 1 | 분당 또는 일일 호출 상한 |
| BAD_REQUEST | 400 | 1 | 본문 형식 오류 |
| IO_ERROR | 500 | 1 | 파일 작업 실패 |
| STATE_CHANGED | 409 | 1 | 승인을 기다리는 사이 대상이 바뀌어 위험도가 올라감. 다시 요청 |
| AUDIT_FAILED | 500 | 1 | 노드가 감사 로그를 쓰지 못해 실행을 거부 |
| BUSY | 429 | 1 | 승인 대기가 너무 많거나 동시 실행이 가득 참 |
| UNSUPPORTED | 501 | 1 | 이 OS 노드는 화면·입력을 지원하지 않음(또는 맥 우클릭에 `cliclick` 필요) |
| SCREEN_FAILED | 500 | 1 | 화면 캡처 도구 실패(권한? 로그인 세션 없음?) |
| INPUT_FAILED | 500 | 1 | 입력 도구 실패(권한? 로그인 세션 없음?) |
| BAD_NODE_NAME | - | 1 | 노드 이름은 소문자·숫자·하이픈 |
| PROXY_DENIED | - | 2 | `RCU_PROXY` 가 이 PC 의 SOCKS5 가 아님(클라이언트 전용) |
| INTERNAL | 500 | 1 | 그 밖 |
