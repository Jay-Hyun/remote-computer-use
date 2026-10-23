# 오류 코드

본문은 `{"code": "...", "message": "..."}`. 메시지에 비밀값과 경로 전체를 넣지 않는다.
CLI는 같은 객체를 `{"error": {...}}`로 감싸 stdout에 내보낸다.

| code | HTTP | CLI exit | 뜻 |
|---|---|---|---|
| UNAUTHORIZED | 401 | 4 | 토큰이 없거나 발급된 것이 아님 |
| PAIR_WRONG | 403 | 4 | 페어링 코드 틀림 |
| PAIR_LOCKED | 429 | 4 | 5번 틀려 잠김, 또는 코드가 이미 쓰임. 노드에서 새 코드 필요 |
| PAIR_EXPIRED | 410 | 4 | 코드 5분 지남 |
| CAPABILITY_OFF | 403 | 2 | 노드에서 해당 능력이 꺼져 있음 (M2) |
| PATH_DENIED | 403 | 2 | 허용 루트 밖, `..`, 거부 패턴 (M2) |
| COMMAND_DENIED | 403 | 2 | 허용 목록에 없음 (M2) |
| SHELL_DENIED | 403 | 2 | 셸 실행 시도 (M2) |
| APPROVAL_PENDING | 202 | 3 | 노드 사용자 승인 대기, `approval_id` 포함 (M2) |
| APPROVAL_DENIED | 403 | 2 | 노드 사용자가 거부 (M2) |
| ADDRESS_DENIED | - | 2 | 컨트롤러가 비허용 주소로 접속을 거부(클라이언트 전용) |
| NETWORK_ERROR | - | 5 | 노드에 닿지 않음(클라이언트 전용) |
| UNKNOWN_NODE | - | 1 | `nodes.toml`에 없는 노드 이름 |
| INTERNAL | 500 | 1 | 그 밖 |
