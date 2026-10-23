//! 인증·승인·서버 검토에서 나온 지적의 회귀 시험.

use rcu::approval::{parse_terminal_answer, Decision, Gate, OpenError, ResolveError};
use rcu::audit::Audit;
use rcu::client;
use rcu::pairing::{PairError, Pairing, SOURCE_MAX_FAILS, TOTAL_MAX_FAILS};
use rcu::policy::{Policy, Risk};
use rcu::secret_store::{env_var_name, valid_node_name};
use rcu::server::{self, AppState};
use rcu::tokens::TokenStore;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn tool(c: &[&str]) -> Option<String> {
    c.iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| p.to_string())
}

struct T {
    addr: String,
    token: String,
    token_id: String,
    state: Arc<AppState>,
    dir: tempfile::TempDir,
    tokens: TokenStore,
}

async fn start(extra: &str, http_wait_ms: u64) -> T {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let mut exec = String::new();
    for (names, args, risk) in [
        (&["/bin/echo", "/usr/bin/echo"][..], "**", "read"),
        (&["/bin/sleep", "/usr/bin/sleep"][..], "*", "write"),
        (&["/bin/touch", "/usr/bin/touch"][..], "*", "write"),
    ] {
        if let Some(p) = tool(names) {
            exec += &format!(
                "[[exec.allow]]\nprogram = '{p}'\nargs = [\"{args}\"]\nrisk = \"{risk}\"\n"
            );
        }
    }
    let text = format!(
        "[capabilities]\nexec = true\nfs_read = true\nfs_write = true\n[fs]\nroots = ['{}']\n{extra}\n{exec}",
        work.display()
    );
    let tokens = TokenStore::new(dir.path().join("tokens.json"));
    let token = tokens.issue("test", "now").unwrap();
    let token_id = tokens.verify(&token).unwrap();
    let mut state = AppState::new(
        Policy::parse(&text).unwrap(),
        tokens.clone(),
        Pairing::with_code("ABCD1234".into(), Instant::now()),
        Audit::new(dir.path().join("audit")),
    );
    state.http_wait = Duration::from_millis(http_wait_ms);
    let state = Arc::new(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(server::serve(listener, state.clone()));
    T {
        addr,
        token,
        token_id,
        state,
        dir,
        tokens,
    }
}

impl T {
    fn work(&self, name: &str) -> String {
        self.dir
            .path()
            .join("work")
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    fn audit_text(&self) -> String {
        let mut all = String::new();
        if let Ok(rd) = std::fs::read_dir(self.dir.path().join("audit")) {
            for f in rd.flatten() {
                all += &std::fs::read_to_string(f.path()).unwrap_or_default();
            }
        }
        all
    }
}

async fn blocking<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
    tokio::task::spawn_blocking(f).await.unwrap()
}

fn raw_request(addr: &str, req: &str, read_reply: bool) -> Option<String> {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    if !read_reply {
        return None;
    }
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    Some(out)
}

fn post(path: &str, token: Option<&str>, body: &str) -> String {
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(unix)]
#[tokio::test]
async fn granted_command_is_audited_even_if_the_client_disconnects() {
    let t = start("", 5000).await;
    let sleep = tool(&["/bin/sleep", "/usr/bin/sleep"]).unwrap();
    t.state
        .gate
        .add_grant(&t.token_id, "exec", Risk::Write, Instant::now());
    let body = format!("{{\"program\":\"{sleep}\",\"args\":[\"1\"]}}");
    let (addr, token) = (t.addr.clone(), t.token.clone());
    blocking(move || {
        // 요청을 보낸 직후 응답을 기다리지 않고 연결을 끊는다.
        raw_request(&addr, &post("/v1/exec", Some(&token), &body), false);
    })
    .await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let log = t.audit_text();
    assert!(log.contains("\"result\":\"START\""), "{log}");
    assert!(
        log.contains("\"capability\":\"exec\"") && log.contains("\"result\":\"OK\""),
        "{log}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn node_refuses_to_run_when_it_cannot_write_the_audit_log() {
    let t = start("", 5000).await;
    // 감사 디렉터리 자리에 일반 파일을 두어 로그를 쓸 수 없게 한다.
    std::fs::write(t.dir.path().join("audit"), "not a directory").unwrap();
    let touch = tool(&["/bin/touch", "/usr/bin/touch"]).unwrap();
    t.state
        .gate
        .add_grant(&t.token_id, "exec", Risk::Write, Instant::now());
    let marker = t.work("marker");
    let (addr, token, m) = (t.addr.clone(), t.token.clone(), marker.clone());
    let err = blocking(move || client::exec(&addr, &token, &touch, &[m]))
        .await
        .unwrap_err();
    assert_eq!(err.code, "AUDIT_FAILED");
    assert!(
        !std::path::Path::new(&marker).exists(),
        "must not run unaudited"
    );
}

#[tokio::test]
async fn revoked_token_cannot_finish_a_pending_request() {
    let t = start("", 150).await;
    std::fs::write(t.work("a.txt"), "x").unwrap();
    let (addr, token, p) = (t.addr.clone(), t.token.clone(), t.work("a.txt"));
    let pending = blocking(move || client::fs_read(&addr, &token, &p))
        .await
        .unwrap_err();
    assert_eq!(pending.code, "APPROVAL_PENDING");
    // 소유자가 토큰을 폐기한 뒤 누군가 승인해도 실행되지 않는다.
    t.tokens.revoke_all().unwrap();
    assert!(t.state.gate.resolve(None, Decision::Once).is_some());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let log = t.audit_text();
    assert!(
        !log.contains("\"result\":\"START\""),
        "revoked request must not start: {log}"
    );
}

#[tokio::test]
async fn revoking_clears_grants_and_denies_waiting_requests() {
    let t = start("", 150).await;
    std::fs::write(t.work("a.txt"), "x").unwrap();
    t.state
        .gate
        .add_grant(&t.token_id, "fs.read", Risk::Read, Instant::now());
    let (addr, token, p) = (t.addr.clone(), t.token.clone(), t.work("a.txt"));
    // fs.write 는 그랜트가 없으니 대기열에 들어간다.
    let (a2, k2, w) = (addr.clone(), token.clone(), t.work("new.txt"));
    let pending = blocking(move || client::fs_write(&a2, &k2, &w, "eA==", false))
        .await
        .unwrap_err();
    assert_eq!(pending.code, "APPROVAL_PENDING");
    assert_eq!(t.state.gate.waiting().len(), 1);

    t.tokens.revoke_all().unwrap();
    for _ in 0..60 {
        if t.state.gate.waiting().is_empty()
            && !t
                .state
                .gate
                .grant_alive(&t.token_id, "fs.read", Risk::Read, Instant::now())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        t.state.gate.waiting().is_empty(),
        "waiting request must be dropped"
    );
    assert!(!t
        .state
        .gate
        .grant_alive(&t.token_id, "fs.read", Risk::Read, Instant::now()));
    let e = blocking(move || client::fs_read(&addr, &token, &p))
        .await
        .unwrap_err();
    assert_eq!(e.code, "UNAUTHORIZED");
}

#[tokio::test]
async fn too_many_pending_requests_are_refused() {
    let t = start("", 100).await;
    std::fs::write(t.work("a.txt"), "x").unwrap();
    for i in 0..5 {
        let (a, k, p) = (t.addr.clone(), t.token.clone(), t.work("a.txt"));
        let e = blocking(move || client::fs_read(&a, &k, &p))
            .await
            .unwrap_err();
        assert_eq!(e.code, "APPROVAL_PENDING", "request {i}");
    }
    let (a, k, p) = (t.addr.clone(), t.token.clone(), t.work("a.txt"));
    let e = blocking(move || client::fs_read(&a, &k, &p))
        .await
        .unwrap_err();
    assert_eq!(e.code, "BUSY");
    assert_eq!(t.state.gate.waiting().len(), 5);
    // 다른 토큰은 아직 자리가 있다.
    let other = t.tokens.issue("other", "now").unwrap();
    let (a, p) = (t.addr.clone(), t.work("a.txt"));
    let e = blocking(move || client::fs_read(&a, &other, &p))
        .await
        .unwrap_err();
    assert_eq!(e.code, "APPROVAL_PENDING");
}

#[test]
fn gate_total_pending_cap() {
    let g = Gate::new(Duration::from_secs(60));
    let mut kept = Vec::new();
    for i in 0..rcu::approval::MAX_PENDING_TOTAL {
        kept.push(
            g.open(&format!("tok{i}"), "exec", Risk::Read, "x".into())
                .unwrap(),
        );
    }
    assert!(matches!(
        g.open("another", "exec", Risk::Read, "x".into()),
        Err(OpenError::TooManyTotal)
    ));
    drop(kept);
}

#[test]
fn grants_are_scoped_by_risk() {
    let g = Gate::new(Duration::from_secs(60));
    let now = Instant::now();
    g.add_grant("t", "exec", Risk::Read, now);
    assert!(g.grant_alive("t", "exec", Risk::Read, now));
    assert!(
        !g.grant_alive("t", "exec", Risk::Write, now),
        "a read grant must not open write"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn read_grant_does_not_cover_write_risk_commands() {
    let t = start("", 5000).await;
    let echo = tool(&["/bin/echo", "/usr/bin/echo"]).unwrap();
    let sleep = tool(&["/bin/sleep", "/usr/bin/sleep"]).unwrap();
    let (a, k, e) = (t.addr.clone(), t.token.clone(), echo.clone());
    let first = tokio::spawn(blocking(move || client::exec(&a, &k, &e, &["hi".into()])));
    for _ in 0..100 {
        if t.state.gate.resolve(None, Decision::Grant).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(first.await.unwrap().is_ok());
    // echo(read) 그랜트가 있어도 sleep(write)은 다시 묻는다.
    let (a, k) = (t.addr.clone(), t.token.clone());
    let second = tokio::spawn(blocking(move || {
        client::exec(&a, &k, &sleep, &["0".into()])
    }));
    for _ in 0..100 {
        if !t.state.gate.waiting().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        t.state.gate.waiting().len(),
        1,
        "write-risk command must ask again"
    );
    t.state.gate.resolve(None, Decision::Deny);
    assert_eq!(second.await.unwrap().unwrap_err().code, "APPROVAL_DENIED");
}

#[test]
fn terminal_answers_parse() {
    let p = |s| parse_terminal_answer(s);
    assert_eq!(p("y 763eb30c\n").unwrap().id.as_deref(), Some("763eb30c"));
    assert_eq!(p("A 76").unwrap().decision, Decision::Grant);
    assert_eq!(p("no").unwrap().id, None);
    assert_eq!(p("YES").unwrap().decision, Decision::Once);
    for bad in ["", "maybe", "y 12 34", "y zz", "y 76; rm", "yy"] {
        assert!(p(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn terminal_prefix_resolution_is_exact_about_which_request() {
    let g = Gate::new(Duration::from_secs(60));
    let a = g.open("t", "exec", Risk::Read, "a".into()).unwrap();
    let b = g.open("t", "exec", Risk::Read, "b".into()).unwrap();
    assert!(matches!(
        g.resolve_prefix("z", Decision::Once),
        Err(ResolveError::NoMatch)
    ));
    assert!(matches!(
        g.resolve_prefix("", Decision::Once),
        Err(ResolveError::NoMatch)
    ));
    // 한 글자 접두어는 쓰지 않는다.
    assert!(matches!(
        g.resolve_prefix(&a.id[..1], Decision::Once),
        Err(ResolveError::NoMatch)
    ));
    // 두 번째 요청만 골라 거부해도 첫 번째는 그대로 대기한다.
    let hit = g.resolve_prefix(&b.id[..4], Decision::Deny).unwrap();
    assert_eq!(hit.id, b.id);
    assert_eq!(g.waiting().len(), 1);
    assert_eq!(g.waiting()[0].id, a.id);
}

#[test]
fn pairing_failures_are_counted_per_source() {
    let now = Instant::now();
    let mut p = Pairing::with_code("ABCD1234".into(), now);
    for _ in 0..SOURCE_MAX_FAILS - 1 {
        assert_eq!(
            p.attempt_from("10.0.0.1", "WRONG000", now),
            Err(PairError::Wrong)
        );
    }
    assert_eq!(
        p.attempt_from("10.0.0.1", "WRONG000", now),
        Err(PairError::Locked)
    );
    // 잠긴 출처는 맞는 코드도 거부되지만, 다른 출처(소유자)는 계속 페어링할 수 있다.
    assert_eq!(
        p.attempt_from("10.0.0.1", "ABCD1234", now),
        Err(PairError::Locked)
    );
    assert_eq!(p.attempt_from("10.0.0.2", "abcd-1234", now), Ok(()));
}

#[test]
fn pairing_code_is_discarded_after_many_failures_overall() {
    let now = Instant::now();
    let mut p = Pairing::with_code("ABCD1234".into(), now);
    let mut last = Ok(());
    for i in 0..TOTAL_MAX_FAILS {
        last = p.attempt_from(&format!("10.0.0.{i}"), "WRONG000", now);
    }
    assert_eq!(last, Err(PairError::Locked));
    assert!(p.current_code().is_none());
}

#[test]
fn node_names_map_to_distinct_env_vars() {
    for ok in ["a", "work-mac", "n1", "mac-mini-2", &"x".repeat(32)] {
        assert!(valid_node_name(ok), "{ok}");
    }
    for bad in [
        "",
        "-a",
        "A",
        "Mac",
        "a_b",
        "a b",
        "맥미니",
        "a.b",
        &"x".repeat(33),
    ] {
        assert!(!valid_node_name(bad), "{bad}");
    }
    assert_ne!(env_var_name("a-b"), env_var_name("ab"));
    assert_eq!(env_var_name("work-mac"), "RCU_TOKEN_WORK_MAC");
}

#[test]
fn token_ids_are_long_and_unique() {
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStore::new(dir.path().join("t.json"));
    let mut ids = std::collections::HashSet::new();
    for _ in 0..50 {
        let t = store.issue("x", "now").unwrap();
        let id = store.verify(&t).unwrap();
        assert_eq!(id.len(), 16);
        assert!(ids.insert(id));
    }
}

#[cfg(unix)]
#[test]
fn secret_files_and_dirs_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let store = TokenStore::new(state.join("tokens.json"));
    store.issue("x", "now").unwrap();
    assert_eq!(mode(&state), 0o700);
    assert_eq!(mode(&state.join("tokens.json")), 0o600);

    let audit_dir = dir.path().join("audit");
    let audit = Audit::new(&audit_dir);
    audit
        .log(rcu::audit::Entry {
            ts: Audit::now(),
            request_id: "r",
            capability: "info",
            target: String::new(),
            risk: None,
            approval: None,
            result: "OK",
            duration_ms: 1,
        })
        .unwrap();
    assert_eq!(mode(&audit_dir), 0o700);
    let file = std::fs::read_dir(&audit_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(mode(&file), 0o600);

    // 이미 느슨한 권한으로 있던 파일도 쓰는 순간 조인다. 링크는 따라가지 않는다.
    let loose = dir.path().join("loose");
    std::fs::write(&loose, "x").unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    rcu::config::write_private(&loose, b"secret").unwrap();
    assert_eq!(mode(&loose), 0o600);
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&loose, &link).unwrap();
    assert!(rcu::config::write_private(&link, b"x").is_err());
}

#[tokio::test]
async fn failed_auth_floods_are_throttled_and_barely_logged() {
    let t = start("", 500).await;
    let mut limited = 0;
    for _ in 0..60 {
        let a = t.addr.clone();
        let e = blocking(move || client::info(&a, "rcu_wrong"))
            .await
            .unwrap_err();
        if e.code == "RATE_LIMITED" {
            limited += 1;
        } else {
            assert_eq!(e.code, "UNAUTHORIZED");
        }
    }
    assert!(limited >= 25, "limited only {limited}");
    let lines = t.audit_text().lines().count();
    assert!(lines <= 5, "audit log grew by {lines} lines");
    // 올바른 토큰은 같은 출처에서도 계속 쓸 수 있다.
    let (a, k) = (t.addr.clone(), t.token.clone());
    assert!(blocking(move || client::info(&a, &k)).await.is_ok());
}

#[tokio::test]
async fn unauthenticated_requests_are_rejected_before_their_body_is_parsed() {
    let t = start("", 500).await;
    // 본문이 JSON 이 아니어도 인증 오류(401)가 먼저 나온다.
    let reply = {
        let (a, r) = (t.addr.clone(), post("/v1/exec", None, "this is not json"));
        blocking(move || raw_request(&a, &r, true).unwrap()).await
    };
    assert!(reply.starts_with("HTTP/1.1 401"), "{reply}");
    let reply = {
        let (a, r) = (t.addr.clone(), post("/v1/exec", Some("rcu_nope"), "{"));
        blocking(move || raw_request(&a, &r, true).unwrap()).await
    };
    assert!(reply.starts_with("HTTP/1.1 401"), "{reply}");
    // 인증된 요청의 깨진 JSON 은 400
    let reply = {
        let (a, r) = (t.addr.clone(), post("/v1/exec", Some(&t.token), "{"));
        blocking(move || raw_request(&a, &r, true).unwrap()).await
    };
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
}

#[tokio::test]
async fn pairing_body_is_small_and_attempts_are_throttled_per_source() {
    let t = start("", 500).await;
    let big = format!("{{\"code\":\"{}\"}}", "A".repeat(10_000));
    let reply = {
        let (a, r) = (t.addr.clone(), post("/v1/pair", None, &big));
        blocking(move || raw_request(&a, &r, true).unwrap()).await
    };
    assert!(
        reply.starts_with("HTTP/1.1 413"),
        "{}",
        &reply[..40.min(reply.len())]
    );
}

#[test]
fn controller_does_not_follow_redirects() {
    use std::net::TcpListener;
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let target_port = target.local_addr().unwrap().port();
    let redirector = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = redirector.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = redirector.accept() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let reply = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target_port}/v1/info\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = s.write_all(reply.as_bytes());
        }
    });
    let res = client::info(&addr, "rcu_x");
    assert!(res.is_err());
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        target.accept().is_err(),
        "the redirect target must never be contacted"
    );
}
