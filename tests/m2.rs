#![cfg(unix)] // Windows 경로 시험은 M4 에서 옮긴다

//! M2: exec / fs / 승인 / 그랜트 / 속도 제한을 루프백 서버로 검사한다.

use rcu::approval::Decision;
use rcu::audit::Audit;
use rcu::client::{self, ClientError};
use rcu::pairing::Pairing;
use rcu::policy::Policy;
use rcu::server::{self, AppState};
use rcu::tokens::TokenStore;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct T {
    addr: String,
    token: String,
    state: Arc<AppState>,
    dir: tempfile::TempDir,
    tokens: TokenStore,
}

fn tool(candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|p| p.to_string())
}

async fn start(extra: &str, http_wait_ms: u64) -> T {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let mut exec_entries = String::new();
    if let Some(echo) = tool(&["/bin/echo", "/usr/bin/echo"]) {
        exec_entries +=
            &format!("[[exec.allow]]\nprogram = '{echo}'\nargs = [\"**\"]\nrisk = \"read\"\n");
    }
    if let Some(sleep) = tool(&["/bin/sleep", "/usr/bin/sleep"]) {
        exec_entries +=
            &format!("[[exec.allow]]\nprogram = '{sleep}'\nargs = [\"*\"]\nrisk = \"write\"\n");
    }
    if let Some(rm) = tool(&["/bin/rm", "/usr/bin/rm"]) {
        exec_entries +=
            &format!("[[exec.allow]]\nprogram = '{rm}'\nargs = [\"*\"]\nrisk = \"destructive\"\n");
    }
    let text = format!(
        "[node]\nname = \"m2\"\n[capabilities]\nexec = true\nfs_read = true\nfs_write = true\n\
         [fs]\nroots = ['{}']\nmax_read_bytes = 1000\nmax_write_bytes = 1000\ndeny = [\"**/.env\"]\n{extra}\n{exec_entries}",
        work.display()
    );
    let tokens = TokenStore::new(dir.path().join("tokens.json"));
    let token = tokens.issue("test", "now").unwrap();
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
        state,
        dir,
        tokens,
    }
}

impl T {
    fn path(&self, name: &str) -> String {
        self.dir
            .path()
            .join("work")
            .join(name)
            .to_string_lossy()
            .into_owned()
    }
}

async fn blocking<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
    tokio::task::spawn_blocking(f).await.unwrap()
}

/// 노드 사용자 역할: 대기 중인 요청이 생기면 결정을 내린다.
async fn approve(state: &Arc<AppState>, decision: Decision) {
    for _ in 0..200 {
        if state.gate.resolve(None, decision).is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no request ever asked for approval");
}

async fn read(t: &T, path: impl Into<String>) -> Result<Value, ClientError> {
    let (a, k, p) = (t.addr.clone(), t.token.clone(), path.into());
    blocking(move || client::fs_read(&a, &k, &p)).await
}

async fn write(
    t: &T,
    path: impl Into<String>,
    data: &[u8],
    overwrite: bool,
) -> Result<Value, ClientError> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let (a, k, p) = (t.addr.clone(), t.token.clone(), path.into());
    blocking(move || client::fs_write(&a, &k, &p, &b64, overwrite)).await
}

async fn exec(t: &T, program: &str, args: &[&str]) -> Result<Value, ClientError> {
    let (a, k, p) = (t.addr.clone(), t.token.clone(), program.to_string());
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    blocking(move || client::exec(&a, &k, &p, &args)).await
}

#[tokio::test]
async fn read_waits_for_node_approval_then_returns_content() {
    let t = start("", 5000).await;
    std::fs::write(t.path("a.txt"), "hello").unwrap();
    let (res, _) = tokio::join!(read(&t, t.path("a.txt")), approve(&t.state, Decision::Once));
    let v = res.unwrap();
    assert_eq!(v["size"], 5);
    // 한 번만 허용했으므로 다음 요청도 다시 묻는다.
    let (res, _) = tokio::join!(read(&t, t.path("a.txt")), approve(&t.state, Decision::Once));
    assert!(res.is_ok());
}

#[tokio::test]
async fn deny_returns_approval_denied() {
    let t = start("", 5000).await;
    std::fs::write(t.path("a.txt"), "x").unwrap();
    let (res, _) = tokio::join!(read(&t, t.path("a.txt")), approve(&t.state, Decision::Deny));
    let e = res.unwrap_err();
    assert_eq!(e.code, "APPROVAL_DENIED");
    assert_eq!(e.exit_code(), 2);
}

#[tokio::test]
async fn grant_lets_next_calls_through_without_asking() {
    let t = start("", 5000).await;
    std::fs::write(t.path("a.txt"), "x").unwrap();
    let (res, _) = tokio::join!(
        read(&t, t.path("a.txt")),
        approve(&t.state, Decision::Grant)
    );
    assert!(res.is_ok());
    // 승인 대기 없이 바로 성공해야 한다.
    for _ in 0..3 {
        assert!(read(&t, t.path("a.txt")).await.is_ok());
    }
    assert!(t.state.gate.waiting().is_empty());
    // 다른 능력(fs.write)은 별도로 묻는다.
    let (res, _) = tokio::join!(
        write(&t, t.path("new.txt"), b"data", false),
        approve(&t.state, Decision::Once)
    );
    assert_eq!(res.unwrap()["bytes"], 4);
}

#[tokio::test]
async fn grant_is_per_token() {
    let t = start("", 5000).await;
    std::fs::write(t.path("a.txt"), "x").unwrap();
    let (res, _) = tokio::join!(
        read(&t, t.path("a.txt")),
        approve(&t.state, Decision::Grant)
    );
    assert!(res.is_ok());
    let other = t.tokens.issue("other", "now").unwrap();
    let (a, p) = (t.addr.clone(), t.path("a.txt"));
    let pending = tokio::spawn(blocking(move || client::fs_read(&a, &other, &p)));
    approve(&t.state, Decision::Once).await; // 다른 토큰은 그랜트가 없어 다시 묻는다
    assert!(pending.await.unwrap().is_ok());
}

#[tokio::test]
async fn slow_approval_returns_202_then_wait_gets_the_result_once() {
    let t = start("", 150).await;
    let target = t.path("late.txt");
    let e = write(&t, &target, b"payload", false).await.unwrap_err();
    assert_eq!(e.code, "APPROVAL_PENDING");
    assert_eq!(e.exit_code(), 3);
    let id = e.approval_id.clone().expect("approval id");
    assert!(
        !std::path::Path::new(&target).exists(),
        "must not run before approval"
    );

    // 같은 id 를 다른 토큰이 가져갈 수 없다.
    let other = t.tokens.issue("other", "now").unwrap();
    let (a, i) = (t.addr.clone(), id.clone());
    let stolen = blocking(move || client::wait(&a, &other, &i))
        .await
        .unwrap_err();
    assert_eq!(stolen.code, "UNKNOWN_APPROVAL");

    assert!(t.state.gate.resolve(Some(&id), Decision::Once).is_some());
    let (a, k, i) = (t.addr.clone(), t.token.clone(), id.clone());
    let v = blocking(move || client::wait(&a, &k, &i)).await.unwrap();
    assert_eq!(v["bytes"], 7);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "payload");
    // 결과를 다시 가져가도 재실행되지 않는다(create_new 라 재실행되면 EXISTS).
    let (a, k, i) = (t.addr.clone(), t.token.clone(), id);
    assert_eq!(
        blocking(move || client::wait(&a, &k, &i)).await.unwrap()["bytes"],
        7
    );
}

#[tokio::test]
async fn wait_for_unknown_id_is_404() {
    let t = start("", 100).await;
    let (a, k) = (t.addr.clone(), t.token.clone());
    let e = blocking(move || client::wait(&a, &k, "deadbeef"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "UNKNOWN_APPROVAL");
}

#[tokio::test]
async fn policy_denials_never_reach_the_approval_queue() {
    let t = start("", 200).await;
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("s.txt"), "s").unwrap();
    let e = read(
        &t,
        outside.path().join("s.txt").to_str().unwrap().to_string(),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, "PATH_DENIED");
    std::fs::write(t.path(".env"), "K=1").unwrap();
    assert_eq!(
        read(&t, t.path(".env")).await.unwrap_err().code,
        "PATH_DENIED"
    );
    let e = read(&t, format!("{}/../x", t.path("sub")))
        .await
        .unwrap_err();
    assert_eq!(e.code, "PATH_DENIED");
    let e = exec(&t, "/bin/sh", &["-c", "id"]).await.unwrap_err();
    assert_eq!(e.code, "SHELL_DENIED");
    let e = exec(&t, "/usr/bin/curl", &["x"]).await.unwrap_err();
    assert_eq!(e.code, "COMMAND_DENIED");
    assert!(t.state.gate.waiting().is_empty());
}

#[tokio::test]
async fn capability_off_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let tokens = TokenStore::new(dir.path().join("t.json"));
    let token = tokens.issue("t", "n").unwrap();
    let state = Arc::new(AppState::new(
        Policy::parse("").unwrap(),
        tokens,
        Pairing::new(Instant::now()),
        Audit::new(dir.path().join("a")),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(server::serve(listener, state));
    let (a, k) = (addr.clone(), token.clone());
    let e = blocking(move || client::fs_read(&a, &k, "/etc/hostname"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "CAPABILITY_OFF");
    let e = blocking(move || client::exec(&addr, &token, "/bin/echo", &[]))
        .await
        .unwrap_err();
    assert_eq!(e.code, "CAPABILITY_OFF");
}

#[tokio::test]
async fn write_rules_new_file_exists_overwrite_and_backup() {
    let t = start("", 5000).await;
    let f = t.path("f.txt");
    let (res, _) = tokio::join!(
        write(&t, &f, b"one", false),
        approve(&t.state, Decision::Grant)
    );
    assert!(res.is_ok());

    // 있는 파일을 --overwrite 없이 쓰면 묻지도 않고 EXISTS
    let e = write(&t, &f, b"two", false).await.unwrap_err();
    assert_eq!(e.code, "EXISTS");
    assert_eq!(std::fs::read_to_string(&f).unwrap(), "one");

    // 덮어쓰기는 fs.write 그랜트가 있어도 매번 묻는다(destructive).
    let (res, _) = tokio::join!(
        write(&t, &f, b"two", true),
        approve(&t.state, Decision::Grant)
    );
    let v = res.unwrap();
    assert_eq!(v["overwrote"], true);
    assert_eq!(v["backup"], "f.txt.rcu-bak");
    assert_eq!(std::fs::read_to_string(&f).unwrap(), "two");
    assert_eq!(
        std::fs::read_to_string(format!("{f}.rcu-bak")).unwrap(),
        "one"
    );

    // destructive 에 "a" 를 답해도 그랜트가 생기지 않는다.
    let (res, _) = tokio::join!(
        write(&t, &f, b"three", true),
        approve(&t.state, Decision::Once)
    );
    assert!(res.is_ok());
}

#[tokio::test]
async fn size_limits_are_enforced() {
    let t = start("", 5000).await;
    std::fs::write(t.path("big.txt"), vec![b'x'; 2000]).unwrap();
    let (res, _) = tokio::join!(
        read(&t, t.path("big.txt")),
        approve(&t.state, Decision::Grant)
    );
    assert_eq!(res.unwrap_err().code, "TOO_LARGE");
    let e = write(&t, t.path("w.txt"), &vec![b'y'; 2000], false)
        .await
        .unwrap_err();
    assert_eq!(e.code, "TOO_LARGE");
    assert!(!std::path::Path::new(&t.path("w.txt")).exists());
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_swapped_in_is_not_followed() {
    let t = start("", 5000).await;
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret"), "top secret").unwrap();
    std::os::unix::fs::symlink(outside.path().join("secret"), t.path("link")).unwrap();
    let e = read(&t, t.path("link")).await.unwrap_err();
    assert_eq!(e.code, "PATH_DENIED");
    let e = write(&t, t.path("link"), b"x", true).await.unwrap_err();
    assert_eq!(e.code, "PATH_DENIED");
}

#[cfg(unix)]
#[tokio::test]
async fn exec_runs_without_a_shell_and_caps_output() {
    let t = start("[exec]\nmax_output_bytes = 2048\ntimeout_secs = 1\n", 5000).await;
    let echo = tool(&["/bin/echo", "/usr/bin/echo"]).unwrap();
    let (res, _) = tokio::join!(
        exec(&t, &echo, &["hi", "$HOME", ";", "id"]),
        approve(&t.state, Decision::Grant)
    );
    let v = res.unwrap();
    assert_eq!(v["exit_code"], 0);
    // 셸이 없으므로 확장되거나 실행되지 않고 그대로 출력된다.
    assert_eq!(v["stdout"], "hi $HOME ; id\n");

    let big = "x".repeat(10_000);
    let v = exec(&t, &echo, &[&big]).await.unwrap();
    assert_eq!(v["truncated"], true);
    assert!(v["stdout"].as_str().unwrap().len() <= 2048);
}

#[cfg(unix)]
#[tokio::test]
async fn exec_times_out_and_kills_the_process() {
    let t = start("[exec]\ntimeout_secs = 1\n", 5000).await;
    let sleep = tool(&["/bin/sleep", "/usr/bin/sleep"]).unwrap();
    let started = Instant::now();
    let (res, _) = tokio::join!(exec(&t, &sleep, &["30"]), approve(&t.state, Decision::Once));
    let v = res.unwrap();
    assert_eq!(v["timed_out"], true);
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[cfg(unix)]
#[tokio::test]
async fn destructive_exec_asks_every_time() {
    let t = start("", 5000).await;
    let rm = tool(&["/bin/rm", "/usr/bin/rm"]).unwrap();
    std::fs::write(t.path("gone1"), "x").unwrap();
    std::fs::write(t.path("gone2"), "x").unwrap();
    for name in ["gone1", "gone2"] {
        let name_path = t.path(name);
        let args = [name_path.as_str()];
        let (res, _) = tokio::join!(exec(&t, &rm, &args), approve(&t.state, Decision::Grant));
        assert_eq!(res.unwrap()["exit_code"], 0);
        assert!(!std::path::Path::new(&t.path(name)).exists());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn child_does_not_inherit_node_secrets() {
    let t = start("", 5000).await;
    std::env::set_var("RCU_TEST_SECRET", "hunter2");
    let env = tool(&["/usr/bin/env", "/bin/env"]).unwrap();
    // env 는 정책상 허용 목록에 넣을 수 없으므로 직접 실행 모듈로 확인한다.
    let out = rcu::exec::run(&env, &[], Duration::from_secs(5), 100_000).unwrap();
    assert!(!out.stdout.contains("hunter2"), "{}", out.stdout);
    drop(t);
}

#[tokio::test]
async fn rate_limit_applies_per_token() {
    let t = start("[limits]\nper_minute = 3\nper_day = 1000\n", 5000).await;
    for _ in 0..3 {
        let (a, k) = (t.addr.clone(), t.token.clone());
        blocking(move || client::info(&a, &k)).await.unwrap();
    }
    let (a, k) = (t.addr.clone(), t.token.clone());
    let e = blocking(move || client::info(&a, &k)).await.unwrap_err();
    assert_eq!(e.code, "RATE_LIMITED");
    // 다른 토큰은 영향 없다.
    let other = t.tokens.issue("other", "now").unwrap();
    let a = t.addr.clone();
    blocking(move || client::info(&a, &other)).await.unwrap();
}

#[tokio::test]
async fn audit_log_records_ops_without_content() {
    let t = start("", 5000).await;
    std::fs::write(t.path("a.txt"), "SUPER-SECRET-CONTENT").unwrap();
    let (res, _) = tokio::join!(read(&t, t.path("a.txt")), approve(&t.state, Decision::Once));
    res.unwrap();
    let _ = read(&t, "/definitely/not/allowed").await;
    let mut all = String::new();
    for f in std::fs::read_dir(t.dir.path().join("audit")).unwrap() {
        all += &std::fs::read_to_string(f.unwrap().path()).unwrap();
    }
    assert!(all.contains("\"capability\":\"fs.read\"") && all.contains("\"approval\":\"once\""));
    assert!(all.contains("PATH_DENIED") || all.contains("CAPABILITY"));
    assert!(!all.contains("SUPER-SECRET-CONTENT"));
    assert!(!all.contains(&t.token));
}
