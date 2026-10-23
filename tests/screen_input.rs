//! M5: 화면 캡처·입력. 가짜 백엔드로 정책·승인·감사 전 구간을 시험한다.

use rcu::approval::Decision;
use rcu::audit::Audit;
use rcu::client::{self, ClientError};
use rcu::desktop::{Button, FakeDesktop};
use rcu::ops::{self, Op};
use rcu::pairing::Pairing;
use rcu::policy::{Policy, Risk};
use rcu::server::{self, AppState};
use rcu::tokens::TokenStore;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct T {
    addr: String,
    token: String,
    state: Arc<AppState>,
    fake: Arc<FakeDesktop>,
    dir: tempfile::TempDir,
}

async fn start(policy_text: &str, http_wait_ms: u64) -> T {
    let dir = tempfile::tempdir().unwrap();
    let tokens = TokenStore::new(dir.path().join("tokens.json"));
    let token = tokens.issue("test", "now").unwrap();
    let fake = Arc::new(FakeDesktop::default());
    let mut state = AppState::new(
        Policy::parse(policy_text).unwrap(),
        tokens,
        Pairing::with_code("ABCD1234".into(), Instant::now()),
        Audit::new(dir.path().join("audit")),
    );
    state.http_wait = Duration::from_millis(http_wait_ms);
    state.desktop = fake.clone();
    let state = Arc::new(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(server::serve(listener, state.clone()));
    T {
        addr,
        token,
        state,
        fake,
        dir,
    }
}

const BOTH: &str = "[capabilities]\nscreen = true\ninput = true\n";

async fn blocking<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
    tokio::task::spawn_blocking(f).await.unwrap()
}

async fn approve(state: &Arc<AppState>, decision: Decision) {
    for _ in 0..200 {
        if state.gate.resolve(None, decision).is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no request ever asked for approval");
}

async fn screen(t: &T) -> Result<Value, ClientError> {
    let (a, k) = (t.addr.clone(), t.token.clone());
    blocking(move || client::screen(&a, &k)).await
}

async fn click(t: &T, x: i32, y: i32) -> Result<Value, ClientError> {
    let (a, k) = (t.addr.clone(), t.token.clone());
    blocking(move || client::click(&a, &k, x, y, "left")).await
}

async fn type_text(t: &T, text: &str) -> Result<Value, ClientError> {
    let (a, k, s) = (t.addr.clone(), t.token.clone(), text.to_string());
    blocking(move || client::type_text(&a, &k, &s)).await
}

async fn key(t: &T, combo: &str) -> Result<Value, ClientError> {
    let (a, k, c) = (t.addr.clone(), t.token.clone(), combo.to_string());
    blocking(move || client::key(&a, &k, &c)).await
}

fn audit_text(t: &T) -> String {
    let mut all = String::new();
    if let Ok(rd) = std::fs::read_dir(t.dir.path().join("audit")) {
        for f in rd.flatten() {
            all += &std::fs::read_to_string(f.path()).unwrap_or_default();
        }
    }
    all
}

#[test]
fn screen_and_input_are_off_by_default() {
    let p = Policy::parse("").unwrap();
    assert_eq!(p.capabilities(), vec!["info"]);
    for op in [
        Op::Screen,
        Op::Click {
            x: 1,
            y: 1,
            button: Button::Left,
        },
        Op::Type { text: "x".into() },
        Op::Key {
            combo: "enter".into(),
        },
    ] {
        assert_eq!(ops::plan(&p, &op).unwrap_err().code, "CAPABILITY_OFF");
    }
    let on = Policy::parse(BOTH).unwrap();
    assert_eq!(on.capabilities(), vec!["info", "screen", "input"]);
}

#[test]
fn risk_classes() {
    let ask_always = Policy::parse(BOTH).unwrap();
    assert!(ops::plan(&ask_always, &Op::Screen)
        .unwrap()
        .risk
        .always_needs_approval());
    let grantable = Policy::parse(&format!("{BOTH}[screen]\ngrant = true\n")).unwrap();
    assert_eq!(ops::plan(&grantable, &Op::Screen).unwrap().risk, Risk::Read);
    for p in [&ask_always, &grantable] {
        let click = ops::plan(
            p,
            &Op::Click {
                x: 5,
                y: 6,
                button: Button::Right,
            },
        )
        .unwrap();
        assert!(
            click.risk.always_needs_approval(),
            "input is asked every time"
        );
    }
}

#[test]
fn prompts_show_exactly_what_will_happen() {
    let p = Policy::parse(BOTH).unwrap();
    let click = ops::plan(
        &p,
        &Op::Click {
            x: 640,
            y: 360,
            button: Button::Right,
        },
    )
    .unwrap();
    assert!(
        click.summary.contains("(640, 360)") && click.summary.contains("right"),
        "{}",
        click.summary
    );
    let typed = ops::plan(
        &p,
        &Op::Type {
            text: "line1\nrm -rf /\u{202e}".into(),
        },
    )
    .unwrap();
    assert!(
        typed.summary.contains("\\n") && typed.summary.contains("\\u{202e}"),
        "{}",
        typed.summary
    );
    assert!(!typed.summary.contains('\n'));
    let key = ops::plan(
        &p,
        &Op::Key {
            combo: "Ctrl+Alt+Del".into(),
        },
    );
    assert!(key.is_err(), "unknown key names are refused");
    let key = ops::plan(
        &p,
        &Op::Key {
            combo: "ctrl+shift+t".into(),
        },
    )
    .unwrap();
    assert!(key.summary.contains("ctrl+shift+t"));
}

#[test]
fn invalid_input_is_refused_before_asking() {
    let p = Policy::parse(&format!("{BOTH}[input]\nmax_text = 10\n")).unwrap();
    let code = |op: Op| ops::plan(&p, &op).unwrap_err().code;
    assert_eq!(
        code(Op::Click {
            x: -1,
            y: 0,
            button: Button::Left
        }),
        "BAD_REQUEST"
    );
    assert_eq!(
        code(Op::Click {
            x: 0,
            y: 200_000,
            button: Button::Left
        }),
        "BAD_REQUEST"
    );
    assert_eq!(
        code(Op::Type {
            text: String::new()
        }),
        "BAD_REQUEST"
    );
    assert_eq!(
        code(Op::Type {
            text: "x".repeat(11)
        }),
        "BAD_REQUEST"
    );
    assert_eq!(
        code(Op::Type {
            text: "bell\x07".into()
        }),
        "BAD_REQUEST"
    );
    assert_eq!(
        code(Op::Key {
            combo: "ctrl+f13".into()
        }),
        "BAD_REQUEST"
    );
    assert_eq!(code(Op::Key { combo: "".into() }), "BAD_REQUEST");
}

#[tokio::test]
async fn capture_asks_every_time_by_default_and_returns_a_png() {
    let t = start(BOTH, 5000).await;
    let (res, _) = tokio::join!(screen(&t), approve(&t.state, Decision::Grant));
    let v = res.unwrap();
    assert_eq!(
        (v["width"].as_u64(), v["height"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(v["screen_width"], 2560);
    assert_eq!(
        *t.fake.calls.lock().unwrap(),
        vec!["capture max_width=1280"]
    );

    // 답이 "기간 승인"이어도 기본 정책에서는 다음 캡처도 다시 묻는다.
    let (res, _) = tokio::join!(screen(&t), approve(&t.state, Decision::Once));
    assert!(res.is_ok());
    assert_eq!(t.fake.calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn capture_grants_work_only_when_the_policy_allows_them() {
    let t = start(
        &format!("{BOTH}[screen]\ngrant = true\nmax_width = 800\n"),
        5000,
    )
    .await;
    let (res, _) = tokio::join!(screen(&t), approve(&t.state, Decision::Grant));
    assert!(res.is_ok());
    assert!(screen(&t).await.is_ok(), "second capture must not ask");
    assert!(t.state.gate.waiting().is_empty());
    assert_eq!(t.fake.calls.lock().unwrap()[1], "capture max_width=800");
}

#[tokio::test]
async fn screenshot_is_saved_to_the_requested_file_and_not_printed() {
    let t = start(BOTH, 5000).await;
    let (res, _) = tokio::join!(screen(&t), approve(&t.state, Decision::Once));
    let out = t.dir.path().join("shot.png");
    let v = client::save_screenshot(res.unwrap(), Some(&out)).unwrap();
    assert!(
        v.get("png_b64").is_none(),
        "the image must not be echoed into the output"
    );
    assert_eq!(v["saved"], out.to_string_lossy().as_ref());
    let bytes = std::fs::read(&out).unwrap();
    assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
    assert_eq!(v["bytes"], bytes.len());

    let again =
        client::save_screenshot(serde_json::json!({"png_b64": "AAAA", "width": 1}), None).unwrap();
    assert!(again.get("png_b64").is_none() && again["note"].as_str().unwrap().contains("--out"));
    // 스크린샷이 아닌 결과는 그대로
    let other = serde_json::json!({"size": 3});
    assert_eq!(client::save_screenshot(other.clone(), None).unwrap(), other);
}

#[tokio::test]
async fn input_is_asked_every_time_and_never_logged_with_its_content() {
    let t = start(BOTH, 5000).await;
    let secret = "hunter2-secret-password";
    let (res, _) = tokio::join!(type_text(&t, secret), approve(&t.state, Decision::Grant));
    assert_eq!(res.unwrap()["typed_chars"], secret.len());
    // "기간 승인"을 답했어도 입력은 그랜트가 생기지 않는다.
    let (res, _) = tokio::join!(click(&t, 10, 20), approve(&t.state, Decision::Once));
    assert!(res.is_ok());
    let (res, _) = tokio::join!(key(&t, "ctrl+c"), approve(&t.state, Decision::Once));
    assert!(res.is_ok());
    assert_eq!(
        *t.fake.calls.lock().unwrap(),
        vec![
            format!("type {} chars", secret.len()),
            "click 10,20 left".into(),
            "key ctrl+c".into()
        ]
    );
    let log = audit_text(&t);
    assert!(
        !log.contains("hunter2"),
        "typed text must never reach the audit log: {log}"
    );
    assert!(
        log.contains("type 23 chars") && log.contains("click 10,20") && log.contains("key ctrl+c"),
        "{log}"
    );
    assert!(log.contains("\"capability\":\"input\""));
}

#[tokio::test]
async fn denied_input_does_nothing() {
    let t = start(BOTH, 5000).await;
    let (res, _) = tokio::join!(click(&t, 1, 2), approve(&t.state, Decision::Deny));
    assert_eq!(res.unwrap_err().code, "APPROVAL_DENIED");
    assert!(t.fake.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn bad_requests_never_reach_the_approval_queue() {
    let t = start(BOTH, 200).await;
    assert_eq!(click(&t, -5, 0).await.unwrap_err().code, "BAD_REQUEST");
    assert_eq!(key(&t, "ctrl+f13").await.unwrap_err().code, "BAD_REQUEST");
    assert_eq!(
        type_text(&t, "bell\x07").await.unwrap_err().code,
        "BAD_REQUEST"
    );
    let (a, k) = (t.addr.clone(), t.token.clone());
    let e = blocking(move || client::click(&a, &k, 1, 1, "middle"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "BAD_REQUEST");
    assert!(t.state.gate.waiting().is_empty());
}

#[tokio::test]
async fn capabilities_off_are_reported_over_http() {
    let t = start("[capabilities]\nscreen = true\n", 200).await;
    assert_eq!(click(&t, 1, 1).await.unwrap_err().code, "CAPABILITY_OFF");
    let t = start("[capabilities]\ninput = true\n", 200).await;
    assert_eq!(screen(&t).await.unwrap_err().code, "CAPABILITY_OFF");
}

#[tokio::test]
async fn input_has_its_own_low_rate_limit() {
    let t = start(&format!("{BOTH}[limits]\ninput_per_minute = 2\n"), 100).await;
    assert_eq!(click(&t, 1, 1).await.unwrap_err().code, "APPROVAL_PENDING");
    assert_eq!(click(&t, 2, 2).await.unwrap_err().code, "APPROVAL_PENDING");
    assert_eq!(click(&t, 3, 3).await.unwrap_err().code, "RATE_LIMITED");
    // 캡처는 영향 없다.
    assert_eq!(screen(&t).await.unwrap_err().code, "APPROVAL_PENDING");
}

#[cfg(not(any(target_os = "macos", windows)))]
#[test]
fn real_backend_reports_unsupported_on_linux() {
    use rcu::desktop::{Desktop, SystemDesktop};
    let d = SystemDesktop;
    assert_eq!(d.capture(1280).unwrap_err().code, "UNSUPPORTED");
    assert_eq!(d.click(1, 1, Button::Left).unwrap_err().code, "UNSUPPORTED");
    assert_eq!(d.type_text("x").unwrap_err().code, "UNSUPPORTED");
}
