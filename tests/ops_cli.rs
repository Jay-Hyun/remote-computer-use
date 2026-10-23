//! 운영 기능: tokens / revoke <id> / 토큰 만료 / unpair / doctor / completions / 노드 이름 확인.

use rcu::audit::Audit;
use rcu::pairing::Pairing;
use rcu::policy::Policy;
use rcu::server::{self, AppState};
use rcu::tokens::TokenStore;
use serde_json::Value;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

fn rcu(home: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rcu"));
    c.env("RCU_HOME", home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg"))
        // tailscale CLI 가 있어도 시험이 영향을 받지 않게 PATH 를 비운다.
        .env("PATH", "")
        .env_remove("RCU_PROXY");
    c
}

fn run_json(cmd: &mut Command) -> (i32, Value) {
    let out = cmd.output().unwrap();
    (
        out.status.code().unwrap(),
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null),
    )
}

#[test]
fn single_token_revocation_by_id() {
    let home = tempfile::tempdir().unwrap();
    let store = TokenStore::new(home.path().join("state/tokens.json"));
    let a = store.issue("laptop", "2026-01-01T00:00:00Z").unwrap();
    let b = store.issue("desktop", "2026-01-02T00:00:00Z").unwrap();
    let (code, v) = run_json(rcu(home.path()).arg("tokens"));
    assert_eq!(code, 0);
    let list = v["tokens"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert!(
        list.iter().all(|t| t.get("hash").is_none()),
        "hashes are never shown"
    );
    let id_a = store.verify(&a).unwrap();

    let (code, v) = run_json(rcu(home.path()).args(["revoke", &id_a]));
    assert_eq!((code, v["revoked"].as_u64()), (0, Some(1)));
    assert!(store.verify(&a).is_none());
    assert!(store.verify(&b).is_some(), "the other token keeps working");

    // 모르는 id 는 0 개, 인자 없음/둘 다는 오류
    let (code, v) = run_json(rcu(home.path()).args(["revoke", "deadbeefdeadbeef"]));
    assert_eq!((code, v["revoked"].as_u64()), (0, Some(0)));
    assert_eq!(run_json(rcu(home.path()).arg("revoke")).0, 1);
    assert_eq!(
        run_json(rcu(home.path()).args(["revoke", "--all", "abcd1234"])).0,
        1
    );
    let (code, v) = run_json(rcu(home.path()).args(["revoke", "--all"]));
    assert_eq!((code, v["revoked"].as_u64()), (0, Some(1)));
}

#[test]
fn id_prefixes_must_be_long_and_unique() {
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStore::new(dir.path().join("t.json"));
    let t = store.issue("x", "now").unwrap();
    let id = store.verify(&t).unwrap();
    assert_eq!(
        store.revoke(&id[..2]).unwrap(),
        0,
        "2 characters are too few"
    );
    assert_eq!(store.revoke(&id[..6]).unwrap(), 1);
}

#[test]
fn expired_tokens_are_rejected_and_not_considered_existing() {
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStore::new(dir.path().join("t.json"));
    let past = store
        .issue_with_expiry("old", "now", Some("2020-01-01T00:00:00Z".into()))
        .unwrap();
    let future = store
        .issue_with_expiry("new", "now", Some("2999-01-01T00:00:00Z".into()))
        .unwrap();
    let never = store.issue("forever", "now").unwrap();
    assert!(store.verify(&past).is_none());
    assert!(store.verify(&future).is_some());
    assert!(store.verify(&never).is_some());
    let expired_id = store
        .list()
        .unwrap()
        .into_iter()
        .find(|t| t.label == "old")
        .unwrap()
        .id;
    assert!(
        !store.exists(&expired_id),
        "expired tokens drop their grants and pending requests"
    );
}

#[tokio::test]
async fn pairing_stamps_the_expiry_from_policy() {
    let dir = tempfile::tempdir().unwrap();
    let tokens = TokenStore::new(dir.path().join("tokens.json"));
    let state = Arc::new(AppState::new(
        Policy::parse("[node]\nname = \"n\"\n[auth]\ntoken_days = 30\n").unwrap(),
        tokens.clone(),
        Pairing::with_code("ABCD1234".into(), Instant::now()),
        Audit::new(dir.path().join("audit")),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(server::serve(listener, state));
    let a = addr.clone();
    let resp = tokio::task::spawn_blocking(move || rcu::client::pair(&a, "ABCD1234", "t"))
        .await
        .unwrap()
        .unwrap();
    assert!(resp["token"].is_string());
    let t = &tokens.list().unwrap()[0];
    let expires = t.expires.as_deref().expect("expiry set");
    use time::format_description::well_known::Rfc3339;
    let when = time::OffsetDateTime::parse(expires, &Rfc3339).unwrap();
    let days = (when - time::OffsetDateTime::now_utc()).whole_days();
    assert!((28..=30).contains(&days), "{days}");
}

#[test]
fn unpair_removes_the_node_and_is_idempotent() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join("nodes.toml"),
        "[[node]]\nname = \"mac\"\naddr = \"127.0.0.1:7443\"\n[[node]]\nname = \"pc\"\naddr = \"127.0.0.1:7444\"\n",
    )
    .unwrap();
    let (code, v) = run_json(rcu(home.path()).args(["unpair", "mac"]));
    assert_eq!((code, v["was_registered"].as_bool()), (0, Some(true)));
    let (_, v) = run_json(rcu(home.path()).arg("nodes"));
    let names: Vec<_> = v["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["pc"]);
    let (code, v) = run_json(rcu(home.path()).args(["unpair", "mac"]));
    assert_eq!((code, v["was_registered"].as_bool()), (0, Some(false)));
}

#[tokio::test]
async fn info_warns_when_the_node_answers_under_a_different_name() {
    let dir = tempfile::tempdir().unwrap();
    let tokens = TokenStore::new(dir.path().join("tokens.json"));
    let token = tokens.issue("t", "now").unwrap();
    let token_again = token.clone();
    let state = Arc::new(AppState::new(
        Policy::parse("[node]\nname = \"impostor\"\n").unwrap(),
        tokens,
        Pairing::new(Instant::now()),
        Audit::new(dir.path().join("audit")),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(server::serve(listener, state));

    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join("nodes.toml"),
        format!("[[node]]\nname = \"mac\"\naddr = \"{addr}\"\nnode_name = \"my-real-mac\"\n"),
    )
    .unwrap();
    let h = home.path().to_path_buf();
    let (code, v) = tokio::task::spawn_blocking(move || {
        run_json(rcu(&h).env("RCU_TOKEN_MAC", &token).args(["info", "mac"]))
    })
    .await
    .unwrap();
    assert_eq!(code, 0);
    let warning = v["warning"].as_str().expect("warning");
    assert!(
        warning.contains("my-real-mac") && warning.contains("impostor"),
        "{warning}"
    );

    // 이름이 같으면 경고가 없다.
    std::fs::write(
        home.path().join("nodes.toml"),
        format!("[[node]]\nname = \"mac\"\naddr = \"{addr}\"\nnode_name = \"impostor\"\n"),
    )
    .unwrap();
    let h = home.path().to_path_buf();
    let (code, v) = tokio::task::spawn_blocking(move || {
        run_json(
            rcu(&h)
                .env("RCU_TOKEN_MAC", &token_again)
                .args(["info", "mac"]),
        )
    })
    .await
    .unwrap();
    assert_eq!(code, 0);
    assert!(v.get("warning").is_none(), "{v}");
}

#[test]
fn doctor_reports_setup_state_and_fixes() {
    let home = tempfile::tempdir().unwrap();
    // 아무것도 없을 때: 실패 없이 안내만
    let (code, v) = run_json(rcu(home.path()).arg("doctor"));
    assert_eq!(code, 0, "{v}");
    let checks = v["checks"].as_array().unwrap();
    let find = |name: &str| {
        checks
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("no check {name}: {v}"))
    };
    assert!(find("policy")["fix"].as_str().unwrap().contains("rcu init"));
    assert_eq!(find("tailscale")["status"], "warn");
    assert!(find("controller")["fix"]
        .as_str()
        .unwrap()
        .contains("rcu pair"));

    // init 뒤: 정책 ok
    assert_eq!(
        rcu(home.path()).arg("init").output().unwrap().status.code(),
        Some(0)
    );
    let (_, v) = run_json(rcu(home.path()).arg("doctor"));
    let policy = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "policy")
        .unwrap()
        .clone();
    assert_eq!(policy["status"], "ok");

    // 깨진 정책은 실패(종료 코드 1)와 고칠 방법
    std::fs::write(
        home.path().join("policy.toml"),
        "[[exec.allow]]\nprogram = '/bin/sh'\nrisk = \"write\"\n",
    )
    .unwrap();
    let (code, v) = run_json(rcu(home.path()).arg("doctor"));
    assert_eq!(code, 1);
    assert_eq!(v["ok"], false);
}

#[cfg(unix)]
#[test]
fn doctor_flags_loose_permissions_and_unreachable_nodes() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join("state")).unwrap();
    std::fs::set_permissions(
        home.path().join("state"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        home.path().join("nodes.toml"),
        format!("[[node]]\nname = \"gone\"\naddr = \"127.0.0.1:{closed}\"\n"),
    )
    .unwrap();
    let (code, v) = run_json(
        rcu(home.path())
            .env("RCU_TOKEN_GONE", "rcu_x")
            .arg("doctor"),
    );
    assert_eq!(code, 1);
    let checks = v["checks"].as_array().unwrap();
    assert!(checks
        .iter()
        .any(|c| c["name"] == "state directory permissions" && c["status"] == "warn"));
    let node = checks.iter().find(|c| c["name"] == "node gone").unwrap();
    assert_eq!(node["status"], "fail");
    assert!(node["fix"].as_str().unwrap().contains("rcu serve"));
}

#[test]
fn doctor_without_a_stored_token_says_how_to_fix_it() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join("nodes.toml"),
        "[[node]]\nname = \"mac\"\naddr = \"127.0.0.1:1\"\n",
    )
    .unwrap();
    let (code, v) = run_json(rcu(home.path()).arg("doctor"));
    assert_eq!(code, 1);
    let node = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "node mac")
        .unwrap()
        .clone();
    assert!(node["fix"].as_str().unwrap().contains("RCU_TOKEN_MAC"));
}

#[test]
fn completions_are_generated() {
    let home = tempfile::tempdir().unwrap();
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let out = rcu(home.path())
            .args(["completions", shell])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{shell}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("rcu") && text.contains("doctor"), "{shell}");
    }
    assert_ne!(
        rcu(home.path())
            .args(["completions", "klingon"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
}
