use rcu::audit::Audit;
use rcu::client;
use rcu::pairing::Pairing;
use rcu::policy::Policy;
use rcu::server::{self, AppState};
use rcu::tokens::TokenStore;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

struct Node {
    addr: String,
    tokens: TokenStore,
    audit_dir: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn start_node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let tokens = TokenStore::new(dir.path().join("tokens.json"));
    let audit_dir = dir.path().join("audit");
    let state = Arc::new(AppState {
        policy: Policy::parse("[node]\nname = \"testnode\"\n[capabilities]\nfs_read = true\n")
            .unwrap(),
        tokens: Mutex::new(tokens.clone()),
        pairing: Mutex::new(Pairing::with_code("ABCD1234".into(), Instant::now())),
        audit: Audit::new(&audit_dir),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(server::serve(listener, state));
    Node {
        addr,
        tokens,
        audit_dir,
        _dir: dir,
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

#[tokio::test]
async fn pair_info_revoke_flow() {
    let node = start_node().await;
    let addr = node.addr.clone();

    // 토큰 없이는 401
    let a = addr.clone();
    let e = blocking(move || client::info(&a, "")).await.unwrap_err();
    assert_eq!(e.code, "UNAUTHORIZED");
    assert_eq!(e.exit_code(), 4);

    // 틀린 코드 4번은 PAIR_WRONG, 5번째에 PAIR_LOCKED, 이후엔 맞는 코드도 거부
    for _ in 0..4 {
        let a = addr.clone();
        let e = blocking(move || client::pair(&a, "WRONG000", "t"))
            .await
            .unwrap_err();
        assert_eq!(e.code, "PAIR_WRONG");
    }
    let a = addr.clone();
    let e = blocking(move || client::pair(&a, "WRONG000", "t"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "PAIR_LOCKED");
    let a = addr.clone();
    let e = blocking(move || client::pair(&a, "ABCD1234", "t"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "PAIR_LOCKED");
}

#[tokio::test]
async fn paired_token_works_until_revoked() {
    let node = start_node().await;
    let addr = node.addr.clone();

    let a = addr.clone();
    let resp = blocking(move || client::pair(&a, "abcd-1234", "laptop"))
        .await
        .unwrap();
    let token = resp["token"].as_str().unwrap().to_string();
    assert_eq!(resp["node"], "testnode");

    let (a, t) = (addr.clone(), token.clone());
    let info = blocking(move || client::info(&a, &t)).await.unwrap();
    assert_eq!(info["name"], "testnode");
    assert_eq!(info["capabilities"], serde_json::json!(["info", "fs.read"]));
    assert!(info["os"].is_string() && info["version"].is_string());

    // 코드는 한 번만 쓸 수 있다.
    let a = addr.clone();
    let e = blocking(move || client::pair(&a, "ABCD1234", "other"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "PAIR_LOCKED");

    // 틀린 토큰은 401
    let a = addr.clone();
    let e = blocking(move || client::info(&a, "rcu_wrong"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "UNAUTHORIZED");

    // 실행 중인 노드에도 폐기가 바로 적용된다.
    assert_eq!(node.tokens.revoke_all().unwrap(), 1);
    let (a, t) = (addr.clone(), token.clone());
    let e = blocking(move || client::info(&a, &t)).await.unwrap_err();
    assert_eq!(e.code, "UNAUTHORIZED");

    // 감사 로그에는 토큰이 없다.
    let mut all = String::new();
    for f in std::fs::read_dir(&node.audit_dir).unwrap() {
        all.push_str(&std::fs::read_to_string(f.unwrap().path()).unwrap());
    }
    assert!(all.contains("\"capability\":\"pair\"") && all.contains("\"capability\":\"info\""));
    assert!(!all.contains(&token));
}

#[tokio::test]
async fn controller_refuses_non_tailnet_address() {
    let e = blocking(|| client::info("8.8.8.8:7443", "rcu_x"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "ADDRESS_DENIED");
    assert_eq!(e.exit_code(), 2);
    let e = blocking(|| client::pair("192.168.1.5:7443", "ABCD1234", "t"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "ADDRESS_DENIED");
}

#[tokio::test]
async fn unreachable_node_is_network_error() {
    // 닫힌 포트
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    drop(l);
    let e = blocking(move || client::info(&addr, "rcu_x"))
        .await
        .unwrap_err();
    assert_eq!(e.code, "NETWORK_ERROR");
    assert_eq!(e.exit_code(), 5);
}

fn rcu(home: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rcu"));
    c.env("RCU_HOME", home);
    c
}

#[test]
fn serve_refuses_public_bind() {
    let home = tempfile::tempdir().unwrap();
    for bind in ["0.0.0.0:7443", "192.168.1.5:7443", "[::]:7443"] {
        let out = rcu(home.path())
            .args(["serve", "--bind", bind])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{bind}");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["error"]["code"], "INTERNAL");
    }
}

#[test]
fn cli_end_to_end() {
    let node_home = tempfile::tempdir().unwrap();
    let ctl_home = tempfile::tempdir().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");

    std::fs::write(
        node_home.path().join("policy.toml"),
        "[node]\nname = \"cli-node\"\n",
    )
    .unwrap();
    let mut serve = rcu(node_home.path())
        .args(["serve", "--bind", &addr])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(serve.stdout.take().unwrap()).lines();
    let code = loop {
        let line = lines.next().expect("serve exited early").unwrap();
        if let Some(rest) = line.strip_prefix("pairing code (5 min): ") {
            break rest.trim().to_string();
        }
    };
    // 서버가 소켓을 열 때까지 잠깐 기다린다.
    for _ in 0..50 {
        if std::net::TcpStream::connect(&addr).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // 틀린 코드 → exit 4
    let out = rcu(ctl_home.path())
        .args(["pair", "n1", &addr, "WRONG000", "--print-token"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["error"]["code"], "PAIR_WRONG");

    // 맞는 코드 → 토큰 출력
    let out = rcu(ctl_home.path())
        .args(["pair", "n1", &addr, &code, "--print-token"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["env_var"], "RCU_TOKEN_N1");
    let token = v["token"].as_str().unwrap().to_string();

    // nodes: 토큰이 환경에 있으면 paired
    let out = rcu(ctl_home.path())
        .env("RCU_TOKEN_N1", &token)
        .arg("nodes")
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["nodes"][0]["name"], "n1");
    assert_eq!(v["nodes"][0]["paired"], true);

    // info 성공
    let out = rcu(ctl_home.path())
        .env("RCU_TOKEN_N1", &token)
        .args(["info", "n1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["name"], "cli-node");

    // 토큰 없음 → exit 4
    let out = rcu(ctl_home.path()).args(["info", "n1"]).output().unwrap();
    assert_eq!(out.status.code(), Some(4));

    // 모르는 노드 → exit 1
    let out = rcu(ctl_home.path())
        .args(["info", "ghost"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));

    // 노드에서 전부 폐기 → info 거부
    let out = rcu(node_home.path())
        .args(["revoke", "--all"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["revoked"], 1);
    let out = rcu(ctl_home.path())
        .env("RCU_TOKEN_N1", &token)
        .args(["info", "n1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));

    serve.kill().unwrap();
    let _ = serve.wait();
}

#[test]
fn policy_check_reports_and_rejects() {
    let home = tempfile::tempdir().unwrap();
    let good = home.path().join("good.toml");
    std::fs::write(&good, "[capabilities]\nfs_read = true\n").unwrap();
    let out = rcu(home.path())
        .args(["policy-check", "--policy", good.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["capabilities"], serde_json::json!(["info", "fs.read"]));

    let bad = home.path().join("bad.toml");
    std::fs::write(
        &bad,
        "[[exec.allow]]\nprogram = \"/bin/sh\"\nrisk = \"write\"\n",
    )
    .unwrap();
    let out = rcu(home.path())
        .args(["policy-check", "--policy", bad.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}
