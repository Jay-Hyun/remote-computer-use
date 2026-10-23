//! RCU_PROXY: 컨트롤러가 로컬 SOCKS5 프록시(예: tailscaled userspace)를 거쳐 노드에 닿는다.
//! 환경 변수를 바꾸므로 이 파일에는 시험 함수를 하나만 둔다.

use rcu::audit::Audit;
use rcu::client::{self, proxy_url_ok};
use rcu::pairing::Pairing;
use rcu::policy::Policy;
use rcu::server::{self, AppState};
use rcu::tokens::TokenStore;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[test]
fn proxy_url_rules() {
    for ok in [
        "socks5://127.0.0.1:1055",
        "socks5://localhost:1055",
        "socks5h://localhost:1055",
        "socks5://[::1]:1055",
        "socks5://localhost",
    ] {
        assert!(proxy_url_ok(ok), "{ok}");
    }
    for bad in [
        "socks5://10.0.0.5:1055",
        "socks5://proxy.example.com:1055",
        "http://127.0.0.1:1055",
        "127.0.0.1:1055",
        "socks5://127.0.0.1.evil.com:1055",
        "socks5://localhost.evil.com:1055",
        // ureq 는 마지막 `@` 앞을 인증 정보로 보고 그 뒤 호스트로 접속한다: 앞쪽만 보고 허용하면 우회된다.
        "socks5://localhost:80@evil.example",
        "socks5://127.0.0.1@evil.example:1080",
        "socks5://[::1]:1@127.0.0.2",
        "socks5://localhost:99999",
        "socks5://localhost:0",
        "socks5://localhost:",
        "socks5://::1:1055",
        "socks5://localhost/path",
        "socks5://localhost?x=1",
        "socks5://localhost#frag",
        "socks5://local%68ost:1055",
        "socks5://localhost\\@evil.example",
        "",
    ] {
        assert!(!proxy_url_ok(bad), "{bad}");
    }
}

/// 인증 없는 SOCKS5 CONNECT 만 지원하는 최소 프록시. 요청받은 목적지를 기록한다.
fn spawn_socks5(seen: Arc<Mutex<Vec<String>>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || {
                let _ = handle(client, seen);
            });
        }
    });
    port
}

fn handle(mut c: TcpStream, seen: Arc<Mutex<Vec<String>>>) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    c.read_exact(&mut head)?;
    let mut methods = vec![0u8; head[1] as usize];
    c.read_exact(&mut methods)?;
    c.write_all(&[5, 0])?;
    let mut req = [0u8; 4];
    c.read_exact(&mut req)?;
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a)?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        3 => {
            let mut len = [0u8; 1];
            c.read_exact(&mut len)?;
            let mut name = vec![0u8; len[0] as usize];
            c.read_exact(&mut name)?;
            String::from_utf8_lossy(&name).into_owned()
        }
        _ => return Ok(()),
    };
    let mut port = [0u8; 2];
    c.read_exact(&mut port)?;
    let target = format!("{host}:{}", u16::from_be_bytes(port));
    seen.lock().unwrap().push(target.clone());
    let upstream = TcpStream::connect(&target)?;
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    let (mut c2, mut u2) = (c.try_clone()?, upstream.try_clone()?);
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c2, &mut u2);
        let _ = u2.shutdown(std::net::Shutdown::Write);
    });
    let (mut u, mut c) = (upstream, c);
    let _ = std::io::copy(&mut u, &mut c);
    let _ = t.join();
    Ok(())
}

#[tokio::test]
async fn controller_reaches_node_through_local_socks5_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let tokens = TokenStore::new(dir.path().join("t.json"));
    let token = tokens.issue("t", "n").unwrap();
    let state = Arc::new(AppState::new(
        Policy::parse("[node]\nname = \"behind-proxy\"\n").unwrap(),
        tokens,
        Pairing::new(Instant::now()),
        Audit::new(dir.path().join("a")),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(server::serve(listener, state));

    let seen = Arc::new(Mutex::new(Vec::new()));
    let proxy_port = spawn_socks5(seen.clone());

    let (addr, tok) = (node_addr.clone(), token.clone());
    let result = tokio::task::spawn_blocking(move || {
        std::env::set_var("RCU_PROXY", format!("socks5://127.0.0.1:{proxy_port}"));
        let ok = client::info(&addr, &tok);
        // 로컬이 아닌 프록시는 토큰을 보내기 전에 거부한다.
        std::env::set_var("RCU_PROXY", "socks5://10.1.2.3:1055");
        let denied = client::info(&addr, &tok);
        std::env::remove_var("RCU_PROXY");
        (ok, denied)
    })
    .await
    .unwrap();

    let info = result.0.expect("request through proxy");
    assert_eq!(info["name"], "behind-proxy");
    assert_eq!(
        *seen.lock().unwrap(),
        vec![node_addr],
        "proxy must have been used"
    );

    let denied = result.1.unwrap_err();
    assert_eq!(denied.code, "PROXY_DENIED");
    assert_eq!(denied.exit_code(), 2);
}
