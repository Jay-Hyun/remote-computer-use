//! 헤더를 천천히 보내며 연결을 붙잡는 상대는 끊어야 하고, 정상 요청은 그대로 처리해야 한다.

use rcu::audit::Audit;
use rcu::client;
use rcu::pairing::Pairing;
use rcu::policy::Policy;
use rcu::server::{self, AppState};
use rcu::tokens::TokenStore;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::test]
async fn slow_header_connections_are_closed_but_normal_requests_work() {
    let dir = tempfile::tempdir().unwrap();
    let tokens = TokenStore::new(dir.path().join("tokens.json"));
    let token = tokens.issue("t", "now").unwrap();
    let mut state = AppState::new(
        Policy::parse("[node]\nname = \"slow\"\n").unwrap(),
        tokens,
        Pairing::new(Instant::now()),
        Audit::new(dir.path().join("audit")),
    );
    state.header_timeout = Duration::from_millis(500);
    let state = Arc::new(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(server::serve(listener, state));

    let a = addr.clone();
    let closed_after = tokio::task::spawn_blocking(move || {
        let mut s = TcpStream::connect(&a).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        // 헤더를 끝내지 않는다(빈 줄이 없다).
        s.write_all(b"GET /v1/info HTTP/1.1\r\nHost: x\r\nX-Slow: ")
            .unwrap();
        let started = Instant::now();
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf); // 서버가 닫거나 408 로 답하면 반환된다.
        (started.elapsed(), n)
    })
    .await
    .unwrap();
    assert!(
        closed_after.0 < Duration::from_secs(5),
        "server held a half-open request for {:?} ({:?})",
        closed_after.0,
        closed_after.1
    );

    // 정상 요청은 영향이 없다.
    let (a, k) = (addr.clone(), token.clone());
    let info = tokio::task::spawn_blocking(move || client::info(&a, &k))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(info["name"], "slow");
}

#[tokio::test]
async fn many_idle_connections_do_not_block_new_requests() {
    let dir = tempfile::tempdir().unwrap();
    let tokens = TokenStore::new(dir.path().join("tokens.json"));
    let token = tokens.issue("t", "now").unwrap();
    let state = Arc::new(AppState::new(
        Policy::parse("").unwrap(),
        tokens,
        Pairing::new(Instant::now()),
        Audit::new(dir.path().join("audit")),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(server::serve(listener, state));
    // 연 채로 아무것도 보내지 않는 연결 50개
    let idle: Vec<TcpStream> = (0..50)
        .map(|_| TcpStream::connect(&addr).unwrap())
        .collect();
    let (a, k) = (addr.clone(), token.clone());
    let res = tokio::task::spawn_blocking(move || client::info(&a, &k))
        .await
        .unwrap();
    assert!(res.is_ok());
    drop(idle);
}
