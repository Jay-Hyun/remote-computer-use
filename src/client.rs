//! 컨트롤러 쪽 HTTP 클라이언트. 토큰은 루프백·테일넷 주소로만 보낸다.

use crate::bind;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientError {
    pub code: String,
    pub message: String,
    pub approval_id: Option<String>,
}

impl ClientError {
    pub fn new(code: &str, message: impl Into<String>) -> ClientError {
        ClientError {
            code: code.to_string(),
            message: message.into(),
            approval_id: None,
        }
    }

    /// 0 성공, 1 기타, 2 정책 거부, 3 승인 대기, 4 인증, 5 네트워크
    pub fn exit_code(&self) -> i32 {
        match self.code.as_str() {
            "UNAUTHORIZED" | "PAIR_WRONG" | "PAIR_LOCKED" | "PAIR_EXPIRED" => 4,
            "CAPABILITY_OFF" | "PATH_DENIED" | "COMMAND_DENIED" | "SHELL_DENIED"
            | "APPROVAL_DENIED" | "APPROVAL_TIMEOUT" | "ADDRESS_DENIED" | "PROXY_DENIED" => 2,
            "APPROVAL_PENDING" => 3,
            "NETWORK_ERROR" => 5,
            _ => 1,
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ClientError {}

#[derive(Deserialize)]
struct ErrBody {
    code: String,
    message: String,
    #[serde(default)]
    approval_id: Option<String>,
}

impl From<ErrBody> for ClientError {
    fn from(body: ErrBody) -> ClientError {
        ClientError {
            code: body.code,
            message: body.message,
            approval_id: body.approval_id,
        }
    }
}

/// 주소를 풀고, 풀린 주소가 모두 루프백·테일넷인지 확인한다.
/// 검사한 IP 로 직접 접속해 DNS 가 중간에 바뀌는 것을 막는다.
fn resolve(addr: &str) -> Result<SocketAddr, ClientError> {
    let addrs: Vec<SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|_| {
            ClientError::new(
                "NETWORK_ERROR",
                "cannot resolve node address (behind a proxy, use the node's tailnet IP instead of a name)",
            )
        })?
        .collect();
    let first = *addrs
        .first()
        .ok_or_else(|| ClientError::new("NETWORK_ERROR", "cannot resolve node address"))?;
    for a in &addrs {
        if bind::check_ip(a.ip()).is_err() {
            return Err(ClientError::new(
                "ADDRESS_DENIED",
                "node address is not loopback or tailnet; refusing to send credentials",
            ));
        }
    }
    Ok(first)
}

/// `RCU_PROXY` 는 이 PC 위의 SOCKS5 프록시만 허용한다(예: 클라우드 컨테이너의
/// `tailscaled --tun=userspace-networking --socks5-server=localhost:1055`).
/// 원격 프록시는 평문 HTTP 와 토큰을 그대로 보게 되므로 쓰지 않는다.
pub fn proxy_url_ok(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("socks5://")
        .or_else(|| url.strip_prefix("socks5h://"))
    else {
        return false;
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    // `user@host` 같은 인증 정보, 경로, 질의, 퍼센트 인코딩은 쓰지 않는다. ureq 는 마지막 `@` 앞을
    // 인증 정보로 보고 그 뒤 호스트로 접속하므로, 문자열 앞쪽만 보고 허용하면 우회된다.
    if rest.is_empty() || rest.contains(['@', '/', '?', '#', '%', '\\', ' ']) {
        return false;
    }
    let (host, port) = match rest.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((h, "")) => (h, None),
            Some((h, after)) => match after.strip_prefix(':') {
                Some(p) => (h, Some(p)),
                None => return false,
            },
            None => return false,
        },
        None => match rest.rsplit_once(':') {
            // 대괄호 없는 IPv6 는 모호하다(`::1:1055` 가 주소인지 포트인지).
            Some((h, _)) if h.contains(':') => return false,
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        },
    };
    let port_ok = port.is_none_or(|p| {
        !p.is_empty()
            && p.len() <= 5
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
    });
    port_ok && matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn agent() -> Result<ureq::Agent, ClientError> {
    // 리다이렉트는 따라가지 않는다: 노드(또는 그 IP에서 응답하는 무언가)가 컨트롤러를 다른 주소로 보낼 수 없다.
    let mut builder = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(70));
    if let Some(url) = std::env::var("RCU_PROXY").ok().filter(|v| !v.is_empty()) {
        if !proxy_url_ok(&url) {
            return Err(ClientError::new(
                "PROXY_DENIED",
                "RCU_PROXY must be a socks5:// proxy on this machine (localhost / 127.0.0.1 / [::1])",
            ));
        }
        let proxy = ureq::Proxy::new(&url)
            .map_err(|_| ClientError::new("PROXY_DENIED", "RCU_PROXY is not a valid proxy URL"))?;
        builder = builder.proxy(proxy);
    }
    Ok(builder.build())
}

fn finish(result: Result<ureq::Response, ureq::Error>) -> Result<Value, ClientError> {
    match result {
        // 202: 노드 사용자의 승인을 기다리는 중. 오류가 아니라 "대기" 신호다.
        Ok(resp) if resp.status() == 202 => match resp.into_json::<ErrBody>() {
            Ok(body) => Err(body.into()),
            Err(_) => Err(ClientError::new("NETWORK_ERROR", "bad response from node")),
        },
        Ok(resp) => resp
            .into_json()
            .map_err(|_| ClientError::new("NETWORK_ERROR", "bad response from node")),
        Err(ureq::Error::Status(_, resp)) => match resp.into_json::<ErrBody>() {
            Ok(body) => Err(body.into()),
            Err(_) => Err(ClientError::new("INTERNAL", "unexpected error response")),
        },
        Err(ureq::Error::Transport(_)) => {
            Err(ClientError::new("NETWORK_ERROR", "cannot reach node"))
        }
    }
}

pub fn pair(addr: &str, code: &str, controller: &str) -> Result<Value, ClientError> {
    let sock = resolve(addr)?;
    finish(
        agent()?
            .post(&format!("http://{sock}/v1/pair"))
            .send_json(json!({ "code": code, "controller": controller })),
    )
}

pub fn info(addr: &str, token: &str) -> Result<Value, ClientError> {
    let sock = resolve(addr)?;
    finish(
        agent()?
            .get(&format!("http://{sock}/v1/info"))
            .set("Authorization", &format!("Bearer {token}"))
            .call(),
    )
}

fn post(addr: &str, token: &str, path: &str, body: Value) -> Result<Value, ClientError> {
    let sock = resolve(addr)?;
    finish(
        agent()?
            .post(&format!("http://{sock}{path}"))
            .set("Authorization", &format!("Bearer {token}"))
            .send_json(body),
    )
}

pub fn exec(addr: &str, token: &str, program: &str, args: &[String]) -> Result<Value, ClientError> {
    post(
        addr,
        token,
        "/v1/exec",
        json!({ "program": program, "args": args }),
    )
}

pub fn fs_read(addr: &str, token: &str, path: &str) -> Result<Value, ClientError> {
    post(addr, token, "/v1/fs/read", json!({ "path": path }))
}

pub fn fs_write(
    addr: &str,
    token: &str,
    path: &str,
    content_b64: &str,
    overwrite: bool,
) -> Result<Value, ClientError> {
    post(
        addr,
        token,
        "/v1/fs/write",
        json!({ "path": path, "content_b64": content_b64, "overwrite": overwrite }),
    )
}

/// 승인 대기 중이던 요청의 결과를 가져온다(최대 60초 기다림).
pub fn wait(addr: &str, token: &str, approval_id: &str) -> Result<Value, ClientError> {
    let sock = resolve(addr)?;
    finish(
        agent()?
            .get(&format!("http://{sock}/v1/approvals/{approval_id}"))
            .set("Authorization", &format!("Bearer {token}"))
            .call(),
    )
}
