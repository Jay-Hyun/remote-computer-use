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
            | "APPROVAL_DENIED" | "APPROVAL_TIMEOUT" | "ADDRESS_DENIED" => 2,
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
        .map_err(|_| ClientError::new("NETWORK_ERROR", "cannot resolve node address"))?
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

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(70))
        .build()
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
        agent()
            .post(&format!("http://{sock}/v1/pair"))
            .send_json(json!({ "code": code, "controller": controller })),
    )
}

pub fn info(addr: &str, token: &str) -> Result<Value, ClientError> {
    let sock = resolve(addr)?;
    finish(
        agent()
            .get(&format!("http://{sock}/v1/info"))
            .set("Authorization", &format!("Bearer {token}"))
            .call(),
    )
}

fn post(addr: &str, token: &str, path: &str, body: Value) -> Result<Value, ClientError> {
    let sock = resolve(addr)?;
    finish(
        agent()
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
        agent()
            .get(&format!("http://{sock}/v1/approvals/{approval_id}"))
            .set("Authorization", &format!("Bearer {token}"))
            .call(),
    )
}
