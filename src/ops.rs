//! 노드가 실행하는 작업: 계획(정책 검사·위험도), 실행, 오류 타입.

use crate::policy::{Access, Policy, PolicyError, Risk};
use crate::{exec, fsops};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpError {
    pub status: u16,
    pub code: &'static str,
    pub message: &'static str,
}

impl OpError {
    pub fn new(status: u16, code: &'static str, message: &'static str) -> OpError {
        OpError {
            status,
            code,
            message,
        }
    }
}

impl From<PolicyError> for OpError {
    fn from(e: PolicyError) -> OpError {
        OpError::new(403, e.code.as_str(), e.message)
    }
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for OpError {}

pub type OpResult = Result<Value, OpError>;

#[derive(Debug, Clone)]
pub enum Op {
    Exec {
        program: String,
        args: Vec<String>,
    },
    Read {
        path: String,
    },
    Write {
        path: String,
        data: Vec<u8>,
        overwrite: bool,
    },
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub capability: &'static str,
    pub risk: Risk,
    /// 감사 로그용(가림 처리 전).
    pub target: String,
}

/// 정책 검사만 하고 실행하지 않는다. 위험도는 정책이 정한다.
pub fn plan(policy: &Policy, op: &Op) -> Result<Plan, OpError> {
    match op {
        Op::Exec { program, args } => {
            let risk = policy.check_command(program, args)?;
            let mut target = program.clone();
            for a in args {
                target.push(' ');
                target.push_str(a);
            }
            Ok(Plan {
                capability: "exec",
                risk,
                target,
            })
        }
        Op::Read { path } => {
            policy.check_path(path, Access::Read)?;
            Ok(Plan {
                capability: "fs.read",
                risk: Risk::Read,
                target: path.clone(),
            })
        }
        Op::Write {
            path,
            data,
            overwrite,
        } => {
            let (_, risk) = fsops::plan_write(policy, path, data.len(), *overwrite)?;
            Ok(Plan {
                capability: "fs.write",
                risk,
                target: path.clone(),
            })
        }
    }
}

/// 승인을 기다리는 동안 정책이 바뀌었을 수 있으므로 실행 직전에 다시 검사한다.
pub fn execute(policy: &Policy, op: &Op) -> OpResult {
    plan(policy, op)?;
    match op {
        Op::Exec { program, args } => {
            let out = exec::run(
                program,
                args,
                Duration::from_secs(policy.exec_timeout_secs),
                policy.exec_max_output_bytes,
            )?;
            Ok(json!({
                "exit_code": out.exit_code,
                "stdout": out.stdout,
                "stderr": out.stderr,
                "truncated": out.truncated,
                "timed_out": out.timed_out,
            }))
        }
        Op::Read { path } => {
            let out = fsops::read(policy, path)?;
            Ok(json!({ "size": out.data.len(), "content_b64": b64(&out.data) }))
        }
        Op::Write {
            path,
            data,
            overwrite,
        } => {
            let out = fsops::write(policy, path, data, *overwrite)?;
            Ok(json!({ "bytes": out.bytes, "overwrote": out.overwrote, "backup": out.backup }))
        }
    }
}

pub fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// 승인 창에 보일 한 줄 설명. 제어 문자를 지워 터미널 조작을 막는다.
pub fn summary(op: &Op) -> String {
    let raw = match op {
        Op::Exec { program, args } => {
            let mut s = format!("run {program}");
            for a in args {
                s.push(' ');
                s.push_str(a);
            }
            s
        }
        Op::Read { path } => format!("read {path}"),
        Op::Write {
            path,
            data,
            overwrite,
        } => {
            if *overwrite {
                format!(
                    "OVERWRITE {path} ({} bytes, backup kept as .rcu-bak)",
                    data.len()
                )
            } else {
                format!("create {path} ({} bytes)", data.len())
            }
        }
    };
    sanitize_for_display(&raw)
}

pub fn sanitize_for_display(text: &str) -> String {
    let mut out: String = text
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(300)
        .collect();
    if text.chars().count() > 300 {
        out.push('…');
    }
    out
}
