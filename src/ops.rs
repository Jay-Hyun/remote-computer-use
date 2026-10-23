//! 노드가 실행하는 작업: 계획(정책 검사·위험도), 실행, 오류 타입.

use crate::desktop::{self, Button, Desktop, SystemDesktop};
use crate::policy::{Access, Policy, PolicyError, Risk};
use crate::{exec, fsops};
use serde_json::{json, Value};
use std::path::Path;
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
    Screen,
    Click {
        x: i32,
        y: i32,
        button: Button,
    },
    Type {
        text: String,
    },
    Key {
        combo: String,
    },
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub capability: &'static str,
    pub risk: Risk,
    /// 감사 로그용(가림 처리 전).
    pub target: String,
    /// 승인 창에 그대로 보일 설명. 잘리지 않고, 보이지 않는 문자는 `\u{..}` 로 드러난다.
    pub summary: String,
}

/// 승인 창에 보일 설명의 최대 길이. 넘으면 요청을 받지 않는다(앞부분만 보고 승인하는 일을 막는다).
pub const MAX_SUMMARY_CHARS: usize = 600;

fn too_long() -> OpError {
    OpError::new(
        413,
        "TOO_LARGE",
        "request is too long to show for approval; use shorter arguments or paths",
    )
}

/// 정책 검사만 하고 실행하지 않는다. 위험도는 정책이 정한다.
pub fn plan(policy: &Policy, op: &Op) -> Result<Plan, OpError> {
    let plan = match op {
        Op::Exec { program, args } => {
            let risk = policy.check_command(program, args)?;
            let mut target = program.clone();
            for a in args {
                target.push(' ');
                target.push_str(a);
            }
            Plan {
                capability: "exec",
                risk,
                target,
                summary: describe(op, None, None),
            }
        }
        Op::Read { path } => {
            let resolved = policy.check_path(path, Access::Read)?;
            Plan {
                capability: "fs.read",
                risk: Risk::Read,
                target: path.clone(),
                summary: describe(op, Some(&resolved.path), Some(Risk::Read)),
            }
        }
        Op::Write {
            path,
            data,
            overwrite,
        } => {
            let (resolved, risk) = fsops::plan_write(policy, path, data.len(), *overwrite)?;
            Plan {
                capability: "fs.write",
                risk,
                target: path.clone(),
                summary: describe(op, Some(&resolved.path), Some(risk)),
            }
        }
        Op::Screen => {
            policy.check_screen()?;
            Plan {
                capability: "screen",
                // 캡처를 기간 승인으로 허용할지는 정책이 정한다. 아니면 매번 묻는 위험도로 취급한다.
                risk: if policy.screen_grant {
                    Risk::Read
                } else {
                    Risk::External
                },
                target: "screen capture".to_string(),
                summary: describe(op, None, None),
            }
        }
        Op::Click { x, y, button } => {
            policy.check_input()?;
            if !(0..=100_000).contains(x) || !(0..=100_000).contains(y) {
                return Err(OpError::new(
                    400,
                    "BAD_REQUEST",
                    "click coordinates are out of range",
                ));
            }
            Plan {
                capability: "input",
                risk: Risk::External,
                target: format!("click {x},{y} {}", button.as_str()),
                summary: describe(op, None, None),
            }
        }
        Op::Type { text } => {
            policy.check_input()?;
            desktop::check_typed_text(text, policy.input_max_text)
                .map_err(|m| OpError::new(400, "BAD_REQUEST", m))?;
            Plan {
                capability: "input",
                risk: Risk::External,
                // 감사 로그에는 입력한 글자 수만 남긴다(비밀번호일 수 있다).
                target: format!("type {} chars", text.chars().count()),
                summary: describe(op, None, None),
            }
        }
        Op::Key { combo } => {
            policy.check_input()?;
            let parsed = desktop::parse_combo(combo)
                .map_err(|_| OpError::new(400, "BAD_REQUEST", "unknown key or modifier"))?;
            Plan {
                capability: "input",
                risk: Risk::External,
                target: format!("key {}", parsed.display()),
                summary: describe(op, None, None),
            }
        }
    };
    if plan.summary.chars().count() > MAX_SUMMARY_CHARS {
        return Err(too_long());
    }
    Ok(plan)
}

/// 승인을 기다리는 동안 상황이 바뀌었을 수 있으므로 실행 직전에 다시 검사한다.
/// 다시 계산한 위험도가 승인받은 위험도보다 높으면(예: 승인 사이에 대상 파일이 생겨 "새 파일"이
/// "덮어쓰기"가 됨) 실행하지 않는다.
pub fn execute(policy: &Policy, op: &Op, approved: Risk) -> OpResult {
    execute_with(policy, &SystemDesktop, op, approved)
}

pub fn execute_with(policy: &Policy, desktop: &dyn Desktop, op: &Op, approved: Risk) -> OpResult {
    let now = plan(policy, op)?;
    if now.risk.rank() > approved.rank() {
        return Err(OpError::new(
            409,
            "STATE_CHANGED",
            "the target changed while the request was waiting; send it again",
        ));
    }
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
        Op::Screen => {
            let cap = desktop.capture(policy.screen_max_width)?;
            let (w, h) = desktop::png_size(&cap.png).unwrap_or((0, 0));
            Ok(json!({
                "png_b64": b64(&cap.png),
                "width": w,
                "height": h,
                "screen_width": cap.screen_width,
                "screen_height": cap.screen_height,
            }))
        }
        Op::Click { x, y, button } => {
            desktop.click(*x, *y, *button)?;
            Ok(json!({ "clicked": [x, y], "button": button.as_str() }))
        }
        Op::Type { text } => {
            desktop.type_text(text)?;
            Ok(json!({ "typed_chars": text.chars().count() }))
        }
        Op::Key { combo } => {
            let parsed = desktop::parse_combo(combo)
                .map_err(|_| OpError::new(400, "BAD_REQUEST", "unknown key or modifier"))?;
            desktop.key(&parsed)?;
            Ok(json!({ "key": parsed.display() }))
        }
    }
}

pub fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// 눈에 안 보이거나 줄 모양을 바꾸는 문자: 제어 문자, 방향 제어(bidi), 폭 없는 문자, 줄·문단 구분자, 태그 문자.
fn is_invisible(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}' | '\u{061C}' | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E007F}')
}

/// 따옴표로 감싸고 `\`·`"`·보이지 않는 문자를 이스케이프해 인자 경계와 실제 내용이 그대로 보이게 한다.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if is_invisible(c) => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn with_resolved(raw: &str, resolved: Option<&Path>) -> String {
    match resolved {
        Some(r) if r.to_string_lossy() != raw => {
            format!("{} -> {}", quote(raw), quote(&r.to_string_lossy()))
        }
        _ => quote(raw),
    }
}

fn describe(op: &Op, resolved: Option<&Path>, risk: Option<Risk>) -> String {
    match op {
        Op::Exec { program, args } => {
            let list: Vec<String> = args.iter().map(|a| quote(a)).collect();
            format!("run {} [{}]", quote(program), list.join(", "))
        }
        Op::Read { path } => format!("read {}", with_resolved(path, resolved)),
        Op::Screen => {
            "take a screenshot of the whole screen (the picture is sent to the controller)"
                .to_string()
        }
        Op::Click { x, y, button } => format!("mouse click ({x}, {y}), {} button", button.as_str()),
        Op::Type { text } => format!(
            "type {} characters on the keyboard: {}",
            text.chars().count(),
            quote(text)
        ),
        Op::Key { combo } => format!("press the key combination {}", quote(combo)),
        Op::Write {
            path,
            data,
            overwrite,
        } => {
            // 위험도를 아는 경우(계획 단계)에는 실제로 덮어쓰는지로 표시한다.
            let overwriting = match risk {
                Some(r) => r == Risk::Destructive,
                None => *overwrite,
            };
            if overwriting {
                format!(
                    "OVERWRITE {} ({} bytes, old content kept in a .rcu-bak file)",
                    with_resolved(path, resolved),
                    data.len()
                )
            } else {
                format!(
                    "create {} ({} bytes)",
                    with_resolved(path, resolved),
                    data.len()
                )
            }
        }
    }
}

/// 요청만으로 만든 설명(해석된 경로 없이). 시험·실패 요청 기록용.
pub fn summary(op: &Op) -> String {
    describe(op, None, None)
}

/// 최후의 안전망: 남은 제어 문자를 지우고 길이를 줄인다(감사 로그 등 잘려도 되는 곳 전용).
pub fn sanitize_for_display(text: &str) -> String {
    let mut out: String = text
        .chars()
        .map(|c| if is_invisible(c) { '?' } else { c })
        .take(300)
        .collect();
    if text.chars().count() > 300 {
        out.push('…');
    }
    out
}
