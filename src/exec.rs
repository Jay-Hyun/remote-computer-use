//! 명령 실행. 셸 없이 인자 배열로만 띄운다. 시간·출력 상한을 둔다.

use crate::ops::OpError;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct ExecOut {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
}

/// 자식 프로세스에 넘기는 환경 변수. 노드 사용자의 나머지 환경(토큰 등)은 넘기지 않는다.
const ENV_ALLOW: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
];

fn drain(mut reader: impl Read + Send + 'static, max: usize) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut truncated = false;
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = max.saturating_sub(out.len());
                    if n > room {
                        truncated = true;
                    }
                    out.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
        let _ = tx.send((out, truncated));
    });
    rx
}

pub fn run(
    program: &str,
    args: &[String],
    timeout: Duration,
    max_output: usize,
) -> Result<ExecOut, OpError> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in ENV_ALLOW {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
    let mut child = cmd
        .spawn()
        .map_err(|_| OpError::new(422, "EXEC_FAILED", "could not start the program"))?;
    let out_rx = drain(child.stdout.take().unwrap(), max_output);
    let err_rx = drain(child.stderr.take().unwrap(), max_output);

    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if start.elapsed() >= timeout => {
                timed_out = true;
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                return Err(OpError::new(
                    500,
                    "EXEC_FAILED",
                    "could not wait for the program",
                ))
            }
        }
    };

    // 손자 프로세스가 파이프를 잡고 있으면 읽기가 끝나지 않으므로 오래 기다리지 않는다.
    let grace = Duration::from_secs(2);
    let (stdout, t1) = out_rx.recv_timeout(grace).unwrap_or((Vec::new(), false));
    let (stderr, t2) = err_rx.recv_timeout(grace).unwrap_or((Vec::new(), false));
    Ok(ExecOut {
        exit_code: status.and_then(|s| s.code()),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated: t1 || t2,
        timed_out,
    })
}
