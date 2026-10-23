//! 명령 실행. 셸 없이 인자 배열로만 띄운다. 시간·출력·동시 실행 상한을 둔다.

use crate::ops::OpError;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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

/// 동시에 돌 수 있는 명령 수. 넘으면 `BUSY`.
pub const MAX_CONCURRENT: usize = 8;

static RUNNING: AtomicUsize = AtomicUsize::new(0);

struct Slot;

impl Slot {
    fn take() -> Option<Slot> {
        let mut cur = RUNNING.load(Ordering::SeqCst);
        loop {
            if cur >= MAX_CONCURRENT {
                return None;
            }
            match RUNNING.compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(Slot),
                Err(now) => cur = now,
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        RUNNING.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 읽은 만큼 공유 버퍼에 쌓는다. 손자 프로세스가 파이프를 잡고 있어 읽기가 끝나지 않아도 지금까지의 출력은 남는다.
struct Captured {
    data: Vec<u8>,
    truncated: bool,
    done: bool,
}

fn drain(mut reader: impl Read + Send + 'static, max: usize) -> Arc<Mutex<Captured>> {
    let shared = Arc::new(Mutex::new(Captured {
        data: Vec::new(),
        truncated: false,
        done: false,
    }));
    let out = Arc::clone(&shared);
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut cap = out.lock().unwrap();
                    let room = max.saturating_sub(cap.data.len());
                    if n > room {
                        cap.truncated = true;
                    }
                    cap.data.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
        out.lock().unwrap().done = true;
    });
    shared
}

/// 시간이 지나면 프로세스 그룹 전체를 죽인다(손자 프로세스가 남지 않게).
fn kill_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        // SAFETY: 자식은 process_group(0) 으로 자기 그룹의 리더다. 그 그룹에만 신호를 보낸다.
        unsafe {
            libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub fn run(
    program: &str,
    args: &[String],
    timeout: Duration,
    max_output: usize,
) -> Result<ExecOut, OpError> {
    let _slot = Slot::take().ok_or_else(|| {
        OpError::new(
            429,
            "BUSY",
            "too many commands are already running on this node",
        )
    })?;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    for key in ENV_ALLOW {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
    let mut child = cmd
        .spawn()
        .map_err(|_| OpError::new(422, "EXEC_FAILED", "could not start the program"))?;
    let out = drain(child.stdout.take().unwrap(), max_output);
    let err = drain(child.stderr.take().unwrap(), max_output);

    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if start.elapsed() >= timeout => {
                timed_out = true;
                kill_tree(&mut child);
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                kill_tree(&mut child);
                return Err(OpError::new(
                    500,
                    "EXEC_FAILED",
                    "could not wait for the program",
                ));
            }
        }
    };

    // 읽기 스레드가 끝나기를 최대 2초 기다린다. 손자 프로세스가 파이프를 잡고 있으면 지금까지 쌓인 출력만 쓴다.
    let grace = Instant::now();
    while grace.elapsed() < Duration::from_secs(2)
        && !(out.lock().unwrap().done && err.lock().unwrap().done)
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    let (stdout, t1) = {
        let c = out.lock().unwrap();
        (c.data.clone(), c.truncated)
    };
    let (stderr, t2) = {
        let c = err.lock().unwrap();
        (c.data.clone(), c.truncated)
    };
    Ok(ExecOut {
        exit_code: status.and_then(|s| s.code()),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated: t1 || t2,
        timed_out,
    })
}
