//! 파일 읽기·쓰기. 정책 검사 뒤 파일을 열고, 연 파일이 검사한 경로와 같은지 다시 확인한다
//! (검사와 열기 사이에 링크가 바뀌는 경쟁을 막는다).

use crate::ops::OpError;
use crate::policy::{Access, Policy, Risk};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub struct ReadOut {
    pub data: Vec<u8>,
}

pub struct WriteOut {
    pub bytes: usize,
    pub overwrote: bool,
    pub backup: Option<String>,
}

fn denied() -> OpError {
    OpError::new(403, "PATH_DENIED", "path is outside the allowed roots")
}

fn io_err() -> OpError {
    OpError::new(500, "IO_ERROR", "file operation failed")
}

/// 열린 파일이 실제로 가리키는 경로. 알 수 없는 OS 에서는 None.
#[cfg(target_os = "linux")]
fn opened_path(file: &File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
}

#[cfg(target_os = "macos")]
fn opened_path(file: &File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: buf 는 PATH_MAX 바이트이고 F_GETPATH 는 그 안에 NUL 로 끝나는 경로를 쓴다.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc == -1 {
        return None;
    }
    let len = buf.iter().position(|&b| b == 0)?;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len])))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn opened_path(_file: &File) -> Option<PathBuf> {
    None
}

/// 연 파일이 승인된 경로와 같은 파일인지. 확인 수단이 없는 OS(윈도우, M4 예정)에서는 통과시킨다.
fn verify_opened(file: &File, expected: &Path) -> bool {
    match opened_path(file) {
        Some(actual) => actual == expected,
        None => true,
    }
}

#[cfg(unix)]
fn no_follow(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn no_follow(_opts: &mut OpenOptions) {}

pub fn read(policy: &Policy, raw: &str) -> Result<ReadOut, OpError> {
    let resolved = policy.check_path(raw, Access::Read)?;
    let mut opts = OpenOptions::new();
    opts.read(true);
    no_follow(&mut opts);
    let mut file = opts.open(&resolved.path).map_err(|_| io_err())?;
    if !verify_opened(&file, &resolved.path) {
        return Err(denied());
    }
    let meta = file.metadata().map_err(|_| io_err())?;
    if !meta.is_file() {
        return Err(OpError::new(
            400,
            "NOT_A_FILE",
            "path is not a regular file",
        ));
    }
    if meta.len() > policy.max_read_bytes {
        return Err(OpError::new(
            413,
            "TOO_LARGE",
            "file is larger than the node's read limit",
        ));
    }
    let mut data = Vec::new();
    (&mut file)
        .take(policy.max_read_bytes + 1)
        .read_to_end(&mut data)
        .map_err(|_| io_err())?;
    if data.len() as u64 > policy.max_read_bytes {
        return Err(OpError::new(
            413,
            "TOO_LARGE",
            "file is larger than the node's read limit",
        ));
    }
    Ok(ReadOut { data })
}

/// 쓰기 계획: 새 파일이면 write, 있는 파일을 덮어쓰면 destructive(항상 승인).
pub fn plan_write(
    policy: &Policy,
    raw: &str,
    len: usize,
    overwrite: bool,
) -> Result<(crate::policy::ResolvedPath, Risk), OpError> {
    let resolved = policy.check_path(raw, Access::Write)?;
    if len as u64 > policy.max_write_bytes {
        return Err(OpError::new(
            413,
            "TOO_LARGE",
            "content is larger than the node's write limit",
        ));
    }
    if resolved.existed {
        let meta = std::fs::metadata(&resolved.path).map_err(|_| io_err())?;
        if !meta.is_file() {
            return Err(OpError::new(
                400,
                "NOT_A_FILE",
                "path is not a regular file",
            ));
        }
        if !overwrite {
            return Err(OpError::new(
                409,
                "EXISTS",
                "file exists; overwriting needs --overwrite and node approval",
            ));
        }
        Ok((resolved, Risk::Destructive))
    } else {
        Ok((resolved, Risk::Write))
    }
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".rcu-bak");
    PathBuf::from(name)
}

pub fn write(
    policy: &Policy,
    raw: &str,
    data: &[u8],
    overwrite: bool,
) -> Result<WriteOut, OpError> {
    let (resolved, risk) = plan_write(policy, raw, data.len(), overwrite)?;
    let overwrote = risk == Risk::Destructive;

    let mut backup = None;
    let mut opts = OpenOptions::new();
    opts.write(true);
    no_follow(&mut opts);
    if overwrote {
        let bak = backup_path(&resolved.path);
        std::fs::copy(&resolved.path, &bak).map_err(|_| io_err())?;
        backup = bak.file_name().map(|n| n.to_string_lossy().into_owned());
        opts.truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut file = opts.open(&resolved.path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            OpError::new(
                409,
                "EXISTS",
                "file exists; overwriting needs --overwrite and node approval",
            )
        } else {
            io_err()
        }
    })?;
    if !verify_opened(&file, &resolved.path) {
        // 방금 우리가 만든 파일이면 치운다. 덮어쓰기였다면 아직 아무것도 쓰지 않았다.
        if !overwrote {
            if let Some(actual) = opened_path(&file) {
                let _ = std::fs::remove_file(actual);
            }
        }
        return Err(denied());
    }
    file.write_all(data).map_err(|_| io_err())?;
    file.sync_all().map_err(|_| io_err())?;
    Ok(WriteOut {
        bytes: data.len(),
        overwrote,
        backup,
    })
}
