//! 파일 읽기·쓰기. 정책 검사 뒤 파일을 열고, 연 파일이 검사한 경로와 같은지 다시 확인한다
//! (검사와 열기 사이에 링크가 바뀌는 경쟁을 막는다). 확인이 끝나기 전에는 파일을 건드리지 않는다.

use crate::ops::OpError;
use crate::policy::{Access, Policy, ResolvedPath, Risk};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
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

#[cfg(windows)]
fn opened_path(file: &File) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };
    let handle = file.as_raw_handle();
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: handle 은 열려 있는 파일이고 buf 는 길이만큼의 쓰기 가능한 버퍼다.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if n == 0 {
            return None;
        }
        if n >= buf.len() {
            buf.resize(n + 1, 0);
            continue;
        }
        return Some(PathBuf::from(std::ffi::OsString::from_wide(&buf[..n])));
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn opened_path(_file: &File) -> Option<PathBuf> {
    None
}

/// 연 파일이 승인된 경로와 같은 파일인지. 확인 수단이 없으면(예: 리눅스에서 /proc 없음) 거부한다.
fn verify_opened(file: &File, expected: &Path) -> bool {
    match opened_path(file) {
        // 윈도우는 대소문자를 구분하지 않는다.
        Some(actual) if cfg!(windows) => actual
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy()),
        Some(actual) => actual == expected,
        None => !cfg!(any(target_os = "linux", target_os = "macos", windows)),
    }
}

/// 마지막 구성요소가 링크면 실패하게 열고, FIFO 같은 특수 파일에서 멈추지 않게 한다.
#[cfg(unix)]
fn safe_flags(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
}

#[cfg(not(unix))]
fn safe_flags(_opts: &mut OpenOptions) {}

/// 하드링크로 거부 패턴을 우회하는 것을 막는다: 링크가 둘 이상인 일반 파일은 건드리지 않는다.
#[cfg(unix)]
fn multiply_linked(_file: &File, meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.nlink() > 1
}

#[cfg(windows)]
fn multiply_linked(file: &File, _meta: &std::fs::Metadata) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    // SAFETY: 구조체는 0 으로 초기화한 뒤 OS 가 채운다. handle 은 열려 있는 파일이다.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    // 확인하지 못하면 안전한 쪽(여러 링크가 있다고 보고 거부)으로.
    ok == 0 || info.nNumberOfLinks > 1
}

#[cfg(not(any(unix, windows)))]
fn multiply_linked(_file: &File, _meta: &std::fs::Metadata) -> bool {
    false
}

/// 일반 파일인지 먼저 확인한다(FIFO·장치 파일을 열다가 멈추는 것을 피한다).
fn require_regular(path: &Path) -> Result<(), OpError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| io_err())?;
    if !meta.is_file() {
        return Err(OpError::new(
            400,
            "NOT_A_FILE",
            "path is not a regular file",
        ));
    }
    Ok(())
}

pub fn read(policy: &Policy, raw: &str) -> Result<ReadOut, OpError> {
    let resolved = policy.check_path(raw, Access::Read)?;
    require_regular(&resolved.path)?;
    let mut opts = OpenOptions::new();
    opts.read(true);
    safe_flags(&mut opts);
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
    if multiply_linked(&file, &meta) {
        return Err(denied());
    }
    if meta.len() > policy.max_read_bytes {
        return Err(too_large_read());
    }
    let mut data = Vec::new();
    (&mut file)
        .take(policy.max_read_bytes + 1)
        .read_to_end(&mut data)
        .map_err(|_| io_err())?;
    if data.len() as u64 > policy.max_read_bytes {
        return Err(too_large_read());
    }
    Ok(ReadOut { data })
}

fn too_large_read() -> OpError {
    OpError::new(
        413,
        "TOO_LARGE",
        "file is larger than the node's read limit",
    )
}

/// 쓰기 계획: 새 파일이면 write, 있는 파일을 덮어쓰면 destructive(항상 승인).
pub fn plan_write(
    policy: &Policy,
    raw: &str,
    len: usize,
    overwrite: bool,
) -> Result<(ResolvedPath, Risk), OpError> {
    let resolved = policy.check_path(raw, Access::Write)?;
    if len as u64 > policy.max_write_bytes {
        return Err(OpError::new(
            413,
            "TOO_LARGE",
            "content is larger than the node's write limit",
        ));
    }
    if resolved.existed {
        require_regular(&resolved.path)?;
        if !overwrite {
            return Err(exists());
        }
        Ok((resolved, Risk::Destructive))
    } else {
        Ok((resolved, Risk::Write))
    }
}

fn exists() -> OpError {
    OpError::new(
        409,
        "EXISTS",
        "file exists; overwriting needs --overwrite and node approval",
    )
}

fn backup_candidates(path: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    (0..100).map(move |n| {
        let mut name = path.as_os_str().to_os_string();
        name.push(if n == 0 {
            ".rcu-bak".to_string()
        } else {
            format!(".rcu-bak.{n}")
        });
        PathBuf::from(name)
    })
}

/// 열려 있고 검증된 원본 내용을 새 백업 파일로 복사한다. 이미 있는 백업이나 링크는 건드리지 않고
/// 다음 번호를 쓴다(`create_new` + `O_NOFOLLOW`).
fn make_backup(original: &mut File, path: &Path, limit: u64) -> Result<String, OpError> {
    let mut content = Vec::new();
    original
        .take(limit + 1)
        .read_to_end(&mut content)
        .map_err(|_| io_err())?;
    if content.len() as u64 > limit {
        return Err(OpError::new(
            413,
            "TOO_LARGE",
            "file is too large to back up before overwriting",
        ));
    }
    for candidate in backup_candidates(path) {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        safe_flags(&mut opts);
        match opts.open(&candidate) {
            Ok(mut bak) => {
                bak.write_all(&content).map_err(|_| io_err())?;
                bak.sync_all().map_err(|_| io_err())?;
                return Ok(candidate
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(io_err()),
        }
    }
    Err(OpError::new(
        409,
        "EXISTS",
        "too many backup files already exist next to the target",
    ))
}

pub fn write(
    policy: &Policy,
    raw: &str,
    data: &[u8],
    overwrite: bool,
) -> Result<WriteOut, OpError> {
    let (resolved, risk) = plan_write(policy, raw, data.len(), overwrite)?;
    let overwrote = risk == Risk::Destructive;

    let mut opts = OpenOptions::new();
    opts.write(true);
    safe_flags(&mut opts);
    if overwrote {
        // 열기만 한다(자르지 않는다). 검증과 백업이 끝난 뒤에야 내용을 지운다.
        opts.read(true);
    } else {
        opts.create_new(true);
    }
    let mut file = opts.open(&resolved.path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            exists()
        } else {
            io_err()
        }
    })?;

    if !verify_opened(&file, &resolved.path) {
        // 방금 우리가 만든 파일이면 치운다. 덮어쓰기에서는 아직 아무것도 건드리지 않았다.
        if !overwrote {
            if let Some(actual) = opened_path(&file) {
                let _ = std::fs::remove_file(actual);
            }
        }
        return Err(denied());
    }

    let mut backup = None;
    if overwrote {
        let meta = file.metadata().map_err(|_| io_err())?;
        if !meta.is_file() {
            return Err(OpError::new(
                400,
                "NOT_A_FILE",
                "path is not a regular file",
            ));
        }
        if multiply_linked(&file, &meta) {
            return Err(denied());
        }
        backup = Some(make_backup(
            &mut file,
            &resolved.path,
            policy.max_read_bytes.max(policy.max_write_bytes),
        )?);
        file.set_len(0).map_err(|_| io_err())?;
        file.rewind().map_err(|_| io_err())?;
    }
    file.write_all(data).map_err(|_| io_err())?;
    file.sync_all().map_err(|_| io_err())?;
    Ok(WriteOut {
        bytes: data.len(),
        overwrote,
        backup,
    })
}
