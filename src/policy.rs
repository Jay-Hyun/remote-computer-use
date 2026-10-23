//! 노드 정책. 기본은 거부이고, 정책 파일에 적힌 것만 허용한다.

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Read,
    Write,
    Destructive,
    External,
}

impl Risk {
    /// 그랜트가 있어도 매번 노드 쪽 승인이 필요한 위험도.
    pub fn always_needs_approval(self) -> bool {
        matches!(self, Risk::Destructive | Risk::External)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    CapabilityOff,
    PathDenied,
    CommandDenied,
    ShellDenied,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::CapabilityOff => "CAPABILITY_OFF",
            Code::PathDenied => "PATH_DENIED",
            Code::CommandDenied => "COMMAND_DENIED",
            Code::ShellDenied => "SHELL_DENIED",
        }
    }
}

/// 오류 문장에는 경로 전체나 비밀값을 넣지 않는다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub code: Code,
    pub message: &'static str,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for PolicyError {}

fn deny(code: Code, message: &'static str) -> PolicyError {
    PolicyError { code, message }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    pub path: PathBuf,
    /// 쓰기 대상이 이미 있으면 true. 덮어쓰기는 destructive 승인 대상이다.
    pub existed: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct RawPolicy {
    node: RawNode,
    capabilities: RawCaps,
    fs: RawFs,
    exec: RawExec,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct RawNode {
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct RawCaps {
    exec: bool,
    fs_read: bool,
    fs_write: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct RawFs {
    roots: Vec<String>,
    deny: Vec<String>,
    max_read_bytes: u64,
}

impl Default for RawFs {
    fn default() -> Self {
        RawFs {
            roots: Vec::new(),
            deny: Vec::new(),
            max_read_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct RawExec {
    allow: Vec<RawExecAllow>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawExecAllow {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    risk: Risk,
}

#[derive(Debug, Clone)]
struct ExecAllow {
    program: String,
    args: Vec<String>,
    risk: Risk,
}

#[derive(Debug)]
pub struct Policy {
    pub node_name: String,
    pub exec_enabled: bool,
    pub fs_read_enabled: bool,
    pub fs_write_enabled: bool,
    pub max_read_bytes: u64,
    roots: Vec<PathBuf>,
    deny: GlobSet,
    exec_allow: Vec<ExecAllow>,
}

/// 항상 거부하는 셸·스크립트 호스트. 문자열 실행 경로를 막는다.
const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "ash",
    "cmd",
    "powershell",
    "pwsh",
    "osascript",
    "wscript",
    "cscript",
    "mshta",
];

/// 다른 프로그램을 대신 실행해 허용 목록을 우회할 수 있는 래퍼.
const WRAPPERS: &[&str] = &[
    "env", "xargs", "sudo", "doas", "su", "runas", "nohup", "nice", "start",
];

fn base_name(program: &str) -> String {
    let name = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase();
    for ext in [".exe", ".com", ".bat", ".cmd"] {
        if let Some(stem) = name.strip_suffix(ext) {
            // cmd.exe 는 stem 이 cmd. .cmd 파일 자체는 셸 스크립트라 아래에서 따로 거부.
            if ext == ".bat" || ext == ".cmd" {
                return name;
            }
            return stem.to_string();
        }
    }
    name
}

pub fn is_shell(program: &str) -> bool {
    let name = base_name(program);
    name.ends_with(".bat") || name.ends_with(".cmd") || SHELLS.contains(&name.as_str())
}

fn is_wrapper(program: &str) -> bool {
    WRAPPERS.contains(&base_name(program).as_str())
}

fn is_absolute_program(program: &str) -> bool {
    Path::new(program).is_absolute() || (program.len() > 2 && program.as_bytes()[1] == b':')
}

fn expand_home(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) {
        if let Some(base) = directories::BaseDirs::new() {
            return base.home_dir().join(rest).to_string_lossy().into_owned();
        }
    }
    s.to_string()
}

fn match_args(patterns: &[String], args: &[String]) -> bool {
    for (i, pat) in patterns.iter().enumerate() {
        if pat == "**" {
            return i == patterns.len() - 1;
        }
        match args.get(i) {
            Some(arg) if pat == "*" || pat == arg => {}
            _ => return false,
        }
    }
    patterns.len() == args.len()
}

impl Policy {
    /// 정책 파일이 없으면 모든 능력이 꺼진 기본 정책을 쓴다.
    pub fn load(path: &Path) -> anyhow::Result<Policy> {
        match std::fs::read_to_string(path) {
            Ok(text) => Policy::parse(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Policy::parse(""),
            Err(e) => Err(anyhow::anyhow!("policy read failed: {e}")),
        }
    }

    pub fn parse(text: &str) -> anyhow::Result<Policy> {
        let raw: RawPolicy = toml::from_str(text)?;

        let mut exec_allow = Vec::new();
        for entry in raw.exec.allow {
            if is_shell(&entry.program) {
                anyhow::bail!("exec.allow: shell programs are never allowed");
            }
            if is_wrapper(&entry.program) {
                anyhow::bail!("exec.allow: wrapper programs (env, sudo, ...) are not allowed");
            }
            if !is_absolute_program(&entry.program) {
                anyhow::bail!("exec.allow: program must be an absolute path");
            }
            if let Some(pos) = entry.args.iter().position(|a| a == "**") {
                if pos != entry.args.len() - 1 {
                    anyhow::bail!("exec.allow: \"**\" is only allowed as the last arg pattern");
                }
            }
            exec_allow.push(ExecAllow {
                program: entry.program,
                args: entry.args,
                risk: entry.risk,
            });
        }

        let mut builder = GlobSetBuilder::new();
        for pat in &raw.fs.deny {
            let pat = expand_home(pat).replace('\\', "/");
            builder.add(Glob::new(&pat)?);
        }

        let roots = raw
            .fs
            .roots
            .iter()
            .map(|r| PathBuf::from(expand_home(r)))
            .collect();

        let node_name = raw
            .node
            .name
            .or_else(|| std::env::var("HOSTNAME").ok())
            .or_else(|| std::env::var("COMPUTERNAME").ok())
            .unwrap_or_else(|| "node".to_string());

        Ok(Policy {
            node_name,
            exec_enabled: raw.capabilities.exec,
            fs_read_enabled: raw.capabilities.fs_read,
            fs_write_enabled: raw.capabilities.fs_write,
            max_read_bytes: raw.fs.max_read_bytes,
            roots,
            deny: builder.build()?,
            exec_allow,
        })
    }

    /// 노드가 켜 둔 능력 이름. `info` 는 항상 켜져 있다.
    pub fn capabilities(&self) -> Vec<&'static str> {
        let mut caps = vec!["info"];
        if self.exec_enabled {
            caps.push("exec");
        }
        if self.fs_read_enabled {
            caps.push("fs.read");
        }
        if self.fs_write_enabled {
            caps.push("fs.write");
        }
        caps
    }

    pub fn check_command(&self, program: &str, args: &[String]) -> Result<Risk, PolicyError> {
        if !self.exec_enabled {
            return Err(deny(Code::CapabilityOff, "exec is off on this node"));
        }
        if is_shell(program) {
            return Err(deny(Code::ShellDenied, "shell execution is not allowed"));
        }
        if is_wrapper(program) {
            return Err(deny(
                Code::CommandDenied,
                "command is not in the allow list",
            ));
        }
        // 심볼릭 링크가 셸을 가리키는 경우도 거부한다.
        if let Ok(real) = std::fs::canonicalize(program) {
            let real = real.to_string_lossy();
            if is_shell(&real) {
                return Err(deny(Code::ShellDenied, "shell execution is not allowed"));
            }
        }
        self.exec_allow
            .iter()
            .find(|e| e.program == program && match_args(&e.args, args))
            .map(|e| e.risk)
            .ok_or_else(|| deny(Code::CommandDenied, "command is not in the allow list"))
    }

    pub fn check_path(&self, raw: &str, access: Access) -> Result<ResolvedPath, PolicyError> {
        let enabled = match access {
            Access::Read => self.fs_read_enabled,
            Access::Write => self.fs_write_enabled,
        };
        if !enabled {
            return Err(deny(Code::CapabilityOff, "file access is off on this node"));
        }
        let denied = || deny(Code::PathDenied, "path is outside the allowed roots");

        let path = Path::new(raw);
        if raw.is_empty() || !path.is_absolute() {
            return Err(denied());
        }
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(denied());
        }

        let (resolved, existed) = match std::fs::canonicalize(path) {
            Ok(p) => (p, true),
            Err(_) if access == Access::Write => {
                let parent = path.parent().ok_or_else(denied)?;
                let name = path.file_name().ok_or_else(denied)?;
                let parent = std::fs::canonicalize(parent).map_err(|_| denied())?;
                (parent.join(name), false)
            }
            Err(_) => return Err(denied()),
        };

        let in_root = self.roots.iter().any(|root| {
            std::fs::canonicalize(root)
                .map(|root| resolved.starts_with(root))
                .unwrap_or(false)
        });
        if !in_root {
            return Err(denied());
        }

        let normalized = resolved.to_string_lossy().replace('\\', "/");
        if self.deny.is_match(normalized.as_str()) {
            return Err(denied());
        }

        Ok(ResolvedPath {
            path: resolved,
            existed,
        })
    }
}
