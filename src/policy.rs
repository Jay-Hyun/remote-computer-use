//! 노드 정책. 기본은 거부이고, 정책 파일에 적힌 것만 허용한다.

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
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
    pub fn as_str(self) -> &'static str {
        match self {
            Risk::Read => "read",
            Risk::Write => "write",
            Risk::Destructive => "destructive",
            Risk::External => "external",
        }
    }

    /// 그랜트가 있어도 매번 노드 쪽 승인이 필요한 위험도.
    /// 위험도 순서: 승인받은 것보다 높은 위험도로 바뀐 요청은 실행하지 않는다.
    pub fn rank(self) -> u8 {
        match self {
            Risk::Read => 0,
            Risk::Write => 1,
            Risk::Destructive => 2,
            Risk::External => 3,
        }
    }

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

/// 승인을 어디서 받을지. 터미널 프롬프트는 항상 켜져 있고, 이 값은 OS 대화상자 여부만 정한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalUi {
    /// 대화상자를 쓸 수 있는 환경이면 쓴다(맥·윈도우, 디스플레이와 zenity 가 있는 리눅스).
    Auto,
    /// 대화상자 없이 터미널만.
    Terminal,
    /// 대화상자 필수. 쓸 수 없으면 `rcu serve` 가 시작하지 않는다.
    Dialog,
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
    limits: RawLimits,
    approval: RawApproval,
    screen: RawScreen,
    input: RawInput,
    auth: RawAuth,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct RawAuth {
    /// 0 이면 토큰이 만료되지 않는다.
    token_days: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct RawScreen {
    max_width: u32,
    /// true 면 캡처도 기간 승인(그랜트)이 가능하다. 기본은 매번 묻는다(화면에는 비밀이 있을 수 있다).
    grant: bool,
}

impl Default for RawScreen {
    fn default() -> Self {
        RawScreen {
            max_width: 1280,
            grant: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct RawInput {
    max_text: usize,
}

impl Default for RawInput {
    fn default() -> Self {
        RawInput { max_text: 500 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct RawLimits {
    per_minute: u32,
    per_day: u32,
    input_per_minute: u32,
}

impl Default for RawLimits {
    fn default() -> Self {
        RawLimits {
            per_minute: 60,
            per_day: 2000,
            input_per_minute: 20,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct RawApproval {
    grant_minutes: u64,
    http_wait_secs: u64,
    ui: String,
}

impl Default for RawApproval {
    fn default() -> Self {
        RawApproval {
            grant_minutes: 60,
            http_wait_secs: 60,
            ui: "auto".to_string(),
        }
    }
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
    screen: bool,
    input: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct RawFs {
    roots: Vec<String>,
    deny: Vec<String>,
    max_read_bytes: u64,
    max_write_bytes: u64,
}

impl Default for RawFs {
    fn default() -> Self {
        RawFs {
            roots: Vec::new(),
            deny: Vec::new(),
            max_read_bytes: 1024 * 1024,
            max_write_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct RawExec {
    allow: Vec<RawExecAllow>,
    timeout_secs: u64,
    max_output_bytes: usize,
}

impl Default for RawExec {
    fn default() -> Self {
        RawExec {
            allow: Vec::new(),
            timeout_secs: 30,
            max_output_bytes: 64 * 1024,
        }
    }
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
    pub max_write_bytes: u64,
    pub exec_timeout_secs: u64,
    pub exec_max_output_bytes: usize,
    pub rate_per_minute: u32,
    pub daily_cap: u32,
    pub input_per_minute: u32,
    pub token_days: u32,
    pub screen_enabled: bool,
    pub input_enabled: bool,
    /// 캡처가 이미지 폭을 이 값으로 줄여 돌려준다.
    pub screen_max_width: u32,
    pub screen_grant: bool,
    pub input_max_text: usize,
    pub grant_minutes: u64,
    /// 한 HTTP 요청이 승인을 기다리는 시간. 넘기면 202 + approval_id.
    pub http_wait_secs: u64,
    pub approval_ui: ApprovalUi,
    roots: Vec<PathBuf>,
    deny: GlobSet,
    protected: Vec<PathBuf>,
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
    "busybox",
    "toybox",
    "rbash",
    "mksh",
    "tclsh",
    "expect",
    "wsl",
    "rundll32",
    "msiexec",
];

/// 다른 프로그램을 대신 실행해 허용 목록을 우회할 수 있는 래퍼.
const WRAPPERS: &[&str] = &[
    "env", "xargs", "sudo", "doas", "su", "runas", "nohup", "nice", "start", "timeout", "time",
    "stdbuf", "setsid", "chroot", "nsenter", "unshare", "flock", "watch", "script", "strace",
    "ltrace", "gdb", "ionice", "taskset", "command", "exec",
];

/// 허용 목록에 `*`/`**` 인자와 함께 넣으면 사실상 셸이 되는 프로그램(막지는 않고 경고한다).
const INTERPRETER_PREFIXES: &[&str] = &[
    "python", "perl", "ruby", "node", "php", "lua", "awk", "gawk", "find", "tar", "less", "vi",
    "vim", "nano", "ssh", "scp", "rsync", "git", "make", "npm", "pip", "cargo",
];

/// 정책 파일에 없어도 항상 거부하는 위치: 비밀 파일과 로그인 때 자동 실행되는 파일.
/// 허용 루트가 홈 전체여도 여기에는 읽기·쓰기 모두 막힌다.
const BUILTIN_DENY: &[&str] = &[
    "**/.ssh/**",
    "**/.gnupg/**",
    "**/.aws/**",
    "**/.env",
    "**/.netrc",
    "**/.bashrc",
    "**/.bash_profile",
    "**/.bash_login",
    "**/.profile",
    "**/.zshrc",
    "**/.zshenv",
    "**/.zprofile",
    "**/.zlogin",
    "**/.config/autostart/**",
    "**/.config/systemd/**",
    "**/Library/LaunchAgents/**",
    "**/Library/LaunchDaemons/**",
    "**/Start Menu/**",
    "**/Startup/**",
];

fn base_name(program: &str) -> String {
    // 윈도우는 끝의 점·공백을 무시하므로 `cmd.exe.` 도 cmd.exe 로 본다.
    let name = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .trim_end_matches(['.', ' '])
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
    name.ends_with(".bat")
        || name.ends_with(".cmd")
        || name.ends_with(".ps1")
        || SHELLS.contains(&name.as_str())
}

fn is_wrapper(program: &str) -> bool {
    WRAPPERS.contains(&base_name(program).as_str())
}

fn is_absolute_program(program: &str) -> bool {
    let b = program.as_bytes();
    // 윈도우 드라이브(`C:\`, `C:/`)와 UNC(`\\서버\`)는 윈도우에서만 절대 경로로 본다.
    let windows_form = cfg!(windows)
        && ((b.len() > 2
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && (b[2] == b'\\' || b[2] == b'/'))
            || program.starts_with("\\\\"));
    Path::new(program).is_absolute() || windows_form
}

/// 읽기·쓰기 크기 상한의 상한(메모리에 통째로 올리므로).
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// `/a/link/secret/**` 처럼 글롭 문자가 나오기 전까지의 앞부분을 실제 경로로 바꾼 패턴. 같으면 None.
fn canonical_prefix_variant(pat: &str) -> Option<String> {
    let cut = pat.find(['*', '?', '[', '{']).unwrap_or(pat.len());
    let prefix = &pat[..cut];
    let dir_end = prefix.rfind('/')?;
    let (dir, rest) = (&pat[..dir_end], &pat[dir_end..]);
    if dir.is_empty() {
        return None;
    }
    let real = std::fs::canonicalize(dir).ok()?;
    let real = real.to_string_lossy().replace('\\', "/");
    (real != dir).then(|| format!("{real}{rest}"))
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
        let mut add_glob = |pat: &str| -> anyhow::Result<()> {
            // 대소문자 구분 없이: 맥·윈도우의 기본 파일 시스템은 `.ENV` 와 `.env` 를 같은 파일로 본다.
            builder.add(GlobBuilder::new(pat).case_insensitive(true).build()?);
            Ok(())
        };
        for pat in BUILTIN_DENY {
            add_glob(pat)?;
        }
        for pat in &raw.fs.deny {
            let pat = expand_home(pat).replace('\\', "/");
            if pat.starts_with('~') {
                anyhow::bail!("fs.deny: cannot expand ~ in \"{pat}\"");
            }
            let absolute = pat.starts_with('/')
                || pat.starts_with("**")
                || pat.starts_with('*')
                || (pat.len() > 2 && pat.as_bytes()[1] == b':');
            if !absolute {
                anyhow::bail!("fs.deny: pattern \"{pat}\" must be absolute or start with **/ (relative patterns never match)");
            }
            add_glob(&pat)?;
            // 패턴 앞부분이 심볼릭 링크를 거치면 실제 경로로도 한 번 더 건다.
            if let Some(real) = canonical_prefix_variant(&pat) {
                add_glob(&real)?;
            }
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
            max_read_bytes: raw.fs.max_read_bytes.min(MAX_FILE_BYTES),
            max_write_bytes: raw.fs.max_write_bytes.min(MAX_FILE_BYTES),
            exec_timeout_secs: raw.exec.timeout_secs.clamp(1, 600),
            exec_max_output_bytes: raw.exec.max_output_bytes.clamp(1024, 4 * 1024 * 1024),
            rate_per_minute: raw.limits.per_minute.max(1),
            daily_cap: raw.limits.per_day.max(1),
            input_per_minute: raw.limits.input_per_minute.max(1),
            token_days: raw.auth.token_days.min(3650),
            screen_enabled: raw.capabilities.screen,
            input_enabled: raw.capabilities.input,
            screen_max_width: raw.screen.max_width.clamp(320, 7680),
            screen_grant: raw.screen.grant,
            input_max_text: raw.input.max_text.clamp(1, 5000),
            grant_minutes: raw.approval.grant_minutes.clamp(1, 24 * 60),
            http_wait_secs: raw.approval.http_wait_secs.clamp(1, 120),
            approval_ui: match raw.approval.ui.as_str() {
                "auto" => ApprovalUi::Auto,
                "terminal" => ApprovalUi::Terminal,
                "dialog" => ApprovalUi::Dialog,
                _ => anyhow::bail!("approval.ui must be \"auto\", \"terminal\" or \"dialog\""),
            },
            roots,
            deny: builder.build()?,
            protected: Vec::new(),
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
        if self.screen_enabled {
            caps.push("screen");
        }
        if self.input_enabled {
            caps.push("input");
        }
        caps
    }

    pub fn check_screen(&self) -> Result<(), PolicyError> {
        if self.screen_enabled {
            Ok(())
        } else {
            Err(deny(
                Code::CapabilityOff,
                "screen capture is off on this node",
            ))
        }
    }

    pub fn check_input(&self) -> Result<(), PolicyError> {
        if self.input_enabled {
            Ok(())
        } else {
            Err(deny(Code::CapabilityOff, "input is off on this node"))
        }
    }

    /// 노드 자신의 설정·상태 위치(정책, 토큰 해시, 감사 로그, 페어링 파일)는 허용 루트가 덮고 있어도
    /// 파일 능력으로 건드릴 수 없게 한다.
    pub fn protect(&mut self, path: PathBuf) {
        self.protected.push(path);
    }

    /// 정책 파일을 읽은 사람이 놓치기 쉬운 위험 설정. 막지는 않고 알려 준다.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        let roots: Vec<PathBuf> = self
            .roots
            .iter()
            .filter_map(|r| std::fs::canonicalize(r).ok())
            .collect();
        for entry in &self.exec_allow {
            let name = base_name(&entry.program);
            let open_args = entry.args.iter().any(|a| a == "*" || a == "**");
            if open_args && INTERPRETER_PREFIXES.iter().any(|p| name.starts_with(p)) {
                out.push(format!(
                    "exec.allow {}: `*`/`**` arguments on a program that can run other programs or touch any file make it as powerful as a shell; narrow the args",
                    entry.program
                ));
            }
            if let Ok(real) = std::fs::canonicalize(&entry.program) {
                if roots.iter().any(|root| real.starts_with(root)) {
                    out.push(format!(
                        "exec.allow {}: the program lives inside fs.roots, so file write approval could replace it",
                        entry.program
                    ));
                }
            }
        }
        if !self.exec_allow.is_empty() {
            out.push(
                "exec arguments are not checked against fs.roots/deny: an allowed program can read or write anywhere its user can".to_string(),
            );
        }
        for root in &roots {
            if root.parent().is_none() {
                out.push(format!(
                    "fs.roots contains the filesystem root ({})",
                    root.display()
                ));
            }
        }
        out
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
        // 윈도우의 `\\?\` 접두어는 패턴 비교 전에 뗀다.
        let normalized = normalized.strip_prefix("//?/").unwrap_or(&normalized);
        if self.deny.is_match(normalized) {
            return Err(denied());
        }
        if self.protected.iter().any(|p| {
            std::fs::canonicalize(p)
                .map(|p| resolved.starts_with(&p))
                .unwrap_or(false)
        }) {
            return Err(denied());
        }

        Ok(ResolvedPath {
            path: resolved,
            existed,
        })
    }
}
