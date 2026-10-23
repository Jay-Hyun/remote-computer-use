//! 설정·상태 파일 위치와 컨트롤러의 노드 목록.
//!
//! 기준 디렉터리: `RCU_HOME` 이 있으면 그것, 없으면 OS 설정 디렉터리 아래 `rcu`.
//! (맥 `~/Library/Application Support/rcu`, 리눅스 `~/.config/rcu`,
//!  윈도우 `%APPDATA%\rcu\config`)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub fn home_dir() -> anyhow::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("RCU_HOME") {
        return Ok(PathBuf::from(dir));
    }
    directories::ProjectDirs::from("", "", "rcu")
        .map(|d| d.config_dir().to_path_buf())
        .ok_or_else(|| anyhow::anyhow!("cannot determine config directory; set RCU_HOME"))
}

pub fn policy_path() -> anyhow::Result<PathBuf> {
    Ok(home_dir()?.join("policy.toml"))
}

pub fn tokens_path() -> anyhow::Result<PathBuf> {
    Ok(home_dir()?.join("state").join("tokens.json"))
}

pub fn state_dir() -> anyhow::Result<PathBuf> {
    Ok(home_dir()?.join("state"))
}

/// `rcu pair-code` 가 실행 중인 노드에 새 코드를 요청하는 표식 파일.
pub fn pair_request_path() -> anyhow::Result<PathBuf> {
    Ok(state_dir()?.join("pair-request"))
}

/// 노드가 새 코드를 적어 주는 파일(읽은 쪽이 지운다).
pub fn pairing_code_path() -> anyhow::Result<PathBuf> {
    Ok(state_dir()?.join("pairing-code"))
}

pub fn audit_dir() -> anyhow::Result<PathBuf> {
    Ok(home_dir()?.join("audit"))
}

pub fn nodes_path() -> anyhow::Result<PathBuf> {
    Ok(home_dir()?.join("nodes.toml"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeEntry {
    pub name: String,
    pub addr: String,
    /// 페어링 때 노드가 알려 준 이름. 나중에 달라지면 경고한다(주소 바꿔치기 탐지).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
}

/// 컨트롤러가 아는 노드. 토큰은 여기 두지 않는다(보안 저장소).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Nodes {
    #[serde(default, rename = "node")]
    pub nodes: Vec<NodeEntry>,
}

impl Nodes {
    pub fn load() -> anyhow::Result<Nodes> {
        match std::fs::read_to_string(nodes_path()?) {
            Ok(text) => Ok(toml::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Nodes::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let path = nodes_path()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&NodeEntry> {
        self.nodes.iter().find(|n| n.name == name)
    }

    pub fn upsert(&mut self, entry: NodeEntry) {
        match self.nodes.iter_mut().find(|n| n.name == entry.name) {
            Some(existing) => *existing = entry,
            None => self.nodes.push(entry),
        }
    }
}

/// 비밀이 들어갈 수 있는 디렉터리: 소유자만 접근(0700). 상위 디렉터리도 같은 권한으로 만든다.
pub fn create_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

/// 소유자만 읽는 파일(0600)을 처음부터 그 권한으로 만든다(만든 뒤 chmod 하는 틈이 없다).
/// 마지막 구성요소가 심볼릭 링크면 따라가지 않는다.
pub fn write_private(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(content)
}
