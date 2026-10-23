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
