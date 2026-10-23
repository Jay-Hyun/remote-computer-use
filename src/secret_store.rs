//! 컨트롤러 쪽 토큰 보관. 평문 파일에는 두지 않는다.
//!
//! - 맥·윈도우: OS 보안 저장소(키체인 / 자격 증명 관리자)
//! - 리눅스·클라우드 컨테이너: 환경 변수 `RCU_TOKEN_<노드이름>` (읽기 전용)

use std::collections::HashMap;
use std::sync::Mutex;

pub trait SecretStore {
    fn get(&self, node: &str) -> anyhow::Result<Option<String>>;
    fn set(&self, node: &str, token: &str) -> anyhow::Result<()>;
    fn delete(&self, node: &str) -> anyhow::Result<()>;
}

pub fn env_var_name(node: &str) -> String {
    let key: String = node
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("RCU_TOKEN_{key}")
}

/// 환경 변수에서만 읽는다.
pub struct EnvStore;

impl SecretStore for EnvStore {
    fn get(&self, node: &str) -> anyhow::Result<Option<String>> {
        Ok(std::env::var(env_var_name(node))
            .ok()
            .filter(|v| !v.is_empty()))
    }

    fn set(&self, node: &str, _token: &str) -> anyhow::Result<()> {
        anyhow::bail!(
            "no OS secure store on this system; pair on a machine with one, or set {} from an environment secret",
            env_var_name(node)
        )
    }

    fn delete(&self, _node: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

/// 시험용.
#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<String, String>>);

impl SecretStore for MemoryStore {
    fn get(&self, node: &str) -> anyhow::Result<Option<String>> {
        Ok(self.0.lock().unwrap().get(node).cloned())
    }

    fn set(&self, node: &str, token: &str) -> anyhow::Result<()> {
        self.0
            .lock()
            .unwrap()
            .insert(node.to_string(), token.to_string());
        Ok(())
    }

    fn delete(&self, node: &str) -> anyhow::Result<()> {
        self.0.lock().unwrap().remove(node);
        Ok(())
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub struct OsStore;

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl OsStore {
    fn entry(node: &str) -> anyhow::Result<keyring::Entry> {
        Ok(keyring::Entry::new("rcu", node)?)
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl SecretStore for OsStore {
    fn get(&self, node: &str) -> anyhow::Result<Option<String>> {
        match OsStore::entry(node)?.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set(&self, node: &str, token: &str) -> anyhow::Result<()> {
        OsStore::entry(node)?.set_password(token)?;
        Ok(())
    }

    fn delete(&self, node: &str) -> anyhow::Result<()> {
        match OsStore::entry(node)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// 환경 변수가 있으면 그것을, 없으면 OS 보안 저장소를 쓴다.
pub struct DefaultStore;

impl SecretStore for DefaultStore {
    fn get(&self, node: &str) -> anyhow::Result<Option<String>> {
        if let Some(v) = EnvStore.get(node)? {
            return Ok(Some(v));
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        return OsStore.get(node);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        Ok(None)
    }

    fn set(&self, node: &str, token: &str) -> anyhow::Result<()> {
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        return OsStore.set(node, token);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        EnvStore.set(node, token)
    }

    fn delete(&self, node: &str) -> anyhow::Result<()> {
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        return OsStore.delete(node);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        EnvStore.delete(node)
    }
}
