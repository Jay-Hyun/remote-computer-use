//! 노드 쪽 토큰 저장소. 토큰 원문은 저장하지 않고 SHA-256 해시만 둔다.
//! 요청마다 파일을 다시 읽으므로 `rcu revoke --all` 이 실행 중인 노드에도 바로 적용된다.

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    id: String,
    label: String,
    hash: String,
    created: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    tokens: Vec<Entry>,
}

#[derive(Debug, Clone)]
pub struct TokenStore {
    path: PathBuf,
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

impl TokenStore {
    pub fn new(path: impl Into<PathBuf>) -> TokenStore {
        TokenStore { path: path.into() }
    }

    fn read(&self) -> anyhow::Result<File> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(serde_json::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(File::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn write(&self, file: &File) -> anyhow::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(file)?)?;
        set_private(&tmp)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// 새 토큰을 발급한다. 원문은 이 반환값으로만 볼 수 있다.
    pub fn issue(&self, label: &str, created: &str) -> anyhow::Result<String> {
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<32>());
        let token = format!("rcu_{secret}");
        let mut file = self.read()?;
        file.tokens.push(Entry {
            id: hex(&random_bytes::<4>()),
            label: label.chars().take(64).collect(),
            hash: hash_token(&token),
            created: created.to_string(),
        });
        self.write(&file)?;
        Ok(token)
    }

    /// 맞는 토큰이면 토큰 id 를 돌려준다. 모든 항목을 상수 시간으로 비교한다.
    pub fn verify(&self, token: &str) -> Option<String> {
        let file = self.read().ok()?;
        let given = hash_token(token);
        let mut found = None;
        for entry in &file.tokens {
            if bool::from(entry.hash.as_bytes().ct_eq(given.as_bytes())) {
                found = Some(entry.id.clone());
            }
        }
        found
    }

    pub fn revoke_all(&self) -> anyhow::Result<usize> {
        let file = self.read()?;
        let n = file.tokens.len();
        self.write(&File::default())?;
        Ok(n)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(unix)]
fn set_private(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}
