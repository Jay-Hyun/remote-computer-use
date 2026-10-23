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
    /// RFC 3339. 없으면 만료되지 않는다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires: Option<String>,
}

/// `rcu tokens` 에 보이는 정보(해시는 보이지 않는다).
#[derive(Debug, Clone, Serialize)]
pub struct TokenInfo {
    pub id: String,
    pub label: String,
    pub created: String,
    pub expires: Option<String>,
}

fn expired(entry: &Entry) -> bool {
    use time::format_description::well_known::Rfc3339;
    entry
        .expires
        .as_deref()
        .and_then(|e| time::OffsetDateTime::parse(e, &Rfc3339).ok())
        .is_some_and(|t| t <= time::OffsetDateTime::now_utc())
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
            crate::config::create_private_dir(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        crate::config::write_private(&tmp, &serde_json::to_vec_pretty(file)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// 읽고-고치고-쓰는 동안 다른 프로세스(`rcu revoke`, 실행 중인 노드의 페어링)와 겹치지 않게 파일 잠금을 건다.
    fn locked<T>(&self, f: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<T> {
        if let Some(dir) = self.path.parent() {
            crate::config::create_private_dir(dir)?;
        }
        let lock = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.path.with_extension("lock"))?;
        lock.lock()?;
        let result = f();
        let _ = lock.unlock();
        result
    }

    /// 새 토큰을 발급한다. 원문은 이 반환값으로만 볼 수 있다.
    pub fn issue(&self, label: &str, created: &str) -> anyhow::Result<String> {
        self.issue_with_expiry(label, created, None)
    }

    /// `expires` 는 RFC 3339 시각. 그 뒤에는 토큰이 거부된다.
    pub fn issue_with_expiry(
        &self,
        label: &str,
        created: &str,
        expires: Option<String>,
    ) -> anyhow::Result<String> {
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes::<32>());
        let token = format!("rcu_{secret}");
        self.locked(|| {
            let mut file = self.read()?;
            // 토큰 id 는 승인·그랜트·속도 제한의 열쇠이므로 겹치지 않게 다시 뽑는다.
            let mut id = hex(&random_bytes::<8>());
            while file.tokens.iter().any(|t| t.id == id) {
                id = hex(&random_bytes::<8>());
            }
            file.tokens.push(Entry {
                id,
                label: label.chars().take(64).collect(),
                hash: hash_token(&token),
                created: created.to_string(),
                expires,
            });
            self.write(&file)?;
            Ok(token)
        })
    }

    /// 이 id 의 토큰이 아직 발급된 상태인지(폐기되면 false).
    pub fn exists(&self, id: &str) -> bool {
        self.read()
            .map(|f| f.tokens.iter().any(|t| t.id == id && !expired(t)))
            .unwrap_or(false)
    }

    pub fn list(&self) -> anyhow::Result<Vec<TokenInfo>> {
        Ok(self
            .read()?
            .tokens
            .into_iter()
            .map(|t| TokenInfo {
                id: t.id,
                label: t.label,
                created: t.created,
                expires: t.expires,
            })
            .collect())
    }

    /// id 하나(또는 2자 이상의 유일한 앞부분)에 해당하는 토큰만 폐기한다. 폐기한 개수.
    pub fn revoke(&self, id: &str) -> anyhow::Result<usize> {
        self.locked(|| {
            let mut file = self.read()?;
            let matches: Vec<usize> = file
                .tokens
                .iter()
                .enumerate()
                .filter(|(_, t)| t.id == id || (id.len() >= 4 && t.id.starts_with(id)))
                .map(|(i, _)| i)
                .collect();
            if matches.len() > 1 {
                anyhow::bail!("that id prefix matches several tokens; type more of it");
            }
            let Some(&index) = matches.first() else {
                return Ok(0);
            };
            file.tokens.remove(index);
            self.write(&file)?;
            Ok(1)
        })
    }

    /// 맞는 토큰이면 토큰 id 를 돌려준다. 모든 항목을 상수 시간으로 비교한다.
    pub fn verify(&self, token: &str) -> Option<String> {
        let file = self.read().ok()?;
        let given = hash_token(token);
        let mut found = None;
        for entry in &file.tokens {
            if bool::from(entry.hash.as_bytes().ct_eq(given.as_bytes())) && !expired(entry) {
                found = Some(entry.id.clone());
            }
        }
        found
    }

    pub fn revoke_all(&self) -> anyhow::Result<usize> {
        self.locked(|| {
            let file = self.read()?;
            let n = file.tokens.len();
            self.write(&File::default())?;
            Ok(n)
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
