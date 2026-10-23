//! 승인 게이트: 노드 사용자가 요청을 허용·거부한다. 기간 승인(그랜트)도 여기서 관리한다.

use crate::ops::OpResult;
use crate::policy::Risk;
use rand::RngCore;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, watch};

/// 승인 대기 제한. 넘기면 거부로 처리한다.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// 끝난 요청의 결과를 보관하는 시간(`rcu wait` 로 가져갈 수 있다).
const RESULT_KEEP: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// 이번 한 번만
    Once,
    /// 기간 동안(destructive·external 은 그랜트가 생기지 않고 한 번으로 취급)
    Grant,
    Deny,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingInfo {
    pub id: String,
    pub capability: String,
    pub risk: Risk,
    pub summary: String,
}

pub type Notifier = Box<dyn Fn(&PendingInfo) + Send + Sync>;

struct Entry {
    info: PendingInfo,
    token_id: String,
    decision_tx: Option<oneshot::Sender<Decision>>,
    result_tx: watch::Sender<Option<OpResult>>,
    finished: Option<Instant>,
}

#[derive(Default)]
struct Inner {
    /// (토큰 id, 능력, 위험도 순위) → 만료 시각. 위험도별로 따로 승인받는다(`read` 승인이 `write` 를 열지 않는다).
    grants: HashMap<(String, String, u8), Instant>,
    entries: HashMap<String, Entry>,
    order: Vec<String>,
}

pub struct Opened {
    pub id: String,
    pub decision_rx: oneshot::Receiver<Decision>,
    pub result_rx: watch::Receiver<Option<OpResult>>,
}

pub struct Gate {
    grant_ttl: Duration,
    inner: Mutex<Inner>,
    notifier: Mutex<Option<Notifier>>,
}

impl Gate {
    pub fn new(grant_ttl: Duration) -> Gate {
        Gate {
            grant_ttl,
            inner: Mutex::new(Inner::default()),
            notifier: Mutex::new(None),
        }
    }

    pub fn set_notifier(&self, notifier: Notifier) {
        *self.notifier.lock().unwrap() = Some(notifier);
    }

    pub fn grant_alive(&self, token_id: &str, capability: &str, risk: Risk, now: Instant) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let key = (token_id.to_string(), capability.to_string(), risk.rank());
        match inner.grants.get(&key) {
            Some(expires) if *expires > now => true,
            Some(_) => {
                inner.grants.remove(&key);
                false
            }
            None => false,
        }
    }

    pub fn add_grant(&self, token_id: &str, capability: &str, risk: Risk, now: Instant) {
        self.inner.lock().unwrap().grants.insert(
            (token_id.to_string(), capability.to_string(), risk.rank()),
            now + self.grant_ttl,
        );
    }

    /// 더는 발급된 상태가 아닌 토큰(폐기됨)의 그랜트를 지우고, 그 토큰의 대기 중 요청을 거부한다.
    /// 거부된 대기 요청의 수를 돌려준다.
    pub fn drop_revoked(&self, exists: impl Fn(&str) -> bool) -> usize {
        let mut inner = self.inner.lock().unwrap();
        inner.grants.retain(|(token, _, _), _| exists(token));
        let mut denied = 0;
        for entry in inner.entries.values_mut() {
            if entry.finished.is_none() && !exists(&entry.token_id) {
                if let Some(tx) = entry.decision_tx.take() {
                    let _ = tx.send(Decision::Deny);
                    denied += 1;
                }
            }
        }
        denied
    }

    pub fn open(
        &self,
        token_id: &str,
        capability: &str,
        risk: Risk,
        summary: String,
    ) -> Result<Opened, OpenError> {
        let (decision_tx, decision_rx) = oneshot::channel();
        let (result_tx, result_rx) = watch::channel(None);
        let info;
        {
            let mut inner = self.inner.lock().unwrap();
            let now = Instant::now();
            inner.entries.retain(|_, e| {
                e.finished
                    .is_none_or(|t| now.saturating_duration_since(t) < RESULT_KEEP)
            });
            let live: HashSet<&String> = inner.entries.keys().collect();
            let order: Vec<String> = inner
                .order
                .iter()
                .filter(|id| live.contains(id))
                .cloned()
                .collect();
            inner.order = order;

            // 승인 대기가 쌓여 노드 사용자가 질문 폭탄을 맞거나 메모리가 새는 것을 막는다.
            let waiting: Vec<&Entry> = inner
                .entries
                .values()
                .filter(|e| e.decision_tx.is_some())
                .collect();
            if waiting.len() >= MAX_PENDING_TOTAL {
                return Err(OpenError::TooManyTotal);
            }
            if waiting.iter().filter(|e| e.token_id == token_id).count() >= MAX_PENDING_PER_TOKEN {
                return Err(OpenError::TooManyForToken);
            }

            let mut id = new_id();
            while inner.entries.contains_key(&id) {
                id = new_id();
            }
            info = PendingInfo {
                id: id.clone(),
                capability: capability.to_string(),
                risk,
                summary,
            };
            inner.entries.insert(
                id.clone(),
                Entry {
                    info: info.clone(),
                    token_id: token_id.to_string(),
                    decision_tx: Some(decision_tx),
                    result_tx,
                    finished: None,
                },
            );
            inner.order.push(id);
        }
        if let Some(notify) = self.notifier.lock().unwrap().as_ref() {
            notify(&info);
        }
        Ok(Opened {
            id: info.id,
            decision_rx,
            result_rx,
        })
    }

    pub fn publish(&self, id: &str, result: OpResult) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(id) {
            entry.decision_tx = None;
            entry.finished = Some(Instant::now());
            // send_replace: 구독자가 없어도 값을 보관해야 나중에 `rcu wait` 가 가져간다.
            entry.result_tx.send_replace(Some(result));
        }
    }

    /// 대기 중인 요청에 결정을 전한다. `id` 가 None 이면 가장 오래된 것.
    pub fn resolve(&self, id: Option<&str>, decision: Decision) -> Option<PendingInfo> {
        let mut inner = self.inner.lock().unwrap();
        let order = inner.order.clone();
        for entry_id in order {
            if id.is_some_and(|want| want != entry_id) {
                continue;
            }
            let Some(entry) = inner.entries.get_mut(&entry_id) else {
                continue;
            };
            let Some(tx) = entry.decision_tx.take() else {
                continue;
            };
            let info = entry.info.clone();
            if tx.send(decision).is_ok() {
                return Some(info);
            }
        }
        None
    }

    /// 터미널 답변용: id 앞부분(2자 이상)으로 대기 중인 요청 하나를 고른다.
    pub fn resolve_prefix(
        &self,
        prefix: &str,
        decision: Decision,
    ) -> Result<PendingInfo, ResolveError> {
        if prefix.len() < 2 {
            return Err(ResolveError::NoMatch);
        }
        let matches: Vec<PendingInfo> = self
            .waiting()
            .into_iter()
            .filter(|p| p.id.starts_with(prefix))
            .collect();
        match matches.as_slice() {
            [] => Err(ResolveError::NoMatch),
            [one] => self
                .resolve(Some(&one.id), decision)
                .ok_or(ResolveError::NoMatch),
            _ => Err(ResolveError::Ambiguous),
        }
    }

    pub fn waiting(&self) -> Vec<PendingInfo> {
        let inner = self.inner.lock().unwrap();
        inner
            .order
            .iter()
            .filter_map(|id| inner.entries.get(id))
            .filter(|e| e.decision_tx.is_some())
            .map(|e| e.info.clone())
            .collect()
    }

    /// 같은 토큰이 연 요청의 결과만 구독할 수 있다.
    pub fn subscribe(&self, id: &str, token_id: &str) -> Option<watch::Receiver<Option<OpResult>>> {
        let inner = self.inner.lock().unwrap();
        let entry = inner.entries.get(id)?;
        (entry.token_id == token_id).then(|| entry.result_tx.subscribe())
    }

    /// 대기 시간이 끝났을 때 더 이상 결정을 받지 않게 한다.
    pub fn expire(&self, id: &str) {
        if let Some(entry) = self.inner.lock().unwrap().entries.get_mut(id) {
            entry.decision_tx = None;
        }
    }
}

/// 한 토큰이 동시에 승인 대기를 걸 수 있는 요청 수와 노드 전체 상한.
pub const MAX_PENDING_PER_TOKEN: usize = 5;
pub const MAX_PENDING_TOTAL: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    TooManyForToken,
    TooManyTotal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    NoMatch,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalAnswer {
    pub decision: Decision,
    pub id: Option<String>,
}

/// 터미널 한 줄 답변: `y`, `a`, `n` 다음에 선택적으로 요청 id(앞부분). 알아듣지 못하면 None.
pub fn parse_terminal_answer(line: &str) -> Option<TerminalAnswer> {
    let mut parts = line.split_whitespace();
    let decision = match parts.next()?.to_ascii_lowercase().as_str() {
        "y" | "yes" => Decision::Once,
        "a" | "always" => Decision::Grant,
        "n" | "no" => Decision::Deny,
        _ => return None,
    };
    let id = parts.next().map(|s| s.to_ascii_lowercase());
    if parts.next().is_some()
        || id
            .as_ref()
            .is_some_and(|i| !i.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(TerminalAnswer { decision, id })
}

fn new_id() -> String {
    let mut buf = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}
