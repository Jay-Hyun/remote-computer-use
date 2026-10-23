//! 추가 전용 감사 로그. 하루 한 파일(JSON Lines). 내용·토큰·비밀값은 기록하지 않는다.

use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use time::macros::format_description;
use time::{Date, Duration, OffsetDateTime};

pub const RETENTION_DAYS: i64 = 30;

#[derive(Debug, Serialize)]
pub struct Entry<'a> {
    pub ts: String,
    pub request_id: &'a str,
    pub capability: &'a str,
    /// 명령 또는 경로. 가림 처리 후 기록된다.
    pub target: String,
    pub risk: Option<&'a str>,
    pub approval: Option<&'a str>,
    pub result: &'a str,
    pub duration_ms: u64,
}

#[derive(Debug, Clone)]
pub struct Audit {
    dir: PathBuf,
}

/// `rcu_...` 토큰과 `Bearer ...` 값을 가린다.
pub fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = match (rest.find("rcu_"), rest.find("Bearer ")) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    } {
        let (head, tail) = rest.split_at(pos);
        out.push_str(head);
        let skip = if tail.starts_with("Bearer ") { 7 } else { 0 };
        out.push_str(&tail[..skip]);
        out.push_str("[REDACTED]");
        let body = &tail[skip..];
        let end = body
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(body.len());
        rest = &body[end..];
    }
    out.push_str(rest);
    out
}

impl Audit {
    pub fn new(dir: impl Into<PathBuf>) -> Audit {
        Audit { dir: dir.into() }
    }

    pub fn now() -> String {
        OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default()
    }

    fn file_for(&self, day: Date) -> PathBuf {
        let name = day
            .format(format_description!("[year]-[month]-[day]"))
            .unwrap_or_default();
        self.dir.join(format!("{name}.jsonl"))
    }

    pub fn log(&self, mut entry: Entry<'_>) -> anyhow::Result<()> {
        entry.target = redact(&entry.target);
        std::fs::create_dir_all(&self.dir)?;
        let path = self.file_for(OffsetDateTime::now_utc().date());
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');
        file.write_all(&line)?;
        Ok(())
    }

    /// 보관 기간이 지난 일별 파일을 지운다. 지운 개수를 돌려준다.
    pub fn prune(&self, today: Date, keep_days: i64) -> anyhow::Result<usize> {
        let cutoff = today - Duration::days(keep_days);
        let mut removed = 0;
        let Ok(dir) = std::fs::read_dir(&self.dir) else {
            return Ok(0);
        };
        for item in dir.flatten() {
            let name = item.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".jsonl") else {
                continue;
            };
            if let Ok(day) = Date::parse(stem, format_description!("[year]-[month]-[day]")) {
                if day < cutoff {
                    std::fs::remove_file(item.path())?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}
