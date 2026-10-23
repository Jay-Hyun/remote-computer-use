use rcu::audit::{redact, Audit, Entry};
use rcu::tokens::TokenStore;
use time::macros::date;

#[test]
fn token_roundtrip_and_hash_only_storage() {
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStore::new(dir.path().join("state").join("tokens.json"));
    let token = store.issue("laptop", "2026-01-01T00:00:00Z").unwrap();
    assert!(token.starts_with("rcu_"));
    assert!(store.verify(&token).is_some());
    assert!(store.verify("rcu_wrong").is_none());
    assert!(store.verify("").is_none());

    let on_disk = std::fs::read_to_string(store.path()).unwrap();
    assert!(!on_disk.contains(&token), "plain token must not be stored");
    assert!(on_disk.contains("laptop"));
}

#[test]
fn tokens_are_unique_per_issue() {
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStore::new(dir.path().join("t.json"));
    let a = store.issue("a", "t").unwrap();
    let b = store.issue("b", "t").unwrap();
    assert_ne!(a, b);
    assert!(store.verify(&a).is_some() && store.verify(&b).is_some());
}

#[test]
fn revoke_all_invalidates_everything() {
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStore::new(dir.path().join("t.json"));
    let a = store.issue("a", "t").unwrap();
    let b = store.issue("b", "t").unwrap();
    assert_eq!(store.revoke_all().unwrap(), 2);
    assert!(store.verify(&a).is_none() && store.verify(&b).is_none());
}

#[cfg(unix)]
#[test]
fn token_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let store = TokenStore::new(dir.path().join("t.json"));
    store.issue("a", "t").unwrap();
    let mode = std::fs::metadata(store.path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0);
}

#[test]
fn redact_hides_tokens_and_bearer() {
    assert_eq!(redact("run rcu_abc-DEF_123 now"), "run [REDACTED] now");
    assert_eq!(
        redact("Authorization: Bearer abc.def"),
        "Authorization: Bearer [REDACTED].def"
    );
    assert_eq!(
        redact("Bearer xyz rcu_k1 end"),
        "Bearer [REDACTED] [REDACTED] end"
    );
    assert_eq!(redact("nothing here"), "nothing here");
}

#[test]
fn audit_appends_jsonl_without_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let audit = Audit::new(dir.path().join("audit"));
    for i in 0..2 {
        audit
            .log(Entry {
                ts: Audit::now(),
                request_id: &format!("req{i}"),
                capability: "exec",
                target: "curl -H 'Bearer rcu_SECRET123' http://x".into(),
                risk: Some("write"),
                approval: None,
                result: "OK",
                duration_ms: 3,
            })
            .unwrap();
    }
    let file = std::fs::read_dir(dir.path().join("audit"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let text = std::fs::read_to_string(file).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert!(!text.contains("SECRET123"));
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["capability"], "exec");
    }
}

#[test]
fn prune_removes_only_old_daily_files() {
    let dir = tempfile::tempdir().unwrap();
    let audit_dir = dir.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();
    for name in [
        "2026-01-01.jsonl",
        "2026-01-20.jsonl",
        "2026-02-10.jsonl",
        "notes.txt",
    ] {
        std::fs::write(audit_dir.join(name), "{}\n").unwrap();
    }
    let audit = Audit::new(&audit_dir);
    let removed = audit.prune(date!(2026 - 02 - 10), 30).unwrap();
    assert_eq!(removed, 1); // 2026-01-01 만 30일 초과
    assert!(!audit_dir.join("2026-01-01.jsonl").exists());
    assert!(audit_dir.join("2026-01-20.jsonl").exists());
    assert!(audit_dir.join("notes.txt").exists());
}
