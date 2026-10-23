use rcu::approval::{Decision, Gate};
use rcu::limits::{Limit, Limiter};
use rcu::ops::{sanitize_for_display, summary, Op};
use rcu::policy::Risk;
use std::time::{Duration, Instant};
use time::macros::date;

#[test]
fn limiter_per_minute_window_resets() {
    let l = Limiter::new(2, 100);
    let t0 = Instant::now();
    let d = date!(2026 - 03 - 01);
    assert!(l.check("a", t0, d).is_ok());
    assert!(l.check("a", t0, d).is_ok());
    assert_eq!(l.check("a", t0, d), Err(Limit::Minute));
    assert!(l.check("b", t0, d).is_ok());
    assert!(l.check("a", t0 + Duration::from_secs(61), d).is_ok());
}

#[test]
fn limiter_daily_cap_is_node_wide_and_resets_next_day() {
    let l = Limiter::new(100, 3);
    let t0 = Instant::now();
    let d1 = date!(2026 - 03 - 01);
    assert!(l.check("a", t0, d1).is_ok());
    assert!(l.check("b", t0, d1).is_ok());
    assert!(l.check("c", t0, d1).is_ok());
    assert_eq!(l.check("d", t0, d1), Err(Limit::Day));
    assert!(l.check("d", t0, date!(2026 - 03 - 02)).is_ok());
}

#[test]
fn rejected_calls_do_not_consume_the_budget() {
    let l = Limiter::new(1, 2);
    let t0 = Instant::now();
    let d = date!(2026 - 03 - 01);
    assert!(l.check("a", t0, d).is_ok());
    for _ in 0..10 {
        assert_eq!(l.check("a", t0, d), Err(Limit::Minute));
    }
    assert!(l.check("b", t0, d).is_ok()); // 일 상한 2 중 1개만 쓰였다
}

#[test]
fn grants_expire_and_are_scoped() {
    let g = Gate::new(Duration::from_secs(60));
    let t0 = Instant::now();
    assert!(!g.grant_alive("tok", "exec", t0));
    g.add_grant("tok", "exec", t0);
    assert!(g.grant_alive("tok", "exec", t0 + Duration::from_secs(59)));
    assert!(!g.grant_alive("tok", "fs.read", t0));
    assert!(!g.grant_alive("other", "exec", t0));
    assert!(!g.grant_alive("tok", "exec", t0 + Duration::from_secs(61)));
}

#[test]
fn resolve_targets_oldest_or_given_id() {
    let g = Gate::new(Duration::from_secs(60));
    let a = g.open("t", "exec", Risk::Read, "a".into());
    let b = g.open("t", "exec", Risk::Read, "b".into());
    assert_eq!(g.waiting().len(), 2);
    assert_eq!(g.resolve(Some(&b.id), Decision::Once).unwrap().id, b.id);
    assert_eq!(g.resolve(None, Decision::Deny).unwrap().id, a.id);
    assert!(g.resolve(None, Decision::Once).is_none());
}

#[test]
fn subscribe_requires_the_same_token() {
    let g = Gate::new(Duration::from_secs(60));
    let o = g.open("owner", "exec", Risk::Read, "x".into());
    assert!(g.subscribe(&o.id, "owner").is_some());
    assert!(g.subscribe(&o.id, "thief").is_none());
    assert!(g.subscribe("nope", "owner").is_none());
}

#[test]
fn notifier_is_called_with_the_request() {
    use std::sync::{Arc, Mutex};
    let g = Gate::new(Duration::from_secs(60));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    g.set_notifier(Box::new(move |p| {
        s2.lock().unwrap().push(p.summary.clone())
    }));
    g.open("t", "fs.read", Risk::Read, "read /x".into());
    assert_eq!(*seen.lock().unwrap(), vec!["read /x".to_string()]);
}

#[test]
fn approval_prompt_text_has_no_control_characters() {
    let evil = Op::Exec {
        program: "/usr/bin/echo".into(),
        args: vec!["\x1b[2J\x1b[Hfake prompt\r\nallow? y".into()],
    };
    let text = summary(&evil);
    assert!(!text.chars().any(|c| c.is_control()), "{text:?}");
    assert!(text.contains("fake prompt"));
}

#[test]
fn long_summaries_are_truncated() {
    let long = "a".repeat(1000);
    let text = sanitize_for_display(&long);
    assert!(text.chars().count() <= 301);
    assert!(text.ends_with('…'));
}

#[test]
fn overwrite_summary_says_overwrite() {
    let op = Op::Write {
        path: "/w/f".into(),
        data: vec![1, 2, 3],
        overwrite: true,
    };
    assert!(summary(&op).starts_with("OVERWRITE \"/w/f\""));
}

#[test]
fn result_published_before_anyone_listens_is_still_delivered() {
    let g = Gate::new(Duration::from_secs(60));
    let o = g.open("t", "exec", Risk::Read, "x".into());
    let id = o.id.clone();
    drop(o); // 원래 HTTP 요청이 끊긴 상황: 구독자 없음
    g.publish(&id, Ok(serde_json::json!({"ok": true})));
    let rx = g.subscribe(&id, "t").unwrap();
    assert_eq!(rx.borrow().clone().unwrap().unwrap()["ok"], true);
}
