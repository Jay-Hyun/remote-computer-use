#![cfg(unix)]
//! 보안 검토에서 나온 지적의 회귀 시험.

use rcu::fsops;
use rcu::ops::{self, Op};
use rcu::policy::{Access, Code, Policy, Risk};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

fn policy(root: &Path, extra: &str) -> Policy {
    Policy::parse(&format!(
        "[capabilities]\nexec = true\nfs_read = true\nfs_write = true\n[fs]\nroots = ['{}']\n{extra}\n",
        root.display()
    ))
    .unwrap()
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
fn approved_risk_is_enforced_at_execution() {
    let dir = tempfile::tempdir().unwrap();
    let p = policy(dir.path(), "");
    let target = dir.path().join("late.txt");
    let op = Op::Write {
        path: target.to_string_lossy().into(),
        data: b"new".to_vec(),
        overwrite: true,
    };
    // 계획 시점에는 파일이 없어 새 파일(write)이다.
    let plan = ops::plan(&p, &op).unwrap();
    assert_eq!(plan.risk, Risk::Write);
    assert!(plan.summary.starts_with("create "), "{}", plan.summary);
    // 승인을 기다리는 사이 파일이 생겼다.
    fs::write(&target, "precious").unwrap();
    let err = ops::execute(&p, &op, plan.risk).unwrap_err();
    assert_eq!(err.code, "STATE_CHANGED");
    assert_eq!(fs::read_to_string(&target).unwrap(), "precious");
    // 덮어쓰기로 승인받았다면 실행된다.
    assert!(ops::execute(&p, &op, Risk::Destructive).is_ok());
    assert_eq!(fs::read_to_string(&target).unwrap(), "new");
}

#[test]
fn approval_text_shows_invisible_characters_and_argument_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let p = policy(
        dir.path(),
        "[[exec.allow]]\nprogram = '/usr/bin/git'\nargs = [\"**\"]\nrisk = \"read\"\n",
    );
    let plan_for = |args: &[&str]| {
        ops::plan(
            &p,
            &Op::Exec {
                program: "/usr/bin/git".into(),
                args: s(args),
            },
        )
        .unwrap()
        .summary
    };
    let bidi = plan_for(&["status", "\u{202e}gpj.txt", "a\u{200b}b"]);
    assert!(
        bidi.contains("\\u{202e}") && bidi.contains("\\u{200b}"),
        "{bidi}"
    );
    assert!(!bidi.chars().any(|c| c == '\u{202e}' || c == '\u{200b}'));
    // ["a b"] 와 ["a","b"] 는 다르게 보인다.
    assert_ne!(plan_for(&["a b"]), plan_for(&["a", "b"]));
    // 줄바꿈으로 가짜 줄을 만들 수 없다.
    let nl = plan_for(&["x\nread \"/tmp/y\" (read)"]);
    assert!(!nl.contains('\n') && nl.contains("\\n"), "{nl}");
}

#[test]
fn over_long_requests_are_refused_not_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let p = policy(
        dir.path(),
        "[[exec.allow]]\nprogram = '/usr/bin/git'\nargs = [\"**\"]\nrisk = \"read\"\n",
    );
    let long = "a".repeat(ops::MAX_SUMMARY_CHARS + 10);
    let err = ops::plan(
        &p,
        &Op::Exec {
            program: "/usr/bin/git".into(),
            args: s(&["status", &long, "--tail"]),
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "TOO_LARGE");
}

#[test]
fn summary_shows_where_a_symlink_really_points() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub/real.txt"), "x").unwrap();
    symlink(root.join("sub/real.txt"), root.join("notes.txt")).unwrap();
    let p = policy(&root, "");
    let plan = ops::plan(
        &p,
        &Op::Write {
            path: root.join("notes.txt").to_string_lossy().into(),
            data: b"y".to_vec(),
            overwrite: true,
        },
    )
    .unwrap();
    assert!(
        plan.summary.contains("->") && plan.summary.contains("sub/real.txt"),
        "{}",
        plan.summary
    );
    assert!(plan.summary.starts_with("OVERWRITE"));
}

#[test]
fn backup_never_follows_links_or_replaces_older_backups() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim");
    fs::write(&victim, "VICTIM").unwrap();
    let f = root.join("f.txt");
    fs::write(&f, "one").unwrap();
    // 백업 이름 자리에 바깥을 가리키는 링크
    symlink(&victim, root.join("f.txt.rcu-bak")).unwrap();
    let p = policy(&root, "");

    let out = fsops::write(&p, f.to_str().unwrap(), b"two", true).unwrap();
    assert_eq!(out.backup.as_deref(), Some("f.txt.rcu-bak.1"));
    assert_eq!(
        fs::read_to_string(&victim).unwrap(),
        "VICTIM",
        "link target must stay untouched"
    );
    assert_eq!(
        fs::read_to_string(root.join("f.txt.rcu-bak.1")).unwrap(),
        "one"
    );

    // 두 번째 덮어쓰기는 앞의 백업을 지우지 않고 다음 번호를 쓴다.
    let out = fsops::write(&p, f.to_str().unwrap(), b"three", true).unwrap();
    assert_eq!(out.backup.as_deref(), Some("f.txt.rcu-bak.2"));
    assert_eq!(
        fs::read_to_string(root.join("f.txt.rcu-bak.1")).unwrap(),
        "one"
    );
    assert_eq!(
        fs::read_to_string(root.join("f.txt.rcu-bak.2")).unwrap(),
        "two"
    );
    assert_eq!(fs::read_to_string(&f).unwrap(), "three");
}

#[test]
fn overwrite_does_not_leave_stale_bytes_or_holes() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let f = root.join("f.txt");
    fs::write(&f, "a much longer original content").unwrap();
    let p = policy(&root, "");
    fsops::write(&p, f.to_str().unwrap(), b"short", true).unwrap();
    assert_eq!(fs::read(&f).unwrap(), b"short");
}

#[test]
fn hardlinks_cannot_bypass_deny_globs_or_be_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    fs::write(root.join(".env"), "SECRET").unwrap();
    fs::hard_link(root.join(".env"), root.join("alias.txt")).unwrap();
    let p = policy(&root, "deny = [\"**/.env\"]");
    let err = fsops::read(&p, root.join("alias.txt").to_str().unwrap())
        .err()
        .unwrap();
    assert_eq!(err.code, "PATH_DENIED");

    fs::write(root.join("a.txt"), "orig").unwrap();
    fs::hard_link(root.join("a.txt"), root.join("b.txt")).unwrap();
    let err = fsops::write(&p, root.join("b.txt").to_str().unwrap(), b"x", true)
        .err()
        .unwrap();
    assert_eq!(err.code, "PATH_DENIED");
    assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "orig");
}

#[test]
fn fifo_does_not_hang_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let fifo = root.join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    let p = policy(&root, "");
    let (tx, rx) = std::sync::mpsc::channel();
    let path = fifo.to_string_lossy().into_owned();
    std::thread::spawn(move || {
        let r = fsops::read(&p, &path).err().map(|e| e.code);
        let _ = tx.send(r);
    });
    let got = rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("read of a FIFO must not block");
    assert_eq!(got, Some("NOT_A_FILE"));
}

#[test]
fn nodes_own_state_is_protected_even_under_a_broad_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let home = root.join(".config/rcu");
    fs::create_dir_all(home.join("state")).unwrap();
    fs::write(home.join("state/tokens.json"), "{}").unwrap();
    fs::write(home.join("policy.toml"), "").unwrap();
    let mut p = policy(&root, "");
    p.protect(home.clone());
    for path in [
        "state/tokens.json",
        "policy.toml",
        "state/pair-request",
        "state/pairing-code",
    ] {
        let full = home.join(path);
        assert_eq!(
            p.check_path(full.to_str().unwrap(), Access::Read)
                .err()
                .map(|e| e.code),
            Some(Code::PathDenied),
            "read {path}"
        );
        assert!(
            p.check_path(full.to_str().unwrap(), Access::Write).is_err(),
            "write {path}"
        );
    }
    // 다른 곳은 그대로 쓸 수 있다.
    fs::write(root.join("ok.txt"), "x").unwrap();
    assert!(p
        .check_path(root.join("ok.txt").to_str().unwrap(), Access::Read)
        .is_ok());
}

#[test]
fn deny_globs_ignore_case_and_cover_startup_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let p = policy(&root, "deny = [\"**/secrets/**\"]");
    for rel in [
        ".ENV",
        ".Env",
        "SECRETS/k",
        ".SSH/authorized_keys",
        ".zshenv",
        ".zshrc",
        ".bashrc",
        ".config/autostart/x.desktop",
        "Library/LaunchAgents/x.plist",
    ] {
        let full = root.join(rel);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        assert_eq!(
            p.check_path(full.to_str().unwrap(), Access::Write)
                .err()
                .map(|e| e.code),
            Some(Code::PathDenied),
            "{rel}"
        );
    }
}

#[test]
fn deny_patterns_work_through_symlinked_prefixes_and_bad_ones_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    fs::create_dir_all(root.join("real/secret")).unwrap();
    fs::write(root.join("real/secret/k"), "k").unwrap();
    symlink(root.join("real"), root.join("alias")).unwrap();
    // 별칭 경로로 쓴 거부 패턴이 실제 경로에도 걸린다.
    let p = policy(
        &root,
        &format!("deny = ['{}/alias/secret/**']", root.display()),
    );
    assert!(p
        .check_path(root.join("real/secret/k").to_str().unwrap(), Access::Read)
        .is_err());

    // 상대 패턴과 풀 수 없는 ~ 는 조용히 무시하지 않고 거부한다.
    assert!(Policy::parse("[fs]\ndeny = [\".env\"]\n").is_err());
    assert!(Policy::parse("[fs]\ndeny = [\"secrets/*\"]\n").is_err());
    assert!(Policy::parse("[fs]\ndeny = [\"~other/x\"]\n").is_err());
}

#[test]
fn windows_style_program_names_are_not_absolute_on_unix() {
    let t = |prog: &str| {
        Policy::parse(&format!(
            "[[exec.allow]]\nprogram = '{prog}'\nrisk = \"read\"\n"
        ))
        .is_err()
    };
    assert!(t("x:git"));
    assert!(t("C:\\Windows\\cmd.exe.")); // 셸(끝의 점은 무시)
    assert!(t("/opt/run.ps1"));
}

#[test]
fn more_shells_and_wrappers_cannot_be_allow_listed() {
    for prog in [
        "/bin/busybox",
        "/usr/bin/toybox",
        "/bin/rbash",
        "/usr/bin/mksh",
        "/usr/bin/timeout",
        "/usr/bin/time",
        "/usr/bin/stdbuf",
        "/usr/bin/setsid",
        "/usr/bin/nsenter",
        "/usr/bin/flock",
        "/usr/bin/script",
        "/usr/bin/strace",
        "/usr/bin/gdb",
    ] {
        let text =
            format!("[[exec.allow]]\nprogram = '{prog}'\nargs = [\"**\"]\nrisk = \"write\"\n");
        assert!(Policy::parse(&text).is_err(), "{prog}");
    }
}

#[test]
fn file_size_limits_are_clamped() {
    let p = Policy::parse("[fs]\nmax_read_bytes = 999999999999\nmax_write_bytes = 999999999999\n")
        .unwrap();
    assert!(p.max_read_bytes <= 64 * 1024 * 1024 && p.max_write_bytes <= 64 * 1024 * 1024);
}

#[test]
fn risky_policies_produce_warnings() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let p = policy(
        &root,
        "[[exec.allow]]\nprogram = '/usr/bin/python3'\nargs = [\"**\"]\nrisk = \"write\"\n",
    );
    let w = p.warnings().join("\n");
    assert!(
        w.contains("python3") && w.contains("as powerful as a shell"),
        "{w}"
    );
    assert!(w.contains("not checked against fs.roots"), "{w}");
    assert!(Policy::parse("").unwrap().warnings().is_empty());
}
