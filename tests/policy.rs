#![cfg(unix)] // Windows 경로 시험은 M4 에서 옮긴다

use rcu::policy::{Access, Code, Policy, Risk};
use std::fs;

fn policy_for(root: &std::path::Path, extra: &str) -> Policy {
    let text = format!(
        r#"
[capabilities]
exec = true
fs_read = true
fs_write = true

[fs]
roots = ["{}"]
deny = ["**/.env", "**/.ssh/**"]

[[exec.allow]]
program = "/usr/bin/git"
args = ["status", "*"]
risk = "read"

[[exec.allow]]
program = "/usr/bin/ls"
args = ["**"]
risk = "read"
{extra}
"#,
        root.to_string_lossy().replace('\\', "/")
    );
    Policy::parse(&text).unwrap()
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
fn default_policy_denies_everything() {
    let p = Policy::parse("").unwrap();
    assert_eq!(p.capabilities(), vec!["info"]);
    assert_eq!(
        p.check_command("/usr/bin/git", &s(&["status"]))
            .unwrap_err()
            .code,
        Code::CapabilityOff
    );
    assert_eq!(
        p.check_path("/tmp/x", Access::Read).unwrap_err().code,
        Code::CapabilityOff
    );
    assert_eq!(
        p.check_path("/tmp/x", Access::Write).unwrap_err().code,
        Code::CapabilityOff
    );
}

#[test]
fn missing_policy_file_means_default_deny() {
    let dir = tempfile::tempdir().unwrap();
    let p = Policy::load(&dir.path().join("nope.toml")).unwrap();
    assert!(!p.exec_enabled && !p.fs_read_enabled && !p.fs_write_enabled);
}

#[test]
fn capability_off_even_with_allow_list() {
    let p = Policy::parse(
        r#"
[[exec.allow]]
program = "/usr/bin/git"
risk = "read"
"#,
    )
    .unwrap();
    assert_eq!(
        p.check_command("/usr/bin/git", &[]).unwrap_err().code,
        Code::CapabilityOff
    );
}

#[test]
fn path_inside_root_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.txt"), "hi").unwrap();
    let p = policy_for(dir.path(), "");
    let r = p
        .check_path(dir.path().join("a.txt").to_str().unwrap(), Access::Read)
        .unwrap();
    assert!(r.existed);
}

#[test]
fn dotdot_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("a.txt"), "hi").unwrap();
    let p = policy_for(dir.path(), "");
    let sneaky = format!("{}/sub/../a.txt", dir.path().display());
    assert_eq!(
        p.check_path(&sneaky, Access::Read).unwrap_err().code,
        Code::PathDenied
    );
}

#[test]
fn relative_and_empty_paths_are_denied() {
    let dir = tempfile::tempdir().unwrap();
    let p = policy_for(dir.path(), "");
    assert_eq!(
        p.check_path("a.txt", Access::Read).unwrap_err().code,
        Code::PathDenied
    );
    assert_eq!(
        p.check_path("", Access::Read).unwrap_err().code,
        Code::PathDenied
    );
}

#[test]
fn outside_root_is_denied() {
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    fs::write(other.path().join("secret.txt"), "x").unwrap();
    let p = policy_for(root.path(), "");
    let outside = other.path().join("secret.txt");
    assert_eq!(
        p.check_path(outside.to_str().unwrap(), Access::Read)
            .unwrap_err()
            .code,
        Code::PathDenied
    );
}

#[cfg(unix)]
#[test]
fn symlink_escape_is_denied() {
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    fs::write(other.path().join("secret.txt"), "x").unwrap();
    std::os::unix::fs::symlink(other.path(), root.path().join("link")).unwrap();
    let p = policy_for(root.path(), "");
    let via_link = root.path().join("link").join("secret.txt");
    assert_eq!(
        p.check_path(via_link.to_str().unwrap(), Access::Read)
            .unwrap_err()
            .code,
        Code::PathDenied
    );
    // 새 파일을 링크 디렉터리 안에 쓰는 것도 막는다.
    let new_file = root.path().join("link").join("new.txt");
    assert_eq!(
        p.check_path(new_file.to_str().unwrap(), Access::Write)
            .unwrap_err()
            .code,
        Code::PathDenied
    );
}

#[cfg(unix)]
#[test]
fn symlink_file_pointing_outside_is_denied() {
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    fs::write(other.path().join("secret.txt"), "x").unwrap();
    std::os::unix::fs::symlink(other.path().join("secret.txt"), root.path().join("l.txt")).unwrap();
    let p = policy_for(root.path(), "");
    let link = root.path().join("l.txt");
    assert_eq!(
        p.check_path(link.to_str().unwrap(), Access::Read)
            .unwrap_err()
            .code,
        Code::PathDenied
    );
    assert_eq!(
        p.check_path(link.to_str().unwrap(), Access::Write)
            .unwrap_err()
            .code,
        Code::PathDenied
    );
}

#[test]
fn deny_globs_win_inside_root() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".env"), "KEY=1").unwrap();
    fs::create_dir(dir.path().join(".ssh")).unwrap();
    fs::write(dir.path().join(".ssh").join("id_rsa"), "k").unwrap();
    let p = policy_for(dir.path(), "");
    for f in [".env", ".ssh/id_rsa"] {
        let path = dir.path().join(f);
        assert_eq!(
            p.check_path(path.to_str().unwrap(), Access::Read)
                .unwrap_err()
                .code,
            Code::PathDenied,
            "{f}"
        );
    }
}

#[test]
fn write_to_new_file_reports_not_existed() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("old.txt"), "x").unwrap();
    let p = policy_for(dir.path(), "");
    let fresh = p
        .check_path(dir.path().join("new.txt").to_str().unwrap(), Access::Write)
        .unwrap();
    assert!(!fresh.existed);
    let old = p
        .check_path(dir.path().join("old.txt").to_str().unwrap(), Access::Write)
        .unwrap();
    assert!(old.existed);
}

#[test]
fn write_into_missing_parent_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let p = policy_for(dir.path(), "");
    let path = dir.path().join("nodir").join("f.txt");
    assert_eq!(
        p.check_path(path.to_str().unwrap(), Access::Write)
            .unwrap_err()
            .code,
        Code::PathDenied
    );
}

#[test]
fn only_fs_read_enabled_blocks_writes() {
    let dir = tempfile::tempdir().unwrap();
    let text = format!(
        "[capabilities]\nfs_read = true\n[fs]\nroots = [\"{}\"]\n",
        dir.path().to_string_lossy().replace('\\', "/")
    );
    let p = Policy::parse(&text).unwrap();
    let path = dir.path().join("f.txt");
    assert_eq!(
        p.check_path(path.to_str().unwrap(), Access::Write)
            .unwrap_err()
            .code,
        Code::CapabilityOff
    );
}

#[test]
fn shells_are_denied_at_check_time() {
    let dir = tempfile::tempdir().unwrap();
    let p = policy_for(dir.path(), "");
    for prog in [
        "/bin/sh",
        "/bin/bash",
        "/usr/bin/zsh",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "pwsh",
        "/usr/bin/osascript",
    ] {
        assert_eq!(
            p.check_command(prog, &s(&["-c", "id"])).unwrap_err().code,
            Code::ShellDenied,
            "{prog}"
        );
    }
}

#[test]
fn shells_cannot_be_put_in_the_allow_list() {
    for prog in [
        "/bin/sh",
        "/bin/bash",
        "C:\\Windows\\System32\\cmd.exe",
        "/opt/run.bat",
        "/opt/run.cmd",
    ] {
        let text = format!("[[exec.allow]]\nprogram = '{prog}'\nrisk = \"write\"\n");
        assert!(Policy::parse(&text).is_err(), "{prog}");
    }
}

#[test]
fn wrappers_cannot_be_put_in_the_allow_list() {
    for prog in ["/usr/bin/env", "/usr/bin/sudo", "/usr/bin/xargs"] {
        let text = format!("[[exec.allow]]\nprogram = '{prog}'\nrisk = \"write\"\n");
        assert!(Policy::parse(&text).is_err(), "{prog}");
    }
}

#[test]
fn relative_program_in_allow_list_is_rejected() {
    assert!(Policy::parse("[[exec.allow]]\nprogram = \"git\"\nrisk = \"read\"\n").is_err());
}

#[test]
fn doublestar_must_be_last_arg_pattern() {
    let text =
        "[[exec.allow]]\nprogram = \"/usr/bin/git\"\nargs = [\"**\", \"x\"]\nrisk = \"read\"\n";
    assert!(Policy::parse(text).is_err());
}

#[test]
fn unknown_risk_is_rejected() {
    assert!(
        Policy::parse("[[exec.allow]]\nprogram = \"/usr/bin/git\"\nrisk = \"safe\"\n").is_err()
    );
}

#[test]
fn allow_list_matches_program_and_args() {
    let dir = tempfile::tempdir().unwrap();
    let p = policy_for(dir.path(), "");
    assert_eq!(
        p.check_command("/usr/bin/git", &s(&["status", "--short"]))
            .unwrap(),
        Risk::Read
    );
    // 인자 개수·내용이 맞지 않으면 거부
    assert_eq!(
        p.check_command("/usr/bin/git", &s(&["status"]))
            .unwrap_err()
            .code,
        Code::CommandDenied
    );
    assert_eq!(
        p.check_command("/usr/bin/git", &s(&["push", "x"]))
            .unwrap_err()
            .code,
        Code::CommandDenied
    );
    assert_eq!(
        p.check_command("/usr/bin/git", &s(&["status", "a", "b"]))
            .unwrap_err()
            .code,
        Code::CommandDenied
    );
    // 허용 목록에 없는 프로그램
    assert_eq!(
        p.check_command("/usr/bin/curl", &s(&["x"]))
            .unwrap_err()
            .code,
        Code::CommandDenied
    );
    // 이름만 같은 다른 경로
    assert_eq!(
        p.check_command("/tmp/git", &s(&["status", "x"]))
            .unwrap_err()
            .code,
        Code::CommandDenied
    );
    // `**` 는 0개 이상의 인자
    assert_eq!(p.check_command("/usr/bin/ls", &[]).unwrap(), Risk::Read);
    assert_eq!(
        p.check_command("/usr/bin/ls", &s(&["-la", "/"])).unwrap(),
        Risk::Read
    );
}

#[test]
fn empty_args_pattern_allows_only_no_args() {
    let p = Policy::parse(
        "[capabilities]\nexec = true\n[[exec.allow]]\nprogram = \"/usr/bin/uptime\"\nrisk = \"read\"\n",
    )
    .unwrap();
    assert!(p.check_command("/usr/bin/uptime", &[]).is_ok());
    assert!(p.check_command("/usr/bin/uptime", &s(&["-p"])).is_err());
}

#[test]
fn risk_comes_from_policy_not_caller() {
    let p = Policy::parse(
        r#"
[capabilities]
exec = true
[[exec.allow]]
program = "/usr/bin/rm"
args = ["**"]
risk = "destructive"
"#,
    )
    .unwrap();
    let risk = p.check_command("/usr/bin/rm", &s(&["-r", "x"])).unwrap();
    assert_eq!(risk, Risk::Destructive);
    assert!(risk.always_needs_approval());
    assert!(!Risk::Write.always_needs_approval());
}

#[cfg(unix)]
#[test]
fn symlink_to_shell_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let sh = ["/bin/sh", "/usr/bin/sh"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists());
    let Some(sh) = sh else { return };
    let link = dir.path().join("tool");
    std::os::unix::fs::symlink(sh, &link).unwrap();
    let text = format!(
        "[capabilities]\nexec = true\n[[exec.allow]]\nprogram = '{}'\nargs = [\"**\"]\nrisk = \"write\"\n",
        link.display()
    );
    let p = Policy::parse(&text).unwrap();
    assert_eq!(
        p.check_command(link.to_str().unwrap(), &s(&["-c", "id"]))
            .unwrap_err()
            .code,
        Code::ShellDenied
    );
}

#[test]
fn error_messages_do_not_leak_paths() {
    let dir = tempfile::tempdir().unwrap();
    let p = policy_for(dir.path(), "");
    let secret_path = "/etc/very-secret-name/passwd";
    let e = p.check_path(secret_path, Access::Read).unwrap_err();
    assert!(!e.to_string().contains("very-secret-name"));
}

#[test]
fn approval_ui_values() {
    use rcu::policy::ApprovalUi;
    assert_eq!(Policy::parse("").unwrap().approval_ui, ApprovalUi::Auto);
    for (text, want) in [
        ("terminal", ApprovalUi::Terminal),
        ("dialog", ApprovalUi::Dialog),
        ("auto", ApprovalUi::Auto),
    ] {
        let p = Policy::parse(&format!("[approval]\nui = \"{text}\"\n")).unwrap();
        assert_eq!(p.approval_ui, want);
    }
    assert!(Policy::parse("[approval]\nui = \"popup\"\n").is_err());
}
