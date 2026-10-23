use rcu::service::{launchd_plist, schtasks_create_args, systemd_unit};
use std::path::Path;

#[test]
fn launchd_plist_runs_serve_at_load_and_escapes_paths() {
    let plist = launchd_plist(
        Path::new("/Users/a&b/bin/rcu"),
        Some(Path::new("/Users/a/<cfg>")),
        Path::new("/Users/a/node.log"),
    );
    assert!(plist.contains("<string>/Users/a&amp;b/bin/rcu</string>"));
    assert!(plist.contains("<string>serve</string>"));
    assert!(plist.contains("<key>RunAtLoad</key>\n  <true/>"));
    assert!(plist.contains("<key>RCU_HOME</key>\n    <string>/Users/a/&lt;cfg&gt;</string>"));
    assert!(
        !plist.contains("--bind"),
        "address is auto-detected at start-up"
    );
    let none = launchd_plist(Path::new("/x/rcu"), None, Path::new("/x/log"));
    assert!(!none.contains("EnvironmentVariables"));
}

#[test]
fn systemd_unit_quotes_exec_and_restarts() {
    let unit = systemd_unit(
        Path::new("/home/a b/bin/rcu"),
        Some(Path::new("/home/a b/.rcu")),
    );
    assert!(unit.contains("ExecStart=\"/home/a b/bin/rcu\" serve\n"));
    assert!(unit.contains("Environment=\"RCU_HOME=/home/a b/.rcu\"\n"));
    assert!(unit.contains("Restart=on-failure"));
    assert!(unit.contains("WantedBy=default.target"));
}

#[test]
fn schtasks_runs_at_logon_with_limited_rights() {
    let args = schtasks_create_args(Path::new("C:\\Program Files\\rcu\\rcu.exe"));
    let joined = args.join(" ");
    assert!(joined.contains("/SC ONLOGON"));
    assert!(joined.contains("/RL LIMITED"));
    assert!(args.contains(&"\"C:\\Program Files\\rcu\\rcu.exe\" serve".to_string()));
}

#[cfg(unix)]
mod cli {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    fn rcu(home: &std::path::Path) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_rcu"));
        c.env("RCU_HOME", home)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("xdg"));
        c
    }

    #[test]
    fn service_install_no_start_writes_a_unit_and_uninstall_removes_it() {
        let home = tempfile::tempdir().unwrap();
        let out = rcu(home.path())
            .args(["service", "install", "--no-start"])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let unit = std::path::PathBuf::from(v["unit"].as_str().unwrap());
        assert!(
            unit.starts_with(home.path()),
            "must stay inside the user's home: {unit:?}"
        );
        let text = std::fs::read_to_string(&unit).unwrap();
        assert!(text.contains("serve") && text.contains(env!("CARGO_BIN_EXE_rcu")));
        assert_eq!(v["started"], false);

        let out = rcu(home.path())
            .args(["service", "uninstall"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert!(!unit.exists());
    }

    #[test]
    fn pair_code_gets_a_fresh_code_from_a_running_node() {
        let home = tempfile::tempdir().unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr = format!("127.0.0.1:{port}");
        let mut serve = super::KillOnDrop(
            rcu(home.path())
                .args(["serve", "--bind", &addr])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let mut lines = BufReader::new(serve.0.stdout.take().unwrap()).lines();
        let first = loop {
            let line = lines.next().expect("serve exited early").unwrap();
            if let Some(rest) = line.strip_prefix("pairing code (5 min): ") {
                break rest.trim().to_string();
            }
        };

        let out = rcu(home.path()).arg("pair-code").output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let code = v["code"].as_str().unwrap();
        assert_eq!(code.len(), 8);
        assert_ne!(code, first, "a new code, not the old one");
        // 읽은 뒤에는 코드가 파일로 남지 않는다.
        assert!(!home.path().join("state/pairing-code").exists());

        // 새 코드로 실제로 페어링된다.
        let ctl = tempfile::tempdir().unwrap();
        let out = rcu(ctl.path())
            .args(["pair", "n", &addr, code, "--print-token"])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    #[test]
    fn pair_code_without_a_node_fails_clearly() {
        let home = tempfile::tempdir().unwrap();
        let out = rcu(home.path()).arg("pair-code").output().unwrap();
        assert_eq!(out.status.code(), Some(1));
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("rcu serve"));
    }

    #[test]
    fn dialog_ui_without_a_display_refuses_to_start() {
        // 디스플레이와 zenity 가 없는 시험 환경에서만 의미가 있다.
        if rcu::dialog::available() {
            return;
        }
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join("policy.toml"),
            "[approval]\nui = \"dialog\"\n",
        )
        .unwrap();
        let out = rcu(home.path())
            .args(["serve", "--bind", "127.0.0.1:0"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(v["error"]["message"].as_str().unwrap().contains("dialog"));
    }
}

#[cfg(unix)]
struct KillOnDrop(std::process::Child);

#[cfg(unix)]
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn systemd_unit_escapes_specifiers_and_expansion() {
    let unit = systemd_unit(Path::new("/opt/100%/$HOME/rcu"), Some(Path::new("/h/%h")));
    assert!(
        unit.contains("ExecStart=\"/opt/100%%/$$HOME/rcu\" serve"),
        "{unit}"
    );
    assert!(unit.contains("Environment=\"RCU_HOME=/h/%%h\""), "{unit}");
    assert!(unit.contains("NoNewPrivileges=yes"));
}
