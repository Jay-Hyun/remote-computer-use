//! 로그인할 때 `rcu serve` 를 자동으로 띄우는 사용자 단위 서비스(sudo 없음).
//!
//! 승인은 OS 대화상자로 받는다(`approval.ui`), 서비스에는 터미널이 없기 때문이다.
//! - 맥: launchd 사용자 에이전트
//! - 리눅스: systemd 사용자 유닛
//! - 윈도우: 로그온 시 실행되는 예약 작업(사용자 세션이라 대화상자가 보인다)

use anyhow::Context;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const LABEL: &str = "io.github.jay-hyun.rcu";
pub const UNIT_NAME: &str = "rcu-node.service";
pub const TASK_NAME: &str = "rcu-node";

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn launchd_plist(exe: &Path, rcu_home: Option<&Path>, log: &Path) -> String {
    let env = rcu_home
        .map(|h| {
            format!(
                "  <key>EnvironmentVariables</key>\n  <dict>\n    <key>RCU_HOME</key>\n    <string>{}</string>\n  </dict>\n",
                xml_escape(&h.to_string_lossy())
            )
        })
        .unwrap_or_default();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\
  <key>Label</key>\n  <string>{LABEL}</string>\n\
  <key>ProgramArguments</key>\n  <array>\n    <string>{exe}</string>\n    <string>serve</string>\n  </array>\n\
{env}\
  <key>RunAtLoad</key>\n  <true/>\n\
  <key>KeepAlive</key>\n  <true/>\n\
  <key>ThrottleInterval</key>\n  <integer>15</integer>\n\
  <key>StandardOutPath</key>\n  <string>{log}</string>\n\
  <key>StandardErrorPath</key>\n  <string>{log}</string>\n\
</dict>\n</plist>\n",
        exe = xml_escape(&exe.to_string_lossy()),
        log = xml_escape(&log.to_string_lossy()),
    )
}

/// systemd 는 `%h` 같은 지정자와 `$VAR` 를 풀어 쓰므로 `%`·`$` 도 이스케이프한다.
fn systemd_quote(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    )
}

/// 줄바꿈이 든 경로는 유닛/설정 파일에 지시문을 끼워 넣을 수 있으므로 설치를 거부한다.
fn check_path_text(label: &str, p: &Path) -> anyhow::Result<()> {
    if p.to_string_lossy()
        .chars()
        .any(|c| c == '\n' || c == '\r' || c == '\0')
    {
        anyhow::bail!("{label} contains a newline or NUL; refusing to write a service file");
    }
    Ok(())
}

pub fn systemd_unit(exe: &Path, rcu_home: Option<&Path>) -> String {
    let env = rcu_home
        .map(|h| {
            format!(
                "Environment={}\n",
                systemd_quote(&format!("RCU_HOME={}", h.to_string_lossy()))
            )
        })
        .unwrap_or_default();
    format!(
        "[Unit]\nDescription=rcu node (remote-computer-use)\nAfter=network-online.target\n\n\
[Service]\nExecStart={exe} serve\n{env}Restart=on-failure\nRestartSec=15\nNoNewPrivileges=yes\n\n\
[Install]\nWantedBy=default.target\n",
        exe = systemd_quote(&exe.to_string_lossy()),
    )
}

/// `schtasks /Create` 인자. /TR 은 경로에 공백이 있어도 되도록 따옴표로 감싼다.
pub fn schtasks_create_args(exe: &Path) -> Vec<String> {
    vec![
        "/Create".into(),
        "/TN".into(),
        TASK_NAME.into(),
        "/TR".into(),
        format!("\"{}\" serve", exe.to_string_lossy()),
        "/SC".into(),
        "ONLOGON".into(),
        "/RL".into(),
        "LIMITED".into(),
        "/F".into(),
    ]
}

#[derive(Debug)]
pub struct Outcome {
    pub unit_path: Option<PathBuf>,
    pub started: bool,
    pub notes: Vec<String>,
}

fn run(program: &str, args: &[&str], notes: &mut Vec<String>) -> bool {
    match Command::new(program).args(args).output() {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            notes.push(format!(
                "`{program} {}` failed: {}",
                args.join(" "),
                err.trim()
            ));
            false
        }
        Err(e) => {
            notes.push(format!("could not run {program}: {e}"));
            false
        }
    }
}

fn home_override() -> Option<PathBuf> {
    std::env::var_os("RCU_HOME").map(PathBuf::from)
}

#[cfg(target_os = "macos")]
fn unit_path() -> anyhow::Result<PathBuf> {
    let base = directories::BaseDirs::new().context("no home directory")?;
    Ok(base
        .home_dir()
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn unit_path() -> anyhow::Result<PathBuf> {
    let base = directories::BaseDirs::new().context("no home directory")?;
    Ok(base.config_dir().join("systemd/user").join(UNIT_NAME))
}

#[cfg(unix)]
fn write_unit(path: &Path, text: &str) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, text)?;
    Ok(())
}

/// 로그인 서비스가 등록되어 있는지.
pub fn is_installed() -> bool {
    #[cfg(unix)]
    {
        unit_path().map(|p| p.exists()).unwrap_or(false)
    }
    #[cfg(windows)]
    {
        Command::new("schtasks")
            .args(["/Query", "/TN", TASK_NAME])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

pub fn install(start: bool) -> anyhow::Result<Outcome> {
    let exe = std::env::current_exe().context("cannot find the rcu executable")?;
    check_path_text("the rcu executable path", &exe)?;
    if let Some(home) = home_override() {
        check_path_text("RCU_HOME", &home)?;
    }
    let mut notes = Vec::new();

    #[cfg(target_os = "macos")]
    {
        let path = unit_path()?;
        let log = crate::config::home_dir()?.join("node.log");
        if let Some(dir) = log.parent() {
            std::fs::create_dir_all(dir)?;
        }
        write_unit(
            &path,
            &launchd_plist(&exe, home_override().as_deref(), &log),
        )?;
        let mut started = false;
        if start {
            // SAFETY: getuid 는 항상 성공하는 읽기 전용 호출이다.
            let domain = format!("gui/{}", unsafe { libc::getuid() });
            let _ = Command::new("launchctl")
                .args(["bootout", &format!("{domain}/{LABEL}")])
                .output();
            started = run(
                "launchctl",
                &["bootstrap", &domain, &path.to_string_lossy()],
                &mut notes,
            );
        }
        return Ok(Outcome {
            unit_path: Some(path),
            started,
            notes,
        });
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let path = unit_path()?;
        write_unit(&path, &systemd_unit(&exe, home_override().as_deref()))?;
        let mut started = false;
        if start {
            started = run("systemctl", &["--user", "daemon-reload"], &mut notes)
                && run(
                    "systemctl",
                    &["--user", "enable", "--now", UNIT_NAME],
                    &mut notes,
                );
            if started {
                notes.push(
                    "to keep it running when you are logged out: loginctl enable-linger $USER"
                        .to_string(),
                );
            }
        }
        return Ok(Outcome {
            unit_path: Some(path),
            started,
            notes,
        });
    }

    #[cfg(windows)]
    {
        if home_override().is_some() {
            notes.push(
                "RCU_HOME is ignored by the scheduled task; it uses the default config location"
                    .into(),
            );
        }
        let args = schtasks_create_args(&exe);
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let created = run("schtasks", &arg_refs, &mut notes);
        let started = created && start && run("schtasks", &["/Run", "/TN", TASK_NAME], &mut notes);
        if !created {
            anyhow::bail!("could not create the scheduled task: {}", notes.join("; "));
        }
        return Ok(Outcome {
            unit_path: None,
            started,
            notes,
        });
    }

    #[allow(unreachable_code)]
    {
        let _ = (exe, start, &mut notes);
        anyhow::bail!("service install is not supported on this platform")
    }
}

pub fn uninstall() -> anyhow::Result<Outcome> {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut notes = Vec::new();

    #[cfg(target_os = "macos")]
    {
        let path = unit_path()?;
        // SAFETY: getuid 는 항상 성공하는 읽기 전용 호출이다.
        let domain = format!("gui/{}", unsafe { libc::getuid() });
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{LABEL}")])
            .output();
        let existed = path.exists();
        if existed {
            std::fs::remove_file(&path)?;
        }
        return Ok(Outcome {
            unit_path: existed.then_some(path),
            started: false,
            notes,
        });
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let path = unit_path()?;
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", UNIT_NAME])
            .output();
        let existed = path.exists();
        if existed {
            std::fs::remove_file(&path)?;
            let _ = Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .output();
        }
        return Ok(Outcome {
            unit_path: existed.then_some(path),
            started: false,
            notes,
        });
    }

    #[cfg(windows)]
    {
        let _ = Command::new("schtasks")
            .args(["/End", "/TN", TASK_NAME])
            .output();
        run("schtasks", &["/Delete", "/TN", TASK_NAME, "/F"], &mut notes);
        return Ok(Outcome {
            unit_path: None,
            started: false,
            notes,
        });
    }

    #[allow(unreachable_code)]
    {
        let _ = &mut notes;
        anyhow::bail!("service uninstall is not supported on this platform")
    }
}
