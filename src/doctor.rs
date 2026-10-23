//! `rcu doctor`: 이 PC 의 설정을 한 번에 점검하고 고칠 방법을 알려 준다.

use crate::config::{self, Nodes};
use crate::policy::Policy;
use crate::secret_store::{DefaultStore, SecretStore};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Info,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

fn check(name: &str, status: Status, detail: impl Into<String>, fix: Option<&str>) -> Check {
    Check {
        name: name.to_string(),
        status,
        detail: detail.into(),
        fix: fix.map(str::to_string),
    }
}

#[cfg(unix)]
fn mode_of(path: &std::path::Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

pub fn run() -> Vec<Check> {
    let mut out = Vec::new();
    out.push(check(
        "version",
        Status::Info,
        format!(
            "rcu {} on {}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS
        ),
        None,
    ));

    // ---- 이 PC 가 노드일 때 ----
    let home = match config::home_dir() {
        Ok(h) => h,
        Err(e) => {
            out.push(check(
                "config directory",
                Status::Fail,
                e.to_string(),
                Some("set RCU_HOME"),
            ));
            return out;
        }
    };
    out.push(check(
        "config directory",
        Status::Info,
        home.display().to_string(),
        None,
    ));

    #[cfg(unix)]
    for (label, path) in [
        ("config directory permissions", home.clone()),
        ("state directory permissions", home.join("state")),
        ("audit directory permissions", home.join("audit")),
    ] {
        if let Some(mode) = mode_of(&path) {
            if mode & 0o077 != 0 {
                out.push(check(
                    label,
                    Status::Warn,
                    format!("{} is {mode:o}; other users can read it", path.display()),
                    Some(&format!("chmod 700 {}", path.display())),
                ));
            }
        }
    }
    #[cfg(unix)]
    if let Some(mode) = mode_of(&home.join("state/tokens.json")) {
        if mode & 0o077 != 0 {
            out.push(check(
                "token file permissions",
                Status::Warn,
                format!("tokens.json is {mode:o}"),
                Some("chmod 600 on state/tokens.json"),
            ));
        }
    }

    let policy_path = home.join("policy.toml");
    let mut policy: Option<Policy> = None;
    if !policy_path.exists() {
        out.push(check(
            "policy",
            Status::Info,
            "no policy file: this PC cannot act as a node (everything is off)",
            Some("run `rcu init`, then edit the policy"),
        ));
    } else {
        match Policy::load(&policy_path) {
            Ok(p) => {
                out.push(check(
                    "policy",
                    Status::Ok,
                    format!("valid; capabilities: {}", p.capabilities().join(", ")),
                    None,
                ));
                for w in p.warnings() {
                    out.push(check("policy warning", Status::Warn, w, None));
                }
                policy = Some(p);
            }
            Err(e) => out.push(check(
                "policy",
                Status::Fail,
                format!("{e:#}"),
                Some("fix policy.toml, then run `rcu policy-check`"),
            )),
        }
    }

    match crate::bind::detect_tailnet_ip() {
        Some(ip) => out.push(check("tailscale", Status::Ok, format!("this PC's tailnet address is {ip}"), None)),
        None => out.push(check(
            "tailscale",
            Status::Warn,
            "could not find this PC's Tailscale address",
            Some("install Tailscale and sign in (https://tailscale.com), or test with `rcu serve --bind 127.0.0.1:7443`"),
        )),
    }

    if let Some(p) = &policy {
        let dialogs = crate::dialog::available();
        use crate::policy::ApprovalUi;
        match (p.approval_ui, dialogs) {
            (ApprovalUi::Dialog, false) => out.push(check(
                "approval dialogs",
                Status::Fail,
                "approval.ui = \"dialog\" but no dialog can be shown here",
                Some("on Linux install zenity and run inside a desktop session, or set approval.ui = \"terminal\""),
            )),
            (ApprovalUi::Terminal, _) => out.push(check(
                "approval dialogs",
                Status::Info,
                "terminal-only approvals: keep `rcu serve` running in a terminal",
                None,
            )),
            (_, true) => out.push(check("approval dialogs", Status::Ok, "OS dialogs are available", None)),
            (_, false) => out.push(check(
                "approval dialogs",
                Status::Warn,
                "no OS dialog available; approvals only work in the terminal running `rcu serve`",
                Some("a background service cannot be approved without dialogs; on Linux install zenity"),
            )),
        }
        if cfg!(target_os = "macos") && (p.screen_enabled || p.input_enabled) {
            out.push(check(
                "macOS permissions",
                Status::Info,
                "screen capture needs Screen Recording, input needs Accessibility, for the app that runs rcu (Terminal, iTerm, launchd)",
                Some("System Settings > Privacy & Security"),
            ));
        }
        if p.exec_enabled && p.warnings().is_empty() {
            // 경고가 없다는 것만 알린다.
        }
    }

    out.push(if crate::service::is_installed() {
        check(
            "login service",
            Status::Ok,
            "rcu serve starts at login",
            None,
        )
    } else {
        check(
            "login service",
            Status::Info,
            "not installed: the node runs only while `rcu serve` is open",
            Some("`rcu service install` to start it at every login"),
        )
    });

    if let Ok(list) =
        crate::tokens::TokenStore::new(config::tokens_path().unwrap_or_default()).list()
    {
        out.push(check(
            "paired controllers",
            Status::Info,
            format!(
                "{} token(s) issued by this node (see `rcu tokens`)",
                list.len()
            ),
            None,
        ));
    }

    // ---- 이 PC 가 컨트롤러일 때 ----
    if let Ok(proxy) = std::env::var("RCU_PROXY") {
        if !proxy.is_empty() {
            let ok = crate::client::proxy_url_ok(&proxy);
            out.push(check(
                "RCU_PROXY",
                if ok { Status::Ok } else { Status::Fail },
                if ok {
                    format!("using {proxy}")
                } else {
                    "not a local socks5 proxy; rcu will refuse to send tokens".to_string()
                },
                if ok {
                    None
                } else {
                    Some("use socks5://localhost:<port> (tailscaled --socks5-server)")
                },
            ));
        }
    }
    match Nodes::load() {
        Ok(nodes) if nodes.nodes.is_empty() => out.push(check(
            "controller",
            Status::Info,
            "no nodes registered on this PC",
            Some("`rcu pair <name> <ip:port> <code>`"),
        )),
        Ok(nodes) => {
            for n in nodes.nodes {
                let label = format!("node {}", n.name);
                let token = DefaultStore.get(&n.name).ok().flatten();
                let Some(token) = token else {
                    out.push(check(
                        &label,
                        Status::Fail,
                        format!("no token stored for {}", n.addr),
                        Some(&format!(
                            "pair again, or set {}",
                            crate::secret_store::env_var_name(&n.name)
                        )),
                    ));
                    continue;
                };
                match crate::client::info(&n.addr, &token) {
                    Ok(info) => out.push(check(
                        &label,
                        Status::Ok,
                        format!(
                            "{} at {} ({}), capabilities: {}",
                            info["name"].as_str().unwrap_or("?"),
                            n.addr,
                            info["os"].as_str().unwrap_or("?"),
                            info["capabilities"]
                        ),
                        None,
                    )),
                    Err(e) => {
                        let fix = match e.code.as_str() {
                            "UNAUTHORIZED" => "the node no longer accepts this token; pair again",
                            "NETWORK_ERROR" => {
                                "is the node running (`rcu serve`) and are both PCs on Tailscale?"
                            }
                            "ADDRESS_DENIED" => {
                                "the address must be a loopback or Tailscale address"
                            }
                            _ => "see the error",
                        };
                        out.push(check(
                            &label,
                            Status::Fail,
                            format!("{}: {}", e.code, e.message),
                            Some(fix),
                        ));
                    }
                }
            }
        }
        Err(e) => out.push(check(
            "controller",
            Status::Fail,
            format!("{e:#}"),
            Some("fix or delete nodes.toml"),
        )),
    }
    out
}

pub fn overall_ok(checks: &[Check]) -> bool {
    !checks.iter().any(|c| c.status == Status::Fail)
}

/// 사람이 읽는 한 줄.
pub fn line(c: &Check) -> String {
    let tag = match c.status {
        Status::Ok => "[ok]  ",
        Status::Info => "[info]",
        Status::Warn => "[warn]",
        Status::Fail => "[FAIL]",
    };
    match &c.fix {
        Some(fix) => format!("{tag} {}: {} -> {fix}", c.name, c.detail),
        None => format!("{tag} {}: {}", c.name, c.detail),
    }
}
