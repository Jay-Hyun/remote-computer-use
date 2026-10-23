use anyhow::Context;
use base64::Engine;
use clap::{Parser, Subcommand};
use rcu::approval::Decision;
use rcu::audit::{Audit, RETENTION_DAYS};
use rcu::client::ClientError;
use rcu::config::{self, NodeEntry, Nodes};
use rcu::pairing::Pairing;
use rcu::policy::{ApprovalUi, Policy};
use rcu::secret_store::{DefaultStore, SecretStore};
use rcu::server::{self, AppState};
use rcu::tokens::TokenStore;
use serde_json::{json, Value};
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "rcu",
    version,
    about = "remote-computer-use: node agent and controller CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// (노드) 에이전트를 켠다. 루프백 또는 테일스케일 주소에서만 듣는다.
    Serve {
        /// ip:port. 생략하면 이 PC 의 테일스케일 주소(`tailscale ip -4`):7443 을 쓴다.
        #[arg(long)]
        bind: Option<String>,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// (노드) 안전한 기본 정책 파일(모든 능력 꺼짐)을 만든다. 이미 있으면 건드리지 않는다.
    Init,
    /// (노드) 로그인할 때 `rcu serve` 를 자동으로 띄우는 사용자 서비스를 등록·해제한다.
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
    /// (노드) 실행 중인 노드에서 새 페어링 코드를 받아 출력한다(서비스로 돌 때 터미널이 없으므로).
    PairCode,
    /// (노드) 발급한 토큰을 모두 폐기한다.
    Revoke {
        #[arg(long)]
        all: bool,
    },
    /// (노드) 정책 파일을 검사한다.
    PolicyCheck {
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// (컨트롤러) 노드 화면의 코드로 페어링하고 토큰을 보안 저장소에 둔다.
    Pair {
        name: String,
        addr: String,
        code: String,
        /// OS 보안 저장소가 없는 시스템(리눅스·클라우드)용. 토큰을 출력한다.
        /// 사람이 직접 실행해 환경 시크릿 RCU_TOKEN_<NAME> 에 넣을 때만 쓴다.
        #[arg(long)]
        print_token: bool,
    },
    /// (컨트롤러) 노드 정보를 읽는다.
    Info { name: String },
    /// (컨트롤러) 노드에서 명령을 실행한다. 예: rcu exec mac -- /usr/bin/git status
    Exec {
        node: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    /// (컨트롤러) 노드의 파일을 읽는다.
    Read { node: String, path: String },
    /// (컨트롤러) 노드에 파일을 쓴다. 내용은 표준 입력에서 읽는다.
    Write {
        node: String,
        path: String,
        /// 이미 있는 파일을 덮어쓴다(노드에서 매번 승인, 백업 `.rcu-bak` 생성).
        #[arg(long)]
        overwrite: bool,
    },
    /// (컨트롤러) 승인 대기 중이던 요청의 결과를 기다린다(최대 60초). 같은 요청을 다시 보내지 말 것.
    Wait {
        approval_id: String,
        #[arg(long)]
        node: String,
    },
    /// (컨트롤러) 등록된 노드 목록.
    Nodes,
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// 서비스를 등록하고 바로 시작한다.
    Install {
        /// 파일만 쓰고 시작하지 않는다.
        #[arg(long)]
        no_start: bool,
    },
    /// 서비스를 멈추고 등록을 지운다.
    Uninstall,
}

fn print(value: Value) {
    println!("{value}");
}

fn fail(err: &ClientError) -> ! {
    let mut error = json!({ "code": err.code, "message": err.message });
    if let Some(id) = &err.approval_id {
        error["approval_id"] = json!(id);
    }
    print(json!({ "error": error }));
    std::process::exit(err.exit_code());
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Cmd::Serve { bind, policy } => serve(bind, policy),
        Cmd::Init => init(),
        Cmd::Service { action } => service(action),
        Cmd::PairCode => pair_code(),
        Cmd::Revoke { all } => revoke(all),
        Cmd::PolicyCheck { policy } => policy_check(policy),
        Cmd::Pair {
            name,
            addr,
            code,
            print_token,
        } => pair(&name, &addr, &code, print_token),
        Cmd::Info { name } => info(&name),
        Cmd::Exec { node, cmd } => exec(&node, &cmd),
        Cmd::Read { node, path } => read(&node, &path),
        Cmd::Write {
            node,
            path,
            overwrite,
        } => write(&node, &path, overwrite),
        Cmd::Wait { approval_id, node } => wait(&node, &approval_id),
        Cmd::Nodes => nodes(),
    };
    if let Err(e) = result {
        match e.downcast::<ClientError>() {
            Ok(client_err) => fail(&client_err),
            Err(e) => fail(&ClientError::new("INTERNAL", format!("{e:#}"))),
        }
    }
}

const DEFAULT_PORT: u16 = 7443;

fn resolve_bind(bind: Option<String>) -> anyhow::Result<SocketAddr> {
    match bind {
        Some(b) => {
            let addr: SocketAddr = b.parse().context("--bind must be ip:port")?;
            rcu::bind::check_ip(addr.ip())?;
            Ok(addr)
        }
        None => match rcu::bind::detect_tailnet_ip() {
            Some(ip) => Ok(SocketAddr::new(ip, DEFAULT_PORT)),
            None => anyhow::bail!(
                "could not find this PC's Tailscale address (is Tailscale installed and logged in?). \
                 Install/log in to Tailscale, or test locally with --bind 127.0.0.1:{DEFAULT_PORT}"
            ),
        },
    }
}

fn service(action: ServiceCmd) -> anyhow::Result<()> {
    let (outcome, installing) = match action {
        ServiceCmd::Install { no_start } => (rcu::service::install(!no_start)?, true),
        ServiceCmd::Uninstall => (rcu::service::uninstall()?, false),
    };
    print(json!({
        if installing { "installed" } else { "uninstalled" }: true,
        "unit": outcome.unit_path,
        "started": outcome.started,
        "notes": outcome.notes,
        "next": if installing {
            json!(["rcu pair-code   (prints a pairing code from the running node)"])
        } else {
            json!([])
        },
    }));
    if installing && outcome.unit_path.is_some() && !outcome.started && !outcome.notes.is_empty() {
        anyhow::bail!(
            "service written but could not be started: {}",
            outcome.notes.join("; ")
        );
    }
    Ok(())
}

/// 서비스로 도는 노드에서 새 페어링 코드를 받는다: 요청 파일을 두면 노드가 코드를 만들어 파일에 적는다.
fn pair_code() -> anyhow::Result<()> {
    let request = config::pair_request_path()?;
    let answer = config::pairing_code_path()?;
    std::fs::create_dir_all(config::state_dir()?)?;
    let _ = std::fs::remove_file(&answer);
    std::fs::write(&request, b"")?;
    for _ in 0..40 {
        if let Ok(code) = std::fs::read_to_string(&answer) {
            let code = code.trim().to_string();
            if !code.is_empty() {
                let _ = std::fs::remove_file(&answer);
                print(json!({ "code": code, "expires_in_secs": 300 }));
                return Ok(());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let _ = std::fs::remove_file(&request);
    anyhow::bail!("no answer from the node within 10 s; is `rcu serve` (or the service) running with the same RCU_HOME?")
}

fn init() -> anyhow::Result<()> {
    let path = config::policy_path()?;
    let created = !path.exists();
    if created {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, include_str!("../examples/policy.default.toml"))?;
    }
    print(json!({
        "policy": path,
        "created": created,
        "next": [
            "edit the policy file to turn on only what you need (everything is off by default)",
            "rcu policy-check",
            "rcu serve   (prints a pairing code; keep this terminal open to approve requests)"
        ]
    }));
    Ok(())
}

fn serve(bind: Option<String>, policy: Option<PathBuf>) -> anyhow::Result<()> {
    let addr = resolve_bind(bind)?;

    let policy_path = match policy {
        Some(p) => p,
        None => config::policy_path()?,
    };
    let policy = Policy::load(&policy_path).context("policy file is invalid")?;
    let audit = Audit::new(config::audit_dir()?);
    let removed = audit.prune(time::OffsetDateTime::now_utc().date(), RETENTION_DAYS)?;
    if removed > 0 {
        eprintln!("pruned {removed} old audit files");
    }

    let pairing = Pairing::new(Instant::now());
    let code = pairing.current_code().unwrap_or_default().to_string();
    let grant_minutes = policy.grant_minutes;
    let use_dialog = match policy.approval_ui {
        ApprovalUi::Terminal => false,
        ApprovalUi::Auto => rcu::dialog::available(),
        ApprovalUi::Dialog => {
            if !rcu::dialog::available() {
                anyhow::bail!(
                    "approval.ui = \"dialog\" but no dialog is available here (Linux needs a display and zenity)"
                );
            }
            true
        }
    };
    let state = Arc::new(AppState::new(
        policy,
        TokenStore::new(config::tokens_path()?),
        pairing,
        audit,
    ));
    let gate_for_dialog = Arc::clone(&state.gate);
    state.gate.set_notifier(Box::new(move |p| {
        if use_dialog {
            let runner: rcu::dialog::Runner = Arc::new(move |info, still_waiting| {
                rcu::dialog::show(info, grant_minutes, still_waiting)
            });
            rcu::dialog::spawn_prompt(
                Arc::clone(&gate_for_dialog),
                p.clone(),
                runner,
                |info, d| {
                    let verdict = if d == Decision::Deny {
                        "denied"
                    } else {
                        "allowed"
                    };
                    println!("[approval {}] {verdict} (dialog)", info.id);
                },
            );
        }
        println!(
            "\n[approval {}] {} ({}): {}",
            p.id,
            p.capability,
            p.risk.as_str(),
            p.summary
        );
        if p.risk.always_needs_approval() {
            println!("  y = allow once, n = deny (this kind is asked every time)");
        } else {
            println!("  y = allow once, a = allow {grant_minutes} min, n = deny");
        }
    }));

    println!(
        "rcu node \"{}\" listening on {addr}",
        state.policy.node_name
    );
    println!("capabilities: {}", state.policy.capabilities().join(", "));
    println!("pairing code (5 min): {code}");
    println!(
        "press Enter for a new pairing code; answer y / a / n when a request asks for approval"
    );

    let for_stdin = Arc::clone(&state);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        while matches!(stdin.read_line(&mut line), Ok(n) if n > 0) {
            let answer = line.trim().to_ascii_lowercase();
            line.clear();
            if for_stdin.gate.waiting().is_empty() {
                let code = for_stdin.pairing.lock().unwrap().refresh(Instant::now());
                println!("pairing code (5 min): {code}");
                continue;
            }
            let decision = match answer.as_str() {
                "y" | "yes" => Decision::Once,
                "a" | "always" => Decision::Grant,
                "n" | "no" => Decision::Deny,
                _ => {
                    println!("a request is waiting: answer y, a or n");
                    continue;
                }
            };
            if let Some(info) = for_stdin.gate.resolve(None, decision) {
                let verdict = match decision {
                    Decision::Deny => "denied",
                    _ => "allowed",
                };
                println!("[approval {}] {verdict}", info.id);
            }
        }
    });

    // `rcu pair-code` 요청 처리: 요청 파일이 보이면 새 코드를 만들어 파일에 적는다.
    let request_path = config::pair_request_path()?;
    let answer_path = config::pairing_code_path()?;
    let _ = std::fs::remove_file(&request_path);
    let _ = std::fs::remove_file(&answer_path);
    let for_requests = Arc::clone(&state);
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(300));
        if request_path.exists() {
            let _ = std::fs::remove_file(&request_path);
            let code = for_requests.pairing.lock().unwrap().refresh(Instant::now());
            if write_private(&answer_path, &code).is_ok() {
                println!("pairing code (5 min): {code}");
            }
        }
    });

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        server::serve(listener, state).await?;
        anyhow::Ok(())
    })
}

fn write_private(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    std::fs::write(path, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn revoke(all: bool) -> anyhow::Result<()> {
    if !all {
        anyhow::bail!("use --all to revoke every token on this node");
    }
    let n = TokenStore::new(config::tokens_path()?).revoke_all()?;
    print(json!({ "revoked": n }));
    Ok(())
}

fn policy_check(path: Option<PathBuf>) -> anyhow::Result<()> {
    let path = match path {
        Some(p) => p,
        None => config::policy_path()?,
    };
    let policy = Policy::load(&path).context("policy file is invalid")?;
    print(json!({ "ok": true, "name": policy.node_name, "capabilities": policy.capabilities() }));
    Ok(())
}

fn pair(name: &str, addr: &str, code: &str, print_token: bool) -> anyhow::Result<()> {
    let resp = rcu::client::pair(addr, code, &controller_label())?;
    let token = resp["token"].as_str().context("node sent no token")?;
    let mut out = json!({ "paired": name, "node": resp["node"] });
    if print_token {
        out["token"] = json!(token);
        out["env_var"] = json!(rcu::secret_store::env_var_name(name));
    } else {
        DefaultStore.set(name, token)?;
    }
    let mut nodes = Nodes::load()?;
    nodes.upsert(NodeEntry {
        name: name.to_string(),
        addr: addr.to_string(),
    });
    nodes.save()?;
    print(out);
    Ok(())
}

/// 등록된 노드의 주소와 보관된 토큰.
fn node_and_token(name: &str) -> anyhow::Result<(String, String)> {
    let nodes = Nodes::load()?;
    let node = nodes.get(name).ok_or_else(|| {
        ClientError::new("UNKNOWN_NODE", "node is not registered; run `rcu nodes`")
    })?;
    let token = DefaultStore.get(name)?.ok_or_else(|| {
        ClientError::new(
            "UNAUTHORIZED",
            format!(
                "no token for this node; pair first, or set {} from an environment secret",
                rcu::secret_store::env_var_name(name)
            ),
        )
    })?;
    Ok((node.addr.clone(), token))
}

fn info(name: &str) -> anyhow::Result<()> {
    let (addr, token) = node_and_token(name)?;
    print(rcu::client::info(&addr, &token)?);
    Ok(())
}

fn exec(node: &str, cmd: &[String]) -> anyhow::Result<()> {
    let (addr, token) = node_and_token(node)?;
    let (program, args) = cmd.split_first().context("no command given")?;
    print(rcu::client::exec(&addr, &token, program, args)?);
    Ok(())
}

fn read(node: &str, path: &str) -> anyhow::Result<()> {
    let (addr, token) = node_and_token(node)?;
    print(with_text(rcu::client::fs_read(&addr, &token, path)?));
    Ok(())
}

/// `wait` 결과가 파일 읽기이면 읽기 좋게 `text` 를 덧붙인다(UTF-8 일 때만).
fn with_text(mut value: Value) -> Value {
    let text = value["content_b64"]
        .as_str()
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok());
    if let Some(text) = text {
        value["text"] = json!(text);
    }
    value
}

fn write(node: &str, path: &str, overwrite: bool) -> anyhow::Result<()> {
    const MAX_STDIN: u64 = 8 * 1024 * 1024;
    let (addr, token) = node_and_token(node)?;
    let mut data = Vec::new();
    std::io::stdin()
        .take(MAX_STDIN + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_STDIN {
        anyhow::bail!("stdin is larger than 8 MiB");
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
    print(rcu::client::fs_write(&addr, &token, path, &b64, overwrite)?);
    Ok(())
}

fn wait(node: &str, approval_id: &str) -> anyhow::Result<()> {
    let (addr, token) = node_and_token(node)?;
    print(with_text(rcu::client::wait(&addr, &token, approval_id)?));
    Ok(())
}

fn nodes() -> anyhow::Result<()> {
    let list: Vec<Value> = Nodes::load()?
        .nodes
        .iter()
        .map(|n| {
            let paired = DefaultStore.get(&n.name).ok().flatten().is_some();
            json!({ "name": n.name, "addr": n.addr, "paired": paired })
        })
        .collect();
    print(json!({ "nodes": list }));
    Ok(())
}

fn controller_label() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "controller".to_string())
}
