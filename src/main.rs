use anyhow::Context;
use base64::Engine;
use clap::{Parser, Subcommand};
use rcu::approval::{parse_terminal_answer, Decision, ResolveError};
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
        /// 토큰 id(`rcu tokens` 에서 확인). 하나만 폐기한다.
        id: Option<String>,
        /// 발급한 토큰을 모두 폐기한다.
        #[arg(long)]
        all: bool,
    },
    /// (노드) 발급된 토큰 목록(id, 라벨, 생성·만료 시각). 토큰 값은 노드에도 없다.
    Tokens,
    /// (컨트롤러) 노드 등록과 보관된 토큰을 지운다.
    Unpair { node: String },
    /// 이 PC 설정을 한 번에 점검하고 고칠 방법을 알려 준다(노드·컨트롤러 모두).
    Doctor,
    /// 셸 자동완성 스크립트를 출력한다.
    Completions { shell: clap_complete::Shell },
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
    /// (컨트롤러) 노드 화면을 PNG 로 저장한다. 이미지는 `--out` 파일에만 저장되고 출력에는 크기만 나온다.
    Screen {
        node: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// (컨트롤러) 노드 화면의 좌표를 클릭한다(노드 화면 좌표계: 출력의 screen_width/height 기준).
    Click {
        node: String,
        x: i32,
        y: i32,
        #[arg(long, default_value = "left")]
        button: String,
    },
    /// (컨트롤러) 노드에서 글자를 입력한다. 글자는 인자로 주거나 생략하고 표준 입력으로 준다.
    Type {
        node: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        text: Vec<String>,
    },
    /// (컨트롤러) 노드에서 키 조합을 누른다. 예: ctrl+c, enter, cmd+space
    Key { node: String, combo: String },
    /// (컨트롤러) 승인 대기 중이던 요청의 결과를 기다린다(최대 60초). 같은 요청을 다시 보내지 말 것.
    Wait {
        approval_id: String,
        #[arg(long)]
        node: String,
        /// 대기하던 요청이 스크린샷이면 저장할 PNG 경로.
        #[arg(long)]
        out: Option<PathBuf>,
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
        Cmd::Revoke { all, id } => revoke(all, id.as_deref()),
        Cmd::Tokens => tokens(),
        Cmd::Unpair { node } => unpair(&node),
        Cmd::Doctor => doctor(),
        Cmd::Completions { shell } => completions(shell),
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
        Cmd::Wait {
            approval_id,
            node,
            out,
        } => wait(&node, &approval_id, out.as_deref()),
        Cmd::Screen { node, out } => screen(&node, &out),
        Cmd::Click { node, x, y, button } => click(&node, x, y, &button),
        Cmd::Type { node, text } => type_text(&node, &text),
        Cmd::Key { node, combo } => key(&node, &combo),
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
            rcu::bind::check_bind(addr.ip())?;
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
    config::create_private_dir(&config::state_dir()?)?;
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
            config::create_private_dir(dir)?;
        }
        config::write_private(
            &path,
            include_str!("../examples/policy.default.toml").as_bytes(),
        )?;
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
    let mut policy = Policy::load(&policy_path).context("policy file is invalid")?;
    // 노드 자신의 설정·상태(정책, 토큰 해시, 감사 로그, 페어링 파일)는 파일 능력으로 건드릴 수 없다.
    policy.protect(config::home_dir()?);
    policy.protect(policy_path.clone());
    for warning in policy.warnings() {
        eprintln!("policy warning: {warning}");
    }
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
    // 터미널의 맨 `y` 가 방금 도착한 요청에 잘못 걸리지 않도록 마지막 질문 시각을 기억한다.
    let last_prompt = Arc::new(std::sync::Mutex::new(Instant::now()));
    let last_prompt_for_notifier = Arc::clone(&last_prompt);
    state.gate.set_notifier(Box::new(move |p| {
        *last_prompt_for_notifier.lock().unwrap() = Instant::now();
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
            println!(
                "  answer: `y {0}` = allow once, `n {0}` = deny (this kind is asked every time)",
                p.id
            );
        } else {
            println!(
                "  answer: `y {0}` = allow once, `a {0}` = allow {grant_minutes} min, `n {0}` = deny",
                p.id
            );
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
            let text = std::mem::take(&mut line);
            let waiting = for_stdin.gate.waiting();
            if waiting.is_empty() {
                let code = for_stdin.pairing.lock().unwrap().refresh(Instant::now());
                println!("pairing code (5 min): {code}");
                continue;
            }
            let Some(answer) = parse_terminal_answer(&text) else {
                println!("a request is waiting: answer `y <id>`, `a <id>` or `n <id>`");
                continue;
            };
            let resolved = match &answer.id {
                Some(prefix) => for_stdin.gate.resolve_prefix(prefix, answer.decision),
                None if waiting.len() == 1 => {
                    // 방금 도착한 요청을 읽기도 전에 미리 쳐 둔 답이 승인하는 일을 막는다.
                    if last_prompt.lock().unwrap().elapsed()
                        < std::time::Duration::from_millis(1500)
                    {
                        println!(
                            "(ignored: that request just arrived; read it, then answer again)"
                        );
                        continue;
                    }
                    for_stdin
                        .gate
                        .resolve(Some(&waiting[0].id), answer.decision)
                        .ok_or(ResolveError::NoMatch)
                }
                None => {
                    println!(
                        "several requests are waiting; answer with an id, e.g. `y {}`:",
                        waiting[0].id
                    );
                    for p in &waiting {
                        println!(
                            "  {} {} ({}): {}",
                            p.id,
                            p.capability,
                            p.risk.as_str(),
                            p.summary
                        );
                    }
                    continue;
                }
            };
            match resolved {
                Ok(info) => {
                    let verdict = if answer.decision == Decision::Deny {
                        "denied"
                    } else {
                        "allowed"
                    };
                    println!("[approval {}] {verdict}: {}", info.id, info.summary);
                }
                Err(ResolveError::NoMatch) => println!("no waiting request matches that id"),
                Err(ResolveError::Ambiguous) => {
                    println!("that id prefix matches several requests; type more of it")
                }
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
            if config::write_private(&answer_path, code.as_bytes()).is_ok() {
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

fn revoke(all: bool, id: Option<&str>) -> anyhow::Result<()> {
    let store = TokenStore::new(config::tokens_path()?);
    let n = match (all, id) {
        (true, None) => store.revoke_all()?,
        (false, Some(id)) => store.revoke(id)?,
        _ => anyhow::bail!("use either --all or one token id (see `rcu tokens`)"),
    };
    print(json!({ "revoked": n }));
    Ok(())
}

fn policy_check(path: Option<PathBuf>) -> anyhow::Result<()> {
    let path = match path {
        Some(p) => p,
        None => config::policy_path()?,
    };
    let policy = Policy::load(&path).context("policy file is invalid")?;
    print(json!({
        "ok": true,
        "name": policy.node_name,
        "capabilities": policy.capabilities(),
        "warnings": policy.warnings(),
    }));
    Ok(())
}

fn pair(name: &str, addr: &str, code: &str, print_token: bool) -> anyhow::Result<()> {
    if !rcu::secret_store::valid_node_name(name) {
        return Err(ClientError::new(
            "BAD_NODE_NAME",
            "node names are 1-32 characters: lowercase letters, digits and hyphens (e.g. work-mac)",
        )
        .into());
    }
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
        node_name: resp["node"].as_str().map(str::to_string),
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
    let mut value = rcu::client::info(&addr, &token)?;
    // 페어링 때 본 노드 이름과 다르면 알린다(주소가 다른 PC 로 바뀌었을 수 있다).
    let nodes = Nodes::load()?;
    if let (Some(pinned), Some(now)) = (
        nodes.get(name).and_then(|n| n.node_name.clone()),
        value["name"].as_str(),
    ) {
        if pinned != now {
            value["warning"] = json!(format!(
                "this node introduced itself as \"{pinned}\" when you paired, but now answers as \"{now}\"; make sure the address still points at the PC you meant"
            ));
        }
    }
    print(value);
    Ok(())
}

fn unpair(name: &str) -> anyhow::Result<()> {
    let mut nodes = Nodes::load()?;
    let before = nodes.nodes.len();
    nodes.nodes.retain(|n| n.name != name);
    let removed = before - nodes.nodes.len();
    nodes.save()?;
    let secret_error = DefaultStore.delete(name).err().map(|e| format!("{e:#}"));
    print(json!({
        "unpaired": name,
        "was_registered": removed > 0,
        "secret_error": secret_error,
        "note": "tokens held in the environment (RCU_TOKEN_*) are not touched; to cut access completely, also run `rcu revoke <id>` on the node",
    }));
    Ok(())
}

fn tokens() -> anyhow::Result<()> {
    let list = TokenStore::new(config::tokens_path()?).list()?;
    print(json!({ "tokens": list }));
    Ok(())
}

fn doctor() -> anyhow::Result<()> {
    let checks = rcu::doctor::run();
    for c in &checks {
        eprintln!("{}", rcu::doctor::line(c));
    }
    let ok = rcu::doctor::overall_ok(&checks);
    print(json!({ "ok": ok, "checks": checks }));
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

fn completions(shell: clap_complete::Shell) -> anyhow::Result<()> {
    use clap::CommandFactory;
    clap_complete::generate(shell, &mut Cli::command(), "rcu", &mut std::io::stdout());
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

fn wait(node: &str, approval_id: &str, out: Option<&std::path::Path>) -> anyhow::Result<()> {
    let (addr, token) = node_and_token(node)?;
    let value = rcu::client::wait(&addr, &token, approval_id)?;
    print(with_text(rcu::client::save_screenshot(value, out)?));
    Ok(())
}

fn screen(node: &str, out: &std::path::Path) -> anyhow::Result<()> {
    let (addr, token) = node_and_token(node)?;
    let value = rcu::client::screen(&addr, &token)?;
    print(rcu::client::save_screenshot(value, Some(out))?);
    Ok(())
}

fn click(node: &str, x: i32, y: i32, button: &str) -> anyhow::Result<()> {
    let (addr, token) = node_and_token(node)?;
    print(rcu::client::click(&addr, &token, x, y, button)?);
    Ok(())
}

fn type_text(node: &str, text: &[String]) -> anyhow::Result<()> {
    let (addr, token) = node_and_token(node)?;
    let text = if text.is_empty() {
        let mut buf = String::new();
        std::io::stdin().take(64 * 1024).read_to_string(&mut buf)?;
        buf.trim_end_matches('\n').to_string()
    } else {
        text.join(" ")
    };
    print(rcu::client::type_text(&addr, &token, &text)?);
    Ok(())
}

fn key(node: &str, combo: &str) -> anyhow::Result<()> {
    let (addr, token) = node_and_token(node)?;
    print(rcu::client::key(&addr, &token, combo)?);
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
