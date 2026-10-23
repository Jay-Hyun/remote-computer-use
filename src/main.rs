use anyhow::Context;
use clap::{Parser, Subcommand};
use rcu::audit::{Audit, RETENTION_DAYS};
use rcu::client::ClientError;
use rcu::config::{self, NodeEntry, Nodes};
use rcu::pairing::Pairing;
use rcu::policy::Policy;
use rcu::secret_store::{DefaultStore, SecretStore};
use rcu::server::{self, AppState};
use rcu::tokens::TokenStore;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
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
        #[arg(long, default_value = "127.0.0.1:7443")]
        bind: String,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
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
    /// (컨트롤러) 등록된 노드 목록.
    Nodes,
}

fn print(value: Value) {
    println!("{value}");
}

fn fail(err: &ClientError) -> ! {
    print(json!({ "error": { "code": err.code, "message": err.message } }));
    std::process::exit(err.exit_code());
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Cmd::Serve { bind, policy } => serve(&bind, policy),
        Cmd::Revoke { all } => revoke(all),
        Cmd::PolicyCheck { policy } => policy_check(policy),
        Cmd::Pair {
            name,
            addr,
            code,
            print_token,
        } => pair(&name, &addr, &code, print_token),
        Cmd::Info { name } => info(&name),
        Cmd::Nodes => nodes(),
    };
    if let Err(e) = result {
        match e.downcast::<ClientError>() {
            Ok(client_err) => fail(&client_err),
            Err(e) => fail(&ClientError {
                code: "INTERNAL".into(),
                message: format!("{e:#}"),
            }),
        }
    }
}

fn serve(bind: &str, policy: Option<PathBuf>) -> anyhow::Result<()> {
    let addr: SocketAddr = bind.parse().context("--bind must be ip:port")?;
    rcu::bind::check_ip(addr.ip())?;

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
    let state = Arc::new(AppState {
        policy,
        tokens: Mutex::new(TokenStore::new(config::tokens_path()?)),
        pairing: Mutex::new(pairing),
        audit,
    });

    println!(
        "rcu node \"{}\" listening on {addr}",
        state.policy.node_name
    );
    println!("capabilities: {}", state.policy.capabilities().join(", "));
    println!("pairing code (5 min): {code}");
    println!("press Enter for a new pairing code");

    let for_stdin = Arc::clone(&state);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        while matches!(stdin.read_line(&mut line), Ok(n) if n > 0) {
            line.clear();
            let code = for_stdin.pairing.lock().unwrap().refresh(Instant::now());
            println!("pairing code (5 min): {code}");
        }
    });

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        server::serve(listener, state).await?;
        anyhow::Ok(())
    })
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

fn info(name: &str) -> anyhow::Result<()> {
    let nodes = Nodes::load()?;
    let node = nodes.get(name).ok_or_else(|| ClientError {
        code: "UNKNOWN_NODE".into(),
        message: "node is not registered; run `rcu nodes`".into(),
    })?;
    let token = DefaultStore.get(name)?.ok_or_else(|| ClientError {
        code: "UNAUTHORIZED".into(),
        message: "no token for this node; pair first".into(),
    })?;
    print(rcu::client::info(&node.addr, &token)?);
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
