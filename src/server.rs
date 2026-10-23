//! 노드 HTTP 서버.
//!
//! `GET /v1/info`, `POST /v1/pair`, `POST /v1/exec`, `POST /v1/fs/read`, `POST /v1/fs/write`,
//! `GET /v1/approvals/:id`.

use crate::approval::{Decision, Gate, APPROVAL_TIMEOUT};
use crate::audit::{Audit, Entry};
use crate::limits::{Limit, Limiter};
use crate::ops::{self, Op, OpError, OpResult};
use crate::pairing::{PairError, Pairing};
use crate::policy::{Policy, Risk};
use crate::tokens::TokenStore;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::sync::watch;

pub struct AppState {
    pub policy: Policy,
    pub tokens: Mutex<TokenStore>,
    pub pairing: Mutex<Pairing>,
    pub audit: Audit,
    pub gate: Arc<Gate>,
    pub limiter: Limiter,
    /// 한 HTTP 요청이 승인을 기다리는 최대 시간. 넘기면 202 + approval_id.
    pub http_wait: Duration,
}

impl AppState {
    pub fn new(policy: Policy, tokens: TokenStore, pairing: Pairing, audit: Audit) -> AppState {
        let gate = Arc::new(Gate::new(Duration::from_secs(policy.grant_minutes * 60)));
        let limiter = Limiter::new(policy.rate_per_minute, policy.daily_cap);
        let http_wait = Duration::from_secs(policy.http_wait_secs);
        AppState {
            policy,
            tokens: Mutex::new(tokens),
            pairing: Mutex::new(pairing),
            audit,
            gate,
            limiter,
            http_wait,
        }
    }
}

#[derive(Serialize)]
struct ErrBody {
    code: &'static str,
    message: &'static str,
}

type ApiError = (StatusCode, Json<ErrBody>);

fn err(status: StatusCode, code: &'static str, message: &'static str) -> ApiError {
    (status, Json(ErrBody { code, message }))
}

fn op_err(e: &OpError) -> ApiError {
    err(
        StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        e.code,
        e.message,
    )
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/info", get(info))
        .route("/v1/pair", post(pair))
        .route("/v1/exec", post(exec))
        .route("/v1/fs/read", post(fs_read))
        .route("/v1/fs/write", post(fs_write))
        .route("/v1/approvals/:id", get(approval_result))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(state)
}

pub async fn serve(listener: tokio::net::TcpListener, state: Arc<AppState>) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}

fn random_id() -> String {
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[allow(clippy::too_many_arguments)]
fn audit_entry(
    state: &AppState,
    request_id: &str,
    capability: &str,
    target: &str,
    risk: Option<Risk>,
    approval: Option<&str>,
    result: &str,
    started: Instant,
) {
    let entry = Entry {
        ts: Audit::now(),
        request_id,
        capability,
        target: target.to_string(),
        risk: risk.map(Risk::as_str),
        approval,
        result,
        duration_ms: started.elapsed().as_millis() as u64,
    };
    if let Err(e) = state.audit.log(entry) {
        eprintln!("audit write failed: {e}");
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// 토큰이 발급된 것인지 확인하고 속도 제한을 센다. 모든 인증 요청의 첫 관문.
fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let unauthorized = || {
        err(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "missing or invalid token",
        )
    };
    let token = bearer(headers).ok_or_else(unauthorized)?;
    let id = state
        .tokens
        .lock()
        .unwrap()
        .verify(token)
        .ok_or_else(unauthorized)?;
    state
        .limiter
        .check(&id, Instant::now(), OffsetDateTime::now_utc().date())
        .map_err(|limit| match limit {
            Limit::Minute => err(
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                "too many requests; slow down",
            ),
            Limit::Day => err(
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                "daily request cap reached on this node",
            ),
        })?;
    Ok(id)
}

fn auth_or_log(
    state: &AppState,
    headers: &HeaderMap,
    capability: &str,
    started: Instant,
) -> Result<String, ApiError> {
    authenticate(state, headers).inspect_err(|e| {
        audit_entry(
            state,
            &random_id(),
            capability,
            "",
            None,
            None,
            e.1 .0.code,
            started,
        );
    })
}

async fn info(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let started = Instant::now();
    auth_or_log(&state, &headers, "info", started)?;
    audit_entry(
        &state,
        &random_id(),
        "info",
        "",
        Some(Risk::Read),
        None,
        "OK",
        started,
    );
    Ok(Json(json!({
        "name": state.policy.node_name,
        "os": std::env::consts::OS,
        "version": env!("CARGO_PKG_VERSION"),
        "capabilities": state.policy.capabilities(),
    })))
}

#[derive(Deserialize)]
struct PairRequest {
    code: String,
    #[serde(default)]
    controller: String,
}

async fn pair(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PairRequest>,
) -> Result<Json<Value>, ApiError> {
    let started = Instant::now();
    let outcome = state
        .pairing
        .lock()
        .unwrap()
        .attempt(&req.code, Instant::now());
    if let Err(e) = outcome {
        audit_entry(
            &state,
            &random_id(),
            "pair",
            "",
            None,
            None,
            e.code(),
            started,
        );
        let (status, message) = match e {
            PairError::Wrong => (StatusCode::FORBIDDEN, "pairing code is wrong"),
            PairError::Locked => (
                StatusCode::TOO_MANY_REQUESTS,
                "pairing is locked; ask the node user for a new code",
            ),
            PairError::Expired => (
                StatusCode::GONE,
                "pairing code expired; ask the node user for a new code",
            ),
        };
        return Err(err(status, e.code(), message));
    }
    let label = if req.controller.is_empty() {
        "controller"
    } else {
        &req.controller
    };
    let token = state
        .tokens
        .lock()
        .unwrap()
        .issue(label, &Audit::now())
        .map_err(|_| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "could not store token",
            )
        })?;
    audit_entry(&state, &random_id(), "pair", "", None, None, "OK", started);
    Ok(Json(
        json!({ "token": token, "node": state.policy.node_name }),
    ))
}

#[derive(Deserialize)]
struct ExecRequest {
    program: String,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Deserialize)]
struct ReadRequest {
    path: String,
}

#[derive(Deserialize)]
struct WriteRequest {
    path: String,
    content_b64: String,
    #[serde(default)]
    overwrite: bool,
}

async fn exec(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ExecRequest>,
) -> Response {
    let started = Instant::now();
    match auth_or_log(&state, &headers, "exec", started) {
        Ok(token_id) => {
            submit(
                state,
                token_id,
                Op::Exec {
                    program: req.program,
                    args: req.args,
                },
                started,
            )
            .await
        }
        Err(e) => e.into_response(),
    }
}

async fn fs_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ReadRequest>,
) -> Response {
    let started = Instant::now();
    match auth_or_log(&state, &headers, "fs.read", started) {
        Ok(token_id) => submit(state, token_id, Op::Read { path: req.path }, started).await,
        Err(e) => e.into_response(),
    }
}

async fn fs_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<WriteRequest>,
) -> Response {
    let started = Instant::now();
    let token_id = match auth_or_log(&state, &headers, "fs.write", started) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let Ok(data) = base64::engine::general_purpose::STANDARD.decode(req.content_b64.as_bytes())
    else {
        return err(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "content_b64 is not valid base64",
        )
        .into_response();
    };
    submit(
        state,
        token_id,
        Op::Write {
            path: req.path,
            data,
            overwrite: req.overwrite,
        },
        started,
    )
    .await
}

async fn approval_result(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let started = Instant::now();
    let token_id = match auth_or_log(&state, &headers, "approval", started) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match state.gate.subscribe(&id, &token_id) {
        Some(rx) => wait_result(rx, &id, state.http_wait).await,
        None => err(
            StatusCode::NOT_FOUND,
            "UNKNOWN_APPROVAL",
            "no such approval request",
        )
        .into_response(),
    }
}

fn respond(result: &OpResult) -> Response {
    match result {
        Ok(value) => Json(value.clone()).into_response(),
        Err(e) => op_err(e).into_response(),
    }
}

fn pending_response(id: &str) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "code": "APPROVAL_PENDING",
            "message": "waiting for approval on the node; do not resend the request, use `rcu wait`",
            "approval_id": id,
        })),
    )
        .into_response()
}

async fn wait_result(
    mut rx: watch::Receiver<Option<OpResult>>,
    id: &str,
    wait: Duration,
) -> Response {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        if let Some(result) = rx.borrow_and_update().clone() {
            return respond(&result);
        }
        match tokio::time::timeout_at(deadline, rx.changed()).await {
            Ok(Ok(())) => continue,
            _ => return pending_response(id),
        }
    }
}

async fn run_blocking(state: Arc<AppState>, op: Op) -> OpResult {
    tokio::task::spawn_blocking(move || ops::execute(&state.policy, &op))
        .await
        .unwrap_or_else(|_| Err(OpError::new(500, "INTERNAL", "operation crashed")))
}

fn result_code(result: &OpResult) -> &'static str {
    match result {
        Ok(_) => "OK",
        Err(e) => e.code,
    }
}

/// 정책 검사 → (그랜트가 있으면 바로 실행 | 노드 사용자 승인 대기) → 실행.
async fn submit(state: Arc<AppState>, token_id: String, op: Op, started: Instant) -> Response {
    let plan = match ops::plan(&state.policy, &op) {
        Ok(plan) => plan,
        Err(e) => {
            audit_entry(
                &state,
                &random_id(),
                "op",
                &ops::sanitize_for_display(&describe(&op)),
                None,
                None,
                e.code,
                started,
            );
            return op_err(&e).into_response();
        }
    };

    if !plan.risk.always_needs_approval()
        && state
            .gate
            .grant_alive(&token_id, plan.capability, Instant::now())
    {
        let result = run_blocking(state.clone(), op).await;
        audit_entry(
            &state,
            &random_id(),
            plan.capability,
            &plan.target,
            Some(plan.risk),
            Some("grant"),
            result_code(&result),
            started,
        );
        return respond(&result);
    }

    let wait = state.http_wait;
    let opened = state
        .gate
        .open(&token_id, plan.capability, plan.risk, ops::summary(&op));
    let id = opened.id.clone();
    tokio::spawn(drive(
        state,
        token_id,
        op,
        plan,
        opened.id,
        opened.decision_rx,
        started,
    ));
    wait_result(opened.result_rx, &id, wait).await
}

fn describe(op: &Op) -> String {
    ops::summary(op)
}

/// 승인 결정을 기다렸다가 실행하고 결과를 게시한다. HTTP 연결이 끊겨도 한 번만 실행된다.
async fn drive(
    state: Arc<AppState>,
    token_id: String,
    op: Op,
    plan: ops::Plan,
    id: String,
    decision_rx: tokio::sync::oneshot::Receiver<Decision>,
    started: Instant,
) {
    let decided = tokio::time::timeout(APPROVAL_TIMEOUT, decision_rx).await;
    let (approval, result) = match decided {
        Ok(Ok(Decision::Once)) => ("once", run_blocking(state.clone(), op).await),
        Ok(Ok(Decision::Grant)) => {
            if !plan.risk.always_needs_approval() {
                state
                    .gate
                    .add_grant(&token_id, plan.capability, Instant::now());
            }
            ("grant", run_blocking(state.clone(), op).await)
        }
        Ok(Ok(Decision::Deny)) | Ok(Err(_)) => (
            "deny",
            Err(OpError::new(
                403,
                "APPROVAL_DENIED",
                "the node user denied the request",
            )),
        ),
        Err(_) => {
            state.gate.expire(&id);
            (
                "timeout",
                Err(OpError::new(
                    403,
                    "APPROVAL_TIMEOUT",
                    "no one approved the request in time",
                )),
            )
        }
    };
    audit_entry(
        &state,
        &id,
        plan.capability,
        &plan.target,
        Some(plan.risk),
        Some(approval),
        result_code(&result),
        started,
    );
    state.gate.publish(&id, result);
}
