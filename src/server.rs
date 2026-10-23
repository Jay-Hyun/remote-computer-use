//! 노드 HTTP 서버.
//!
//! `GET /v1/info`, `POST /v1/pair`, `POST /v1/exec`, `POST /v1/fs/read`, `POST /v1/fs/write`,
//! `GET /v1/approvals/:id`.
//!
//! 순서 원칙: 인증(토큰·속도 제한)을 먼저 하고, 통과한 요청의 본문만 읽는다.

use crate::approval::{Decision, Gate, OpenError, APPROVAL_TIMEOUT};
use crate::audit::{Audit, Entry};
use crate::desktop::{Button, Desktop, SystemDesktop};
use crate::limits::{Limit, Limiter};
use crate::ops::{self, Op, OpError, OpResult};
use crate::pairing::{PairError, Pairing};
use crate::policy::{Policy, Risk};
use crate::tokens::TokenStore;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::sync::watch;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// 요청 본문 상한(인증 뒤). 페어링은 훨씬 작게.
const BODY_LIMIT: usize = 4 * 1024 * 1024;
const PAIR_BODY_LIMIT: usize = 4 * 1024;
/// 동시에 열려 있는 연결(요청) 수 상한.
const MAX_IN_FLIGHT: usize = 128;
/// 요청 헤더를 다 받아야 하는 기본 시간.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// 동시에 열어 두는 연결 수 상한. 넘으면 나머지는 운영체제 대기열에서 기다린다.
const MAX_CONNECTIONS: usize = 256;
/// 인증에 실패한 출처(IP)가 분당 보낼 수 있는 요청 수.
const PRE_AUTH_PER_MINUTE: u32 = 30;

pub struct AppState {
    pub policy: Policy,
    pub tokens: Mutex<TokenStore>,
    pub pairing: Mutex<Pairing>,
    pub audit: Audit,
    pub gate: Arc<Gate>,
    pub limiter: Limiter,
    /// 입력(클릭·타이핑·키)은 일반 호출보다 훨씬 낮은 분당 상한을 따로 둔다.
    input_limiter: Limiter,
    /// 화면·입력 백엔드. 시험에서는 가짜로 바꾼다.
    pub desktop: Arc<dyn Desktop>,
    /// 인증 실패·잘못된 페어링을 출처별로 센다.
    pre_auth: Limiter,
    /// 인증 실패 감사 줄은 초당 한 줄만 쓰고 나머지는 개수만 센다(로그 폭주 방지).
    auth_fail_log: Mutex<(Instant, u64)>,
    /// 한 HTTP 요청이 승인을 기다리는 최대 시간. 넘기면 202 + approval_id.
    pub http_wait: Duration,
    /// 연결을 연 뒤 요청 헤더를 다 보내야 하는 시간. 천천히 보내며 연결을 붙잡는 상대(slowloris)를 끊는다.
    pub header_timeout: Duration,
}

impl AppState {
    pub fn new(policy: Policy, tokens: TokenStore, pairing: Pairing, audit: Audit) -> AppState {
        let gate = Arc::new(Gate::new(Duration::from_secs(policy.grant_minutes * 60)));
        let limiter = Limiter::new(policy.rate_per_minute, policy.daily_cap);
        let http_wait = Duration::from_secs(policy.http_wait_secs);
        let policy_input_per_minute = policy.input_per_minute;
        AppState {
            policy,
            tokens: Mutex::new(tokens),
            pairing: Mutex::new(pairing),
            audit,
            gate,
            limiter,
            input_limiter: Limiter::new(policy_input_per_minute, u32::MAX),
            desktop: Arc::new(SystemDesktop),
            pre_auth: Limiter::new(PRE_AUTH_PER_MINUTE, u32::MAX),
            auth_fail_log: Mutex::new((Instant::now() - Duration::from_secs(10), 0)),
            http_wait,
            header_timeout: HEADER_TIMEOUT,
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
    // 승인 대기(최대 http_wait)보다 조금 길게. 끝없이 열려 있는 연결을 정리한다.
    let request_timeout = state.http_wait + Duration::from_secs(30);
    Router::new()
        .route("/v1/info", get(info))
        .route("/v1/pair", post(pair))
        .route("/v1/exec", post(exec))
        .route("/v1/fs/read", post(fs_read))
        .route("/v1/fs/write", post(fs_write))
        .route("/v1/screen/capture", post(screen_capture))
        .route("/v1/input/click", post(input_click))
        .route("/v1/input/type", post(input_type))
        .route("/v1/input/key", post(input_key))
        .route("/v1/approvals/:id", get(approval_result))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        .layer(ConcurrencyLimitLayer::new(MAX_IN_FLIGHT))
        .with_state(state)
}

pub async fn serve(listener: tokio::net::TcpListener, state: Arc<AppState>) -> std::io::Result<()> {
    // 토큰이 폐기되면(`rcu revoke --all`, 다른 프로세스) 그 토큰의 그랜트와 대기 요청을 곧바로 정리한다.
    let watcher = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let tokens = watcher.tokens.lock().unwrap().clone();
            watcher.gate.drop_revoked(|id| tokens.exists(id));
        }
    });
    let header_timeout = state.header_timeout;
    let mut make_service = router(state).into_make_service_with_connect_info::<SocketAddr>();
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        // 연결 수가 가득 차면 새 연결을 받지 않는다.
        let permit = Arc::clone(&slots)
            .acquire_owned()
            .await
            .map_err(std::io::Error::other)?;
        let (socket, remote) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // 파일 기술자 부족 같은 일시적 오류에서 바쁘게 도는 것을 막는다.
                eprintln!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let service = match tower::Service::call(&mut make_service, remote).await {
            Ok(svc) => svc,
            Err(never) => match never {},
        };
        tokio::spawn(async move {
            let _permit = permit;
            let hyper_service = hyper::service::service_fn(
                move |req: axum::http::Request<hyper::body::Incoming>| {
                    tower::Service::call(&mut service.clone(), req)
                },
            );
            let mut builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            builder
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(header_timeout);
            let _ = builder
                .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(socket), hyper_service)
                .await;
        });
    }
}

fn random_id() -> String {
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// 감사 줄을 쓴다. 쓰지 못하면 false.
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
) -> bool {
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
    match state.audit.log(entry) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("audit write failed: {e}");
            false
        }
    }
}

/// 인증 실패 기록: 초당 한 줄로 줄이고 건너뛴 수를 다음 줄에 적는다.
fn audit_auth_failure(state: &AppState, capability: &str, code: &str, peer: IpAddr) {
    let skipped = {
        let mut last = state.auth_fail_log.lock().unwrap();
        if last.0.elapsed() < Duration::from_secs(1) {
            last.1 += 1;
            return;
        }
        let skipped = last.1;
        *last = (Instant::now(), 0);
        skipped
    };
    let target = format!("peer={peer} (+{skipped} more failures since the last line)");
    audit_entry(
        state,
        &random_id(),
        capability,
        &target,
        None,
        None,
        code,
        Instant::now(),
    );
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn today() -> time::Date {
    OffsetDateTime::now_utc().date()
}

/// 토큰이 발급된 것인지 확인하고 속도 제한을 센다. 모든 인증 요청의 첫 관문.
/// 인증에 실패한 출처는 분당 횟수를 제한하고, 실패 기록은 줄여서 남긴다.
fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    peer: IpAddr,
    capability: &str,
) -> Result<String, ApiError> {
    let id = bearer(headers).and_then(|token| state.tokens.lock().unwrap().verify(token));
    let Some(id) = id else {
        let throttled = state
            .pre_auth
            .check(&peer.to_string(), Instant::now(), today())
            .is_err();
        let (status, code, message) = if throttled {
            (
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                "too many failed attempts from this address; slow down",
            )
        } else {
            (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "missing or invalid token",
            )
        };
        audit_auth_failure(state, capability, code, peer);
        return Err(err(status, code, message));
    };
    state
        .limiter
        .check(&id, Instant::now(), today())
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

/// 인증이 끝난 뒤에만 본문을 읽는다.
async fn read_json<T: DeserializeOwned>(req: Request, limit: usize) -> Result<T, ApiError> {
    let bytes = axum::body::to_bytes(req.into_body(), limit)
        .await
        .map_err(|_| {
            err(
                StatusCode::PAYLOAD_TOO_LARGE,
                "TOO_LARGE",
                "request body is too large",
            )
        })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "request body is not valid JSON for this endpoint",
        )
    })
}

async fn info(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let started = Instant::now();
    authenticate(&state, &headers, peer.ip(), "info")?;
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Json<Value>, ApiError> {
    let started = Instant::now();
    let source = peer.ip().to_string();
    // 페어링 시도도 출처별로 제한한다(틀린 코드로 계속 두드리는 출처만 막는다).
    if state
        .pre_auth
        .check(&source, Instant::now(), today())
        .is_err()
    {
        audit_auth_failure(&state, "pair", "RATE_LIMITED", peer.ip());
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            "too many pairing attempts from this address; slow down",
        ));
    }
    let req: PairRequest = read_json(req, PAIR_BODY_LIMIT).await?;
    let outcome = state
        .pairing
        .lock()
        .unwrap()
        .attempt_from(&source, &req.code, Instant::now());
    if let Err(e) = outcome {
        audit_entry(
            &state,
            &random_id(),
            "pair",
            &format!("peer={source}"),
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
    let expires = (state.policy.token_days > 0).then(|| {
        use time::format_description::well_known::Rfc3339;
        (OffsetDateTime::now_utc() + time::Duration::days(state.policy.token_days as i64))
            .format(&Rfc3339)
            .unwrap_or_default()
    });
    let token = state
        .tokens
        .lock()
        .unwrap()
        .issue_with_expiry(label, &Audit::now(), expires)
        .map_err(|_| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "could not store token",
            )
        })?;
    audit_entry(
        &state,
        &random_id(),
        "pair",
        &format!("peer={source}"),
        None,
        None,
        "OK",
        started,
    );
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let started = Instant::now();
    let token_id = match authenticate(&state, req.headers(), peer.ip(), "exec") {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match read_json::<ExecRequest>(req, BODY_LIMIT).await {
        Ok(body) => {
            let op = Op::Exec {
                program: body.program,
                args: body.args,
            };
            submit(state, token_id, op, started).await
        }
        Err(e) => e.into_response(),
    }
}

async fn fs_read(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let started = Instant::now();
    let token_id = match authenticate(&state, req.headers(), peer.ip(), "fs.read") {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match read_json::<ReadRequest>(req, BODY_LIMIT).await {
        Ok(body) => submit(state, token_id, Op::Read { path: body.path }, started).await,
        Err(e) => e.into_response(),
    }
}

async fn fs_write(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let started = Instant::now();
    let token_id = match authenticate(&state, req.headers(), peer.ip(), "fs.write") {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let body = match read_json::<WriteRequest>(req, BODY_LIMIT).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let Ok(data) = base64::engine::general_purpose::STANDARD.decode(body.content_b64.as_bytes())
    else {
        return err(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "content_b64 is not valid base64",
        )
        .into_response();
    };
    let op = Op::Write {
        path: body.path,
        data,
        overwrite: body.overwrite,
    };
    submit(state, token_id, op, started).await
}

#[derive(Deserialize)]
struct ClickRequest {
    x: i32,
    y: i32,
    #[serde(default)]
    button: Option<String>,
}

#[derive(Deserialize)]
struct TypeRequest {
    text: String,
}

#[derive(Deserialize)]
struct KeyRequest {
    combo: String,
}

async fn screen_capture(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let started = Instant::now();
    match authenticate(&state, req.headers(), peer.ip(), "screen") {
        Ok(token_id) => submit(state, token_id, Op::Screen, started).await,
        Err(e) => e.into_response(),
    }
}

async fn input_click(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let started = Instant::now();
    let token_id = match authenticate(&state, req.headers(), peer.ip(), "input") {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let body = match read_json::<ClickRequest>(req, BODY_LIMIT).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let Some(button) = Button::parse(body.button.as_deref().unwrap_or("left")) else {
        return err(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "button must be \"left\" or \"right\"",
        )
        .into_response();
    };
    let op = Op::Click {
        x: body.x,
        y: body.y,
        button,
    };
    submit(state, token_id, op, started).await
}

async fn input_type(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let started = Instant::now();
    let token_id = match authenticate(&state, req.headers(), peer.ip(), "input") {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match read_json::<TypeRequest>(req, BODY_LIMIT).await {
        Ok(body) => submit(state, token_id, Op::Type { text: body.text }, started).await,
        Err(e) => e.into_response(),
    }
}

async fn input_key(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let started = Instant::now();
    let token_id = match authenticate(&state, req.headers(), peer.ip(), "input") {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match read_json::<KeyRequest>(req, BODY_LIMIT).await {
        Ok(body) => submit(state, token_id, Op::Key { combo: body.combo }, started).await,
        Err(e) => e.into_response(),
    }
}

async fn approval_result(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let token_id = match authenticate(&state, &headers, peer.ip(), "approval") {
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

fn result_code(result: &OpResult) -> &'static str {
    match result {
        Ok(_) => "OK",
        Err(e) => e.code,
    }
}

/// 실행 한 번: 토큰이 아직 유효한지 확인 → 감사 "START" 기록(못 쓰면 실행하지 않음) → 실행 → 결과 기록.
/// 호출자(HTTP 요청)가 끊겨도 끝까지 가도록 별도 태스크에서 돌린다.
async fn run_audited(
    state: Arc<AppState>,
    token_id: String,
    op: Op,
    plan: ops::Plan,
    approval: &'static str,
    request_id: String,
    started: Instant,
) -> OpResult {
    let handle = tokio::spawn(async move {
        if !state.tokens.lock().unwrap().exists(&token_id) {
            return Err(OpError::new(
                401,
                "UNAUTHORIZED",
                "this token was revoked while the request was waiting",
            ));
        }
        let wrote = audit_entry(
            &state,
            &request_id,
            plan.capability,
            &plan.target,
            Some(plan.risk),
            Some(approval),
            "START",
            started,
        );
        if !wrote {
            return Err(OpError::new(
                500,
                "AUDIT_FAILED",
                "the node could not write its audit log; refusing to run",
            ));
        }
        let risk = plan.risk;
        let st = Arc::clone(&state);
        let result = tokio::task::spawn_blocking(move || {
            ops::execute_with(&st.policy, st.desktop.as_ref(), &op, risk)
        })
        .await
        .unwrap_or_else(|_| Err(OpError::new(500, "INTERNAL", "operation crashed")));
        audit_entry(
            &state,
            &request_id,
            plan.capability,
            &plan.target,
            Some(plan.risk),
            Some(approval),
            result_code(&result),
            started,
        );
        result
    });
    handle
        .await
        .unwrap_or_else(|_| Err(OpError::new(500, "INTERNAL", "operation crashed")))
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
                &ops::sanitize_for_display(&ops::summary(&op)),
                None,
                None,
                e.code,
                started,
            );
            return op_err(&e).into_response();
        }
    };

    if plan.capability == "input"
        && state
            .input_limiter
            .check(&token_id, Instant::now(), today())
            .is_err()
    {
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
            "too many input actions; slow down",
        )
        .into_response();
    }

    if !plan.risk.always_needs_approval()
        && state
            .gate
            .grant_alive(&token_id, plan.capability, plan.risk, Instant::now())
    {
        let result = run_audited(
            state.clone(),
            token_id,
            op,
            plan,
            "grant",
            random_id(),
            started,
        )
        .await;
        return respond(&result);
    }

    let wait = state.http_wait;
    let opened = match state
        .gate
        .open(&token_id, plan.capability, plan.risk, plan.summary.clone())
    {
        Ok(o) => o,
        Err(why) => {
            let message = match why {
                OpenError::TooManyForToken => {
                    "too many of your requests are already waiting for approval on the node"
                }
                OpenError::TooManyTotal => {
                    "too many requests are waiting for approval on the node; try later"
                }
            };
            audit_entry(
                &state,
                &random_id(),
                plan.capability,
                &plan.target,
                Some(plan.risk),
                None,
                "BUSY",
                started,
            );
            return err(StatusCode::TOO_MANY_REQUESTS, "BUSY", message).into_response();
        }
    };
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
    let run = |state: Arc<AppState>, token_id: String, op: Op, plan: ops::Plan, label| {
        run_audited(state, token_id, op, plan, label, random_id(), started)
    };
    let (approval, result) = match decided {
        Ok(Ok(Decision::Once)) => (
            "once",
            run(state.clone(), token_id, op, plan.clone(), "once").await,
        ),
        Ok(Ok(Decision::Grant)) => {
            if !plan.risk.always_needs_approval() {
                state
                    .gate
                    .add_grant(&token_id, plan.capability, plan.risk, Instant::now());
            }
            (
                "grant",
                run(state.clone(), token_id, op, plan.clone(), "grant").await,
            )
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
    if matches!(approval, "deny" | "timeout") {
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
    }
    state.gate.publish(&id, result);
}
