//! 노드 HTTP 서버. M1: `GET /v1/info`, `POST /v1/pair`.

use crate::audit::{Audit, Entry};
use crate::pairing::Pairing;
use crate::policy::Policy;
use crate::tokens::TokenStore;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct AppState {
    pub policy: Policy,
    pub tokens: Mutex<TokenStore>,
    pub pairing: Mutex<Pairing>,
    pub audit: Audit,
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

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/info", get(info))
        .route("/v1/pair", post(pair))
        .with_state(state)
}

pub async fn serve(listener: tokio::net::TcpListener, state: Arc<AppState>) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}

fn request_id() -> String {
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn log(state: &AppState, capability: &str, result: &str, started: Instant) {
    let id = request_id();
    let entry = Entry {
        ts: Audit::now(),
        request_id: &id,
        capability,
        target: String::new(),
        risk: Some("read"),
        approval: None,
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

/// 토큰이 발급된 것인지 확인한다. 모든 인증 요청의 첫 관문.
fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = bearer(headers).ok_or_else(|| {
        err(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "missing or invalid token",
        )
    })?;
    state.tokens.lock().unwrap().verify(token).ok_or_else(|| {
        err(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "missing or invalid token",
        )
    })
}

async fn info(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let started = Instant::now();
    if let Err(e) = authenticate(&state, &headers) {
        log(&state, "info", "UNAUTHORIZED", started);
        return Err(e);
    }
    log(&state, "info", "OK", started);
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
        log(&state, "pair", e.code(), started);
        let (status, message) = match e {
            crate::pairing::PairError::Wrong => (StatusCode::FORBIDDEN, "pairing code is wrong"),
            crate::pairing::PairError::Locked => (
                StatusCode::TOO_MANY_REQUESTS,
                "pairing is locked; ask the node user for a new code",
            ),
            crate::pairing::PairError::Expired => (
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
    log(&state, "pair", "OK", started);
    Ok(Json(
        json!({ "token": token, "node": state.policy.node_name }),
    ))
}
