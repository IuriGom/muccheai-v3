use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum::http::StatusCode;
use axum::Json;

use crate::web::{AppState, extract_bearer_token, extract_client_ip, get_session_owner};

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    tracing::trace!("auth_middleware: {} {}", method, uri);

    let token = extract_bearer_token(&headers);
    let owner_hash = get_session_owner(&state, &headers).await.unwrap_or_default();

    if owner_hash.is_empty() {
        let config = state.config.lock().await;
        let trusted = config.trusted_proxies.clone();
        drop(config);
        let client_ip = extract_client_ip(&addr.ip(), &headers, &trusted);
        tracing::warn!(
            target: "security",
            "Authentication failed: method={} uri={} client={}",
            method,
            uri,
            client_ip
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"Missing or invalid Authorization header"})),
        )
            .into_response();
    }
    // Check token revocation by bearer token, not owner_hash.
    if let Some(ref t) = token {
        let revoked = state.revoked_tokens.lock().await;
        if revoked.contains(t) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error":"Token has been revoked"})),
            )
                .into_response();
        }
    }

    let csrf_required = method != axum::http::Method::GET
        && method != axum::http::Method::HEAD
        && method != axum::http::Method::OPTIONS;

    if csrf_required {
        let csrf_header = headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok());
        let store = state.csrf_tokens.lock().await;
        let expected = store.get(&owner_hash);
        let csrf_valid = match (csrf_header, expected) {
            (Some(h), Some(exp)) => muccheai_crypto::constant_time::eq(h.as_bytes(), exp.as_bytes()),
            _ => false,
        };
        if !csrf_valid {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error":"Invalid or missing CSRF token"})),
            )
                .into_response();
        }
    }

    next.run(request).await
}

pub async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let direct_ip = addr.ip();
    let config = state.config.lock().await;
    let trusted = config.trusted_proxies.clone();
    drop(config);
    let ip = extract_client_ip(&direct_ip, request.headers(), &trusted);
    let now = Instant::now();
    let window = Duration::from_secs(60);
    // GET requests get a higher limit than mutating requests.
    let max_requests = if request.method() == axum::http::Method::GET {
        300u32
    } else {
        100u32
    };

    let mut limiter = state.rate_limiter.lock().await;

    // Prune stale entries to prevent unbounded memory growth.
    limiter.retain(|_, (last, _)| now.saturating_duration_since(*last) <= window);

    // Hard cap: if the map still exceeds 10,000 entries, evict the oldest 10%.
    const MAX_RATE_LIMIT_ENTRIES: usize = 10_000;
    if limiter.len() >= MAX_RATE_LIMIT_ENTRIES {
        let mut entries: Vec<(String, Instant)> = limiter
            .iter()
            .map(|(ip, (t, _))| (ip.clone(), *t))
            .collect();
        entries.sort_by_key(|(_, t)| *t);
        let to_remove = entries.len() / 10;
        for (ip, _) in entries.into_iter().take(to_remove) {
            limiter.remove(&ip);
        }
    }

    let entry = limiter.entry(ip.clone()).or_insert((now, 0));

    if now.saturating_duration_since(entry.0) > window {
        // Reset window
        entry.0 = now;
        entry.1 = 0;
    }

    if entry.1 >= max_requests {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error":"Rate limit exceeded"})),
        )
            .into_response();
    }

    entry.1 += 1;
    // Lock dropped here automatically at end of scope
    drop(limiter);

    next.run(request).await
}
