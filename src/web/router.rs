use std::sync::Arc;

use axum::{Router, middleware, routing::{delete, get, post}};
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};

use crate::web::*;
use crate::web::middleware::{auth_middleware, rate_limit_middleware};

pub fn router(state: Arc<AppState>) -> Router {
    // CORS: default to localhost dev origins, override via MUCCHEAI_CORS_ORIGINS env var.
    // Configured origins are parsed as URLs and validated to ensure they have a scheme+host.
    let parse_origin = |s: &str| -> Option<String> {
        let trimmed = s.trim();
        if trimmed.is_empty() { return None; }
        let url = url::Url::parse(trimmed).ok()?;
        // Reject origins with paths, query strings, userinfo, or fragments
        if url.path() != "/" && !url.path().is_empty() { return None; }
        if url.query().is_some() { return None; }
        if url.username() != "" { return None; }
        if url.fragment().is_some() { return None; }
        Some(format!("{}://{}{}", url.scheme(), url.host_str()?, url.port().map(|p| format!(":{}", p)).unwrap_or_default()))
    };
    let cors_origins: std::collections::HashSet<String> = std::env::var("MUCCHEAI_CORS_ORIGINS")
        .ok()
        .map(|s| s.split(',').filter_map(parse_origin).collect())
        .unwrap_or_else(|| {
            let mut set = std::collections::HashSet::new();
            set.insert("http://localhost:3000".into());
            set.insert("http://127.0.0.1:3000".into());
            set.insert("https://localhost:3000".into());
            set.insert("https://127.0.0.1:3000".into());
            set
        });
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(move |origin, _| {
            let origin_str = match origin.to_str() {
                Ok(s) => s,
                Err(_) => return false,
            };
            // Parse the incoming origin the same way to get canonical form
            parse_origin(origin_str).map(|canonical| cors_origins.contains(&canonical)).unwrap_or(false)
        }))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::HEAD,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
            axum::http::header::HeaderName::from_static("x-csrf-token"),
        ]);

    let csp = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests;"
        ),
    );
    let permissions_policy = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::header::HeaderName::from_static("permissions-policy"),
        axum::http::HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
        ),
    );
    let xcto = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    let xfo = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    let rp = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    let cc = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
    );
    let tls_enabled = std::env::var("MUCCHEAI_TLS_CERT").is_ok();
    let hsts = if tls_enabled {
        Some(tower_http::set_header::SetResponseHeaderLayer::overriding(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            axum::http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
    } else {
        None
    };

    let static_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/web/static");

    // Public API routes (no auth required, but rate limited)
    let public_api = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/share/:token", get(get_shared_session))
        .route("/encrypt-share/:token", get(get_encrypted_share))
        .route("/presets", get(list_presets))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .with_state(state.clone());

    // API routes — auth + rate limit required
    let api = Router::new()
        .route("/status", get(status))
        .route("/config", get(get_config))
        .route("/audit", post(audit_log))
        .route("/revoke", post(revoke))
        .route("/build-verify", get(build_verify))
        .route("/memory", get(list_memories))
        .route("/memory", post(store_memory))
        .route("/preferences", post(store_preference))
        .route("/memory/:key", delete(delete_memory))
        .route("/memory/queue", get(list_memory_queue))
        .route("/memory/queue", post(propose_memory))
        .route("/memory/queue/:id/approve", post(approve_memory_proposal))
        .route("/memory/queue/:id/reject", post(reject_memory_proposal))
        .route("/chat", post(chat))
        .route("/chat/stream", post(chat_stream))
        .route("/chat/ws", get(ws_chat))
        .route("/search", get(global_search))
        .route("/personas", get(list_personas))
        .route("/personas/switch", post(switch_persona))
        .route("/agents", get(list_agents))
        .route("/agents", post(save_agent))
        .route("/agents/:name", delete(delete_agent))
        .route("/agents/:name/active", post(set_active_agent))
        .route("/agents/test", post(test_connection))
        .route("/csrf", get(get_csrf))
        .route("/settings", get(get_settings))
        .route("/settings", post(save_settings))
        .route("/version", get(get_version))
        .route("/model", get(get_model))
        .route("/model", post(set_model))
        .route("/sessions", get(list_chat_sessions))
        .route("/sessions/:id", get(get_chat_session))
        .route("/sessions/:id/export", get(export_chat_session))
        .route("/sessions/:id/title", post(update_session_title))
        .route("/sessions/:id/summarize", post(summarize_session))
        .route("/sessions/:id/branch", post(branch_session))
        .route("/sessions/:id/share", post(share_session))
        .route("/sessions/:id", delete(delete_chat_session))
        .route("/memory/backup", get(backup_memories))
        .route("/memory/restore", post(restore_memories))
        .route("/logout", post(logout))
        .route("/sessions/:id/collaborate", post(post_collaborative_message))
        .route("/presets/:name/install", post(install_preset))
        .route("/knowledge-graph", get(get_knowledge_graph))
        .route("/custom-tools", get(list_custom_tools))
        .route("/custom-tools", post(create_custom_tool))
        .route("/custom-tools/:name", delete(delete_custom_tool))
        .route("/analytics", get(get_analytics))
        .route("/scheduled-tasks", get(list_scheduled_tasks))
        .route("/scheduled-tasks", post(create_scheduled_task))
        .route("/scheduled-tasks/:id", delete(delete_scheduled_task))
        .route("/vault/status", get(vault_status))
        .route("/vault/split", post(vault_split))
        .route("/vault/reconstruct", post(vault_reconstruct))
        .route("/plugin-audit", get(plugin_audit))
        .route("/chat/image", post(chat_with_image))
        .route("/sessions/:id/folder", post(update_session_folder))
        .route("/sessions/:id/tags", post(update_session_tags))
        .route("/folders", get(list_folders))
        .route("/sessions/:id/digest", get(get_session_digest))
        .route("/sessions/:id/encrypt-share", post(create_encrypted_share))
        .route("/upload", post(upload_file))
        .route("/stt", post(stt))
        .route("/mcp/servers", get(list_mcp_servers))
        .route("/mcp/servers", post(add_mcp_server))
        .route("/mcp/servers/:name", delete(delete_mcp_server))
        .route("/mcp/servers/:name/test", post(test_mcp_server))
        .route("/sandbox/detect", post(detect_code_blocks))
        .route("/sandbox/execute", post(execute_code_block))
        .route("/web-search", post(web_search))
        .route("/memory/recompute-tiers", post(recompute_memory_tiers))
        .route("/pipeline/run", post(run_pipeline))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .fallback(|| async { 
            (axum::http::StatusCode::NOT_FOUND, axum::Json(serde_json::json!({"error": "Not Found"}))) 
        })
        .with_state(state.clone());

    let api = public_api.merge(api);

    let mut router = Router::new()
        .route("/", get(index))
        .route("/personas", get(index))
        .route("/settings", get(index))
        .route("/memory", get(index))
        .route("/status", get(index))
        .route("/chat/:id", get(index))
        .nest("/api", api)
        .fallback_service(
            ServeDir::new(static_dir).fallback(ServeFile::new(static_dir.to_string() + "/index.html")),
        )
        .with_state(state)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(10 * 1024 * 1024))
        .layer(cors)
        .layer(csp)
        .layer(permissions_policy)
        .layer(xcto)
        .layer(xfo)
        .layer(rp)
        .layer(cc);
    if let Some(hsts_layer) = hsts {
        router = router.layer(hsts_layer);
    }
    router
}
