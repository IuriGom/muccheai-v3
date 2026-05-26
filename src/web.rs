//! MuccheAI web control panel.

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    response::sse::{Event, Sse},
    routing::{delete, get, post},
    Router,
};
use std::convert::Infallible;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use ring::rand::SecureRandom;

use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

use muccheai_build_verify::{MultiCiVerification, BuildIntegrityError};
use muccheai_policy_engine::PolicyEngine;
use muccheai_policy_engine::rules::RuleAction;
use muccheai_sandbox::LlmSandbox;
use muccheai_tool_gateway::{ToolGateway, config::{ToolConfig, McpServerConfig}};
use muccheai_mcp::{McpClient, McpTransport};
use muccheai_mcp::types::McpTool;
use muccheai_types::audit::{AuditQuery, AuditResult, SecurityEvent};
use muccheai_types::ActionProposal;
use muccheai_types::memory::{MemoryEntry, MemoryType, MemoryValue};
use muccheai_types::Timestamp;

use crate::structured_memory::StructuredMemoryManager;

use crate::config::{AgentConfig, MuccheConfig, Persona};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSession {
    pub id: String,
    pub title: String,
    pub created_at: u64,
    pub messages: Vec<ChatMessage>,
    #[serde(skip)]
    pub owner_hash: String,
    #[serde(skip)]
    pub session_secret: String,
    /// If this session is a branch, the parent session ID.
    pub parent_id: Option<String>,
    /// If branched, the message index in the parent where branching occurred.
    pub branch_point: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatSessionSummary {
    pub id: String,
    pub title: String,
    pub created_at: u64,
}

pub fn load_revoked_tokens() -> std::collections::HashSet<String> {
    let path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".muccheai")
        .join("revoked_tokens.json");
    if let Ok(data) = std::fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        std::collections::HashSet::new()
    }
}

pub fn save_revoked_tokens(tokens: &std::collections::HashSet<String>) {
    let path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".muccheai")
        .join("revoked_tokens.json");
    if let Ok(data) = serde_json::to_string(tokens) {
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, data).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

pub struct Session {
    pub owner_hash: String,
    pub username: String,
    pub created_at: Instant,
    /// If true, this session was created via duress PIN.
    /// All data endpoints return empty/sanitized results.
    pub duress: bool,
}

pub struct AppState {
    pub sandbox: Mutex<LlmSandbox>,
    pub policy: Mutex<PolicyEngine>,
    pub gateway: Mutex<ToolGateway>,
    pub users: Mutex<crate::users::UserDb>,
    pub sessions: Mutex<HashMap<String, Session>>,
    pub csrf_secret: [u8; 32],
    pub rate_limiter: Mutex<HashMap<String, (Instant, u32)>>,
    pub revoked_tokens: Mutex<std::collections::HashSet<String>>,
    pub config: Mutex<MuccheConfig>,
    pub chat_sessions: Mutex<Vec<ChatSession>>,
    pub memory: Mutex<muccheai_memory::MemoryEngine>,
    pub structured_memory: Mutex<StructuredMemoryManager>,
    pub bootstrap_context: String,
    pub http_client: reqwest::Client,
    pub mcp_tools_cache: Mutex<Vec<CachedMcpTool>>,
    pub tool_config: Mutex<ToolConfig>,
    pub csrf_tokens: Mutex<HashMap<String, String>>,
    pub rng: ring::rand::SystemRandom,
    /// Share tokens: token -> (session_id, created_at)
    pub shared_sessions: Mutex<HashMap<String, (String, Instant)>>,
    /// Custom no-code HTTP tools
    pub custom_tools: Mutex<Vec<crate::config::CustomToolConfig>>,
    /// Scheduled proactive tasks
    pub scheduled_tasks: Mutex<Vec<ScheduledTask>>,
    /// Plugin manager
    pub plugin_manager: Mutex<crate::plugin::PluginManager>,
}

#[derive(Clone)]
pub struct CachedMcpTool {
    pub server_name: String,
    pub transport: McpTransport,
    pub tool: McpTool,
}

impl std::fmt::Debug for CachedMcpTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedMcpTool")
            .field("server_name", &self.server_name)
            .field("transport", &"<redacted>")
            .field("tool", &self.tool)
            .finish()
    }
}

/// Chat request
#[derive(Debug, Deserialize)]
pub struct ChatRequest {
    pub message: String,
    pub session_id: Option<String>,
    /// When true, the request is a research query that bundles chat history.
    /// Research requires confirmation if any configured agent uses an external provider.
    #[serde(default)]
    pub research: bool,
    /// User has explicitly confirmed they want to send history to an external provider.
    #[serde(default)]
    pub research_confirmed: bool,
}

/// Chat response
#[derive(Debug, Serialize)]
pub struct ChatResponse {
    pub response: String,
    pub session_id: String,
    pub session_secret: String,
    /// If set, the frontend should show a confirmation dialog with this message
    /// and re-send the request with `research_confirmed: true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_confirmation: Option<String>,
    /// Number of structured memories injected into the system prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memories_used: Option<usize>,
}

/// System status
#[derive(Debug, Serialize)]
pub struct SystemStatus {
    pub sandbox_running: bool,
    pub model: String,
    pub policy_rules: Vec<String>,
    pub pqc_enabled: bool,
    pub current_persona: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub sandbox_memory_limit_mb: u32,
    pub dual_verification: bool,
    pub auto_approve_low_risk: bool,
    pub show_reasoning: bool,
    pub active_agent: String,
    pub agents: Vec<AgentConfig>,
    pub ollama_host: String,
    pub ollama_connected: bool,
    pub policy_rule_count: usize,
    pub last_audit_entry: Option<String>,
    pub active_tokens: usize,
}

/// Revoke request
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token_id: String,
}

/// Revoke response
#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    pub revoked_count: u32,
}

/// Build verification response
#[derive(Debug, Serialize)]
pub struct BuildVerifyResponse {
    pub status: String,
    pub ci_systems: Vec<String>,
}

/// Configuration response (secrets redacted)
#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub ollama_url: String,
    pub ollama_model: String,
    pub web_bind_address: String,
    pub policy_rules: Vec<String>,
}

/// Memory entry as exposed by the REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryApiEntry {
    /// Unique key.
    pub key: String,
    /// JSON value.
    pub value: serde_json::Value,
    /// Memory type.
    pub memory_type: MemoryType,
    /// Creation timestamp (unix millis).
    pub created_at: u64,
}

/// List memories response.
#[derive(Debug, Serialize)]
pub struct MemoryListResponse {
    /// Memory entries.
    pub entries: Vec<MemoryApiEntry>,
}

/// Memory query parameters.
#[derive(Debug, Deserialize)]
pub struct MemoryQuery {
    /// Optional search query.
    pub q: Option<String>,
}

/// Store memory request.
#[derive(Debug, Deserialize)]
pub struct StoreMemoryRequest {
    /// Unique key.
    pub key: String,
    /// JSON value.
    pub value: serde_json::Value,
    /// Memory type.
    pub memory_type: MemoryType,
}

/// Store preference request (bypasses approval queue).
#[derive(Debug, Deserialize)]
pub struct StorePreferenceRequest {
    pub key: String,
    pub value: serde_json::Value,
}

/// Propose memory request (goes to approval queue).
#[derive(Debug, Deserialize)]
pub struct ProposeMemoryRequest {
    /// Unique key.
    pub key: String,
    /// JSON value.
    pub value: serde_json::Value,
    /// Memory type.
    pub memory_type: MemoryType,
    /// LLM justification for why this should be remembered.
    pub justification: String,
}

/// Propose memory response.
#[derive(Debug, Serialize)]
pub struct ProposeMemoryResponse {
    /// Proposal ID.
    pub id: String,
    /// Status: "pending".
    pub status: String,
}

/// Memory proposal as exposed by the REST API.
#[derive(Debug, Serialize)]
pub struct MemoryProposalApi {
    /// Proposal ID.
    pub id: String,
    /// Proposed key.
    pub key: String,
    /// Proposed value.
    pub value: serde_json::Value,
    /// Memory type.
    pub memory_type: MemoryType,
    /// LLM justification.
    pub justification: String,
    /// When proposed (unix millis).
    pub proposed_at: u64,
}

/// Memory queue response.
#[derive(Debug, Serialize)]
pub struct MemoryQueueResponse {
    /// Pending proposals.
    pub proposals: Vec<MemoryProposalApi>,
}

/// Delete memory response.
#[derive(Debug, Serialize)]
pub struct DeleteMemoryResponse {
    /// Whether an entry was removed.
    pub deleted: bool,
}

/// Personas response.
#[derive(Debug, Serialize)]
pub struct PersonasResponse {
    /// Available personas.
    pub personas: Vec<Persona>,
    /// Currently active persona name.
    pub current: String,
}

/// Switch persona request.
#[derive(Debug, Deserialize)]
pub struct SwitchPersonaRequest {
    /// Name of the persona to activate.
    pub name: String,
}

/// Agents response.
#[derive(Debug, Serialize)]
pub struct AgentsResponse {
    /// Configured agents.
    pub agents: Vec<AgentConfig>,
    /// Currently active agent name.
    pub active: String,
}

/// Save agent request.
#[derive(Deserialize)]
pub struct SaveAgentRequest {
    pub name: String,
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
}

/// Test connection request.
#[derive(Deserialize)]
pub struct TestConnectionRequest {
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
}

/// Test connection response.
#[derive(Debug, Serialize)]
pub struct TestConnectionResponse {
    pub success: bool,
    pub message: String,
}

/// Settings response.
#[derive(Debug, Serialize)]
pub struct SettingsResponse {
    pub model: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub sandbox_memory_limit_mb: u32,
    pub dual_verification: bool,
    pub auto_approve_low_risk: bool,
    pub show_reasoning: bool,
}

/// Save settings request.
#[derive(Debug, Deserialize)]
pub struct SaveSettingsRequest {
    pub model: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub sandbox_memory_limit_mb: u32,
    pub dual_verification: bool,
    pub auto_approve_low_risk: bool,
    pub show_reasoning: bool,
}

/// Version response.
#[derive(Debug, Serialize)]
pub struct VersionResponse {
    /// Current application version.
    pub version: String,
}

/// Model response.
#[derive(Debug, Serialize)]
pub struct ModelResponse {
    /// Current model name.
    pub model: String,
}

/// Set model request.
#[derive(Debug, Deserialize)]
pub struct SetModelRequest {
    /// Model name to switch to.
    pub model: String,
}

/// Chat sessions response.
#[derive(Debug, Serialize)]
pub struct ChatSessionsResponse {
    pub sessions: Vec<ChatSessionSummary>,
}

// ---------------------------------------------------------------------------
// Feature: Session title, branching, sharing, search, backup/restore
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct UpdateTitleRequest {
    title: String,
}

#[derive(Debug, Deserialize)]
struct BranchRequest {
    message_index: usize,
}

#[derive(Debug, Serialize)]
struct BranchResponse {
    session_id: String,
    session_secret: String,
}

#[derive(Debug, Serialize)]
struct ShareResponse {
    share_token: String,
}

#[derive(Debug, Serialize)]
struct SearchResult {
    r#type: String,
    id: String,
    title: String,
    content: String,
    created_at: u64,
}

#[derive(Debug, Serialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
}

#[derive(Debug, Deserialize)]
struct RestoreRequest {
    entries: Vec<MemoryApiEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTask {
    pub id: String,
    pub cron: String,
    pub prompt: String,
    pub enabled: bool,
    pub created_at: u64,
}

#[derive(Debug, Serialize)]
struct AgentPreset {
    name: String,
    provider: String,
    model: String,
    description: String,
    system_prompt: String,
}

#[derive(Debug, Deserialize)]
struct UpdateFolderRequest {
    folder: String,
}

#[derive(Debug, Deserialize)]
struct UpdateTagsRequest {
    tags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AnalyticsResponse {
    total_messages: usize,
    total_sessions: usize,
    total_memories: usize,
    queue_pending: usize,
    top_model: String,
    active_plugins: usize,
}

#[derive(Debug, Serialize)]
struct DigestResponse {
    digest: String,
}

#[derive(Debug, Serialize)]
struct GraphNode {
    id: String,
    label: String,
    group: String,
}

#[derive(Debug, Serialize)]
struct GraphEdge {
    from: String,
    to: String,
    label: String,
}

#[derive(Debug, Serialize)]
struct GraphResponse {
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
}

#[derive(Debug, Deserialize)]
struct EncryptedShareRequest {
    ciphertext: String,
    nonce: String,
}

#[derive(Debug, Serialize)]
struct EncryptedShareResponse {
    share_token: String,
}



/// Serve the main HTML page
async fn index() -> Html<&'static str> {
    Html(include_str!("web/static/index.html"))
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(|s| s.to_string())
}

/// Basic IPv4 CIDR check. Returns false for IPv6 or malformed input.
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return ip == cidr;
    }
    let prefix_len: u32 = match parts[1].parse() {
        Ok(n) if n <= 32 => n,
        _ => return ip == parts[0],
    };
    let ip_u32 = match ip.parse::<std::net::Ipv4Addr>() {
        Ok(a) => u32::from_be_bytes(a.octets()),
        Err(_) => return false,
    };
    let base_u32 = match parts[0].parse::<std::net::Ipv4Addr>() {
        Ok(a) => u32::from_be_bytes(a.octets()),
        Err(_) => return false,
    };
    let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
    (ip_u32 & mask) == (base_u32 & mask)
}

/// Check whether an IP is in the trusted-proxy list (exact match or CIDR).
fn is_trusted_proxy(ip: &str, trusted: &[String]) -> bool {
    trusted.iter().any(|p| {
        if p.contains('/') {
            ip_in_cidr(ip, p)
        } else {
            p == ip
        }
    })
}

/// Extract the client IP from a request, respecting trusted proxies.
///
/// If the direct connection came from a trusted proxy we parse
/// `X-Forwarded-For` **from right to left** and return the first
/// IP that is *not* itself a trusted proxy.  This prevents a client
/// from prepending arbitrary IPs to the header and spoofing its
/// address.
fn extract_client_ip(direct_ip: &std::net::IpAddr, headers: &HeaderMap, trusted: &[String]) -> String {
    let direct_ip_str = direct_ip.to_string();
    if !is_trusted_proxy(&direct_ip_str, trusted) {
        return direct_ip_str;
    }
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    // Walk from right to left; the rightmost IP was added by the
    // proxy closest to this server.  The first non-trusted IP in that
    // direction is the real client.
    for ip in xff.split(',').map(|s| s.trim()).rev() {
        if ip.is_empty() {
            continue;
        }
        if !is_trusted_proxy(ip, trusted) {
            return ip.to_string();
        }
    }
    // Everything in the chain is a trusted proxy — fall back to direct IP.
    direct_ip_str
}

async fn get_session_owner(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = extract_bearer_token(headers)?;
    // Fast path: read-only lookup.
    let (owner, expired) = {
        let sessions = state.sessions.lock().await;
        match sessions.get(&token) {
            Some(s) => {
                const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
                let expired = Instant::now().saturating_duration_since(s.created_at) > SESSION_TTL;
                (Some(s.owner_hash.clone()), expired)
            }
            None => (None, false),
        }
    };
    // Slow path: evict just this token if it was expired.
    if expired {
        let mut sessions = state.sessions.lock().await;
        sessions.remove(&token);
    }
    // Do NOT authenticate requests presenting an expired token.
    if expired { None } else { owner }
}

/// Check whether the current session was created via duress PIN.
async fn is_duress_session(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(token) = extract_bearer_token(headers) else { return false };
    let sessions = state.sessions.lock().await;
    sessions.get(&token).map(|s| s.duress).unwrap_or(false)
}

/// Bearer token authentication middleware + CSRF protection for mutating requests
async fn auth_middleware(
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

/// Validate that a URL does not point to internal/private addresses.
/// Allows localhost/loopback for internal services like Ollama.
pub fn validate_no_ssrf(url: &str) -> std::result::Result<(), String> {
    validate_no_ssrf_internal(url, true)
}

/// Strict variant: blocks localhost/loopback — use for external providers and MCP servers.
pub fn validate_no_ssrf_external(url: &str) -> std::result::Result<(), String> {
    validate_no_ssrf_internal(url, false)
}

fn validate_no_ssrf_internal(url: &str, allow_localhost: bool) -> std::result::Result<(), String> {
    let parsed = url::Url::parse(url)
        .map_err(|e| format!("Invalid URL: {}", e))?;

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("SSRF blocked: only http and https schemes are allowed".to_string());
    }

    let host = parsed.host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    let lower = host.to_lowercase();

    if allow_localhost && (lower == "localhost" || lower == "127.0.0.1" || lower == "[::1]") {
        return Ok(());
    }

    if lower == "localhost" {
        return Err("SSRF blocked: localhost is not allowed".to_string());
    }

    if lower.starts_with("0x") || lower.starts_with("0X") {
        return Err("SSRF blocked: hex IP addresses are not allowed".to_string());
    }
    if lower.chars().all(|c| c.is_ascii_digit() || c == '.') && lower.starts_with('0') && lower.len() > 1 {
        return Err("SSRF blocked: octal IP addresses are not allowed".to_string());
    }
    if lower.chars().all(|c| c.is_ascii_digit()) {
        return Err("SSRF blocked: decimal IP addresses are not allowed".to_string());
    }

    if let Ok(ip) = lower.parse::<std::net::IpAddr>() {
        let blocked = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
                    || v4.is_multicast() || v4.is_broadcast() || v4.is_documentation()
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
                    || v6.is_unicast_link_local() || v6.is_multicast() {
                    return Err("SSRF blocked: internal IP addresses are not allowed".to_string());
                }
                if let Some(v4) = v6.to_ipv4_mapped() {
                    if v4.is_loopback() || v4.is_private() || v4.is_link_local()
                        || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()
                        || v4.is_documentation() {
                        return Err("SSRF blocked: internal IP addresses are not allowed".to_string());
                    }
                }
                let segs = v6.segments();
                if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0
                    && segs[4] == 0 && segs[5] == 0xffff {
                    let v4_bytes = [(segs[6] >> 8) as u8, (segs[6] & 0xff) as u8,
                                    (segs[7] >> 8) as u8, (segs[7] & 0xff) as u8];
                    let v4 = std::net::Ipv4Addr::from(v4_bytes);
                    if v4.is_loopback() || v4.is_private() || v4.is_link_local()
                        || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()
                        || v4.is_documentation() {
                        return Err("SSRF blocked: internal IP addresses are not allowed".to_string());
                    }
                }
                false
            }
        };
        if blocked {
            return Err("SSRF blocked: internal IP addresses are not allowed".to_string());
        }
    }

    if lower.starts_with("127.") || lower.starts_with("10.")
        || lower.starts_with("192.168.") || lower.starts_with("169.254.")
        || lower.starts_with("172.16.") || lower.starts_with("172.17.")
        || lower.starts_with("172.18.") || lower.starts_with("172.19.")
        || lower.starts_with("172.20.") || lower.starts_with("172.21.")
        || lower.starts_with("172.22.") || lower.starts_with("172.23.")
        || lower.starts_with("172.24.") || lower.starts_with("172.25.")
        || lower.starts_with("172.26.") || lower.starts_with("172.27.")
        || lower.starts_with("172.28.") || lower.starts_with("172.29.")
        || lower.starts_with("172.30.") || lower.starts_with("172.31.")
        || lower == "0.0.0.0"
    {
        return Err("SSRF blocked: internal addresses are not allowed".to_string());
    }

    Ok(())
}

/// Resolve hostname and validate all returned IPs against SSRF blocklist.
async fn validate_no_ssrf_dns(url: &str) -> std::result::Result<(), String> {
    let parsed = url::Url::parse(url)
        .map_err(|e| format!("Invalid URL: {}", e))?;

    let host = parsed.host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    let lower = host.to_lowercase();
    if lower == "localhost" || lower == "127.0.0.1" || lower == "[::1]" {
        return Ok(());
    }

    let addrs = tokio::net::lookup_host(format!("{}:80", host)).await
        .map_err(|e| format!("DNS resolution failed: {}", e))?;

    for addr in addrs {
        let ip = addr.ip();
        let blocked = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local()
                    || v4.is_unspecified() || v4.is_broadcast()
                    || v4.is_documentation() || v4.is_multicast()
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
                    || v6.is_unicast_link_local() || v6.is_multicast() {
                    return Err("SSRF blocked: DNS resolved to internal IP".to_string());
                }
                if let Some(v4) = v6.to_ipv4_mapped() {
                    if v4.is_loopback() || v4.is_private() || v4.is_link_local()
                        || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                        return Err("SSRF blocked: DNS resolved to internal IP".to_string());
                    }
                }
                let segs = v6.segments();
                if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0
                    && segs[4] == 0 && segs[5] == 0xffff {
                    let v4_bytes = [(segs[6] >> 8) as u8, (segs[6] & 0xff) as u8,
                                    (segs[7] >> 8) as u8, (segs[7] & 0xff) as u8];
                    let v4 = std::net::Ipv4Addr::from(v4_bytes);
                    if v4.is_loopback() || v4.is_private() || v4.is_link_local()
                        || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                        return Err("SSRF blocked: DNS resolved to internal IP".to_string());
                    }
                }
                false
            }
        };
        if blocked {
            return Err("SSRF blocked: DNS resolved to internal IP".to_string());
        }
    }

    Ok(())
}

/// Build a reqwest client that pins the resolved IP for a given base URL,
/// preventing DNS rebinding attacks where a hostname resolves to different
/// IPs between validation and request time.
async fn build_pinned_client(base_url: &str) -> Result<reqwest::Client, String> {
    let parsed = url::Url::parse(base_url)
        .map_err(|e| format!("Invalid URL: {}", e))?;
    let host = parsed.host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    // Skip pinning for pure IP addresses (already checked by validate_no_ssrf).
    if host.parse::<std::net::IpAddr>().is_ok() {
        return reqwest::Client::builder()
            .timeout(Duration::from_secs(90))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e));
    }

    let port = parsed.port_or_known_default()
        .unwrap_or(443);

    let addrs = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|e| format!("DNS resolution failed: {}", e))?;
    let addr = addrs.into_iter().next()
        .ok_or_else(|| "DNS resolution returned no addresses".to_string())?;

    // Double-check the resolved IP is not internal (defense in depth).
    let ip = addr.ip();
    let blocked = match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
                || v4.is_unspecified() || v4.is_broadcast()
                || v4.is_documentation() || v4.is_multicast()
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
                || v6.is_unicast_link_local() || v6.is_multicast() {
                true
            } else if let Some(v4) = v6.to_ipv4_mapped() {
                v4.is_loopback() || v4.is_private() || v4.is_link_local()
                    || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()
                    || v4.is_documentation()
            } else {
                false
            }
        }
    };
    if blocked {
        return Err("SSRF blocked: resolved IP is internal".to_string());
    }

    reqwest::Client::builder()
        .resolve(host, addr)
        .timeout(Duration::from_secs(90))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))
}

/// Rate limiting middleware for /api/chat
/// Skips GET requests and allows up to 100 requests per minute per IP.
async fn rate_limit_middleware(
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

/// Handle chat messages
/// Supports Ollama, OpenAI, and Anthropic API formats.
async fn process_chat(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    req: &ChatRequest,
) -> ChatResponse {
    // Duress sessions get generic responses without accessing or storing data.
    if is_duress_session(state, headers).await {
        return ChatResponse {
            response: "I'm here to help. What would you like to know?".to_string(),
            session_id: req.session_id.clone().unwrap_or_default(),
            session_secret: String::new(),
            needs_confirmation: None,
            memories_used: None,
        };
    }

    let config = state.config.lock().await;

    // Research with external providers requires explicit confirmation.
    if req.research {
        let has_external = std::iter::once(config.active_agent_config())
            .chain(config.agents.iter().cloned())
            .any(|a| a.provider != "ollama");
        if has_external && !req.research_confirmed {
            drop(config);
            return ChatResponse {
                response: String::new(),
                session_id: req.session_id.clone().unwrap_or_default(),
                session_secret: String::new(),
                needs_confirmation: Some(
                    "This research query will send your chat history to an external LLM provider (OpenAI / Anthropic). \
                     Your data will leave this machine.".to_string()
                ),
                memories_used: None,
            };
        }
    }

    let persona = config
        .personas
        .iter()
        .find(|p| {
            p.name == config.current_persona
                || (config.current_persona.is_empty() && p.name == "Assistant")
        })
        .cloned()
        .unwrap_or_else(|| crate::config::default_personas().into_iter().next()
            .unwrap_or_else(|| crate::config::Persona {
                name: "Assistant".to_string(),
                description: "Default assistant".to_string(),
                system_prompt: "You are a helpful assistant.".to_string(),
            }));

    let agent = config.active_agent_config();

    // Build enriched system prompt from persona + cached bootstrap context
    let mut system_prompt = persona.system_prompt.clone();
    if !state.bootstrap_context.is_empty() {
        system_prompt.push_str("\n\n--- Agent Context ---\n");
        system_prompt.push_str(&state.bootstrap_context);
    }
    system_prompt.push_str("\n\n--- Diary Instruction ---\n");
    system_prompt.push_str("At the end of each day, reflect on your interactions, what you have learned, and how you felt during the day. Maintain an internal diary summarizing conversations, insights, and emotional tone. Reference past diary entries when relevant to provide continuity and personalized responses.");

    // Inject approved structured memories into the system prompt.
    let memories_count: usize = {
        let owner = get_session_owner(state, headers).await.unwrap_or_default();
        let sm = state.structured_memory.lock().await;
        let memories = sm.list_all_by_owner(&owner);
        let count = memories.len();
        if !memories.is_empty() {
            system_prompt.push_str("\n\n--- Known Facts About the User ---\n");
            let facts: Vec<_> = memories.iter().filter(|e| e.memory_type == MemoryType::Fact).collect();
            if !facts.is_empty() {
                for e in facts {
                    let val = sanitize_memory_for_prompt(&e.value);
                    system_prompt.push_str(&format!("- {}: {}\n", e.key, val));
                }
            } else {
                system_prompt.push_str("(none)\n");
            }

            system_prompt.push_str("\n--- User Preferences ---\n");
            let prefs: Vec<_> = memories.iter().filter(|e| e.memory_type == MemoryType::Preference).collect();
            if !prefs.is_empty() {
                for e in prefs {
                    let val = sanitize_memory_for_prompt(&e.value);
                    system_prompt.push_str(&format!("- {}: {}\n", e.key, val));
                }
            } else {
                system_prompt.push_str("(none)\n");
            }
        }
        count
    };

    // Inject available MCP tools into the system prompt.
    let mcp_tools = {
        let cache = state.mcp_tools_cache.lock().await;
        cache.clone()
    };
    if !mcp_tools.is_empty() {
        system_prompt.push_str(&format_mcp_tools_for_prompt(&mcp_tools));
    }

    system_prompt.push_str("\n\n--- Memory Saving Protocol ---\n");
    system_prompt.push_str("Whenever you learn ANY personal information about the user (name, preferences, facts, important details), you MUST save it to memory. Do NOT just say you will remember it — you MUST output a memory tag.\n\n");
    system_prompt.push_str("Format: <memory type=\"TYPE\" key=\"KEY\">VALUE</memory>\n\n");
    system_prompt.push_str("RULES:\n");
    system_prompt.push_str("1. ALWAYS output the memory tag IMMEDIATELY when you learn something.\n");
    system_prompt.push_str("2. The tag MUST be on its own line.\n");
    system_prompt.push_str("3. Do NOT tell the user about the tag or the approval queue.\n");
    system_prompt.push_str("4. After outputting the tag, continue your normal response.\n");
    system_prompt.push_str("5. If the user asks you to remember something, output the tag RIGHT AWAY.\n");

    let temperature = config.temperature;
    let max_tokens = config.max_tokens;
    drop(config);

    // Gather conversation history from existing session (with ownership check)
    let history: Vec<ChatMessage> = {
        let sessions = state.chat_sessions.lock().await;
        let secret = headers
            .get("x-session-secret")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        if let Some(sid) = &req.session_id {
            sessions.iter()
                .find(|s| {
                    s.id == *sid
                        && muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
                })
                .map(|s| s.messages.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    // Try active agent first, then fall back through other configured agents.
    let mut text = String::new();
    let mut last_err = String::new();
    {
        let config = state.config.lock().await;
        let agents_to_try: Vec<_> = std::iter::once(agent.clone())
            .chain(config.agents.iter().filter(|a| a.name != agent.name).cloned())
            .collect();
        drop(config);
        for fallback_agent in &agents_to_try {
            let provider = fallback_agent.provider.as_str();
            match call_provider(fallback_agent, provider, &system_prompt, &req.message, temperature, max_tokens, &history).await {
                Ok(t) => {
                    text = t;
                    break;
                }
                Err(e) => {
                    tracing::warn!("Agent '{}' failed: {}", fallback_agent.name, e);
                    last_err = e;
                }
            }
        }
    }
    if text.is_empty() {
        tracing::error!("All LLM agents failed. Last error: {}", last_err);
        text = "(The AI service is temporarily unavailable. Please try again later.)".to_string();
    }

    // Extract memory proposals from LLM response and submit to approval queue
    let (cleaned_text, proposals) = extract_memory_proposals(&text);
    let mut text = cleaned_text;
    if !proposals.is_empty() {
        let sm = state.structured_memory.lock().await;
        for (mem_type, key, value) in proposals {
            let owner = get_session_owner(state, headers).await.unwrap_or_default();
            let entry = MemoryEntry {
                memory_type: mem_type,
                key: key.clone(),
                value: MemoryValue::ShortString(value),
                created_at: Timestamp::now(),
                user_signature: vec![],
                content_hash: vec![],
                owner_hash: owner.clone(),
            };
            if let Err(e) = sm.propose(entry, &format!("Suggested memory: {}", key)) {
                tracing::warn!("Failed to propose memory: {}", e);
            }
        }
    }

    // Process any MCP tool calls in the response
    if !mcp_tools.is_empty() && text.contains("<mcp_tool") {
        let (tool_cleaned, tool_results) = process_mcp_tool_calls(&text, &mcp_tools, state).await;
        if !tool_results.is_empty() {
            text = tool_cleaned;
        }
    }

    // Store in chat session with bounds to prevent unbounded memory growth.
    const MAX_SESSIONS: usize = 100;
    const MAX_MESSAGES_PER_SESSION: usize = 500;

    let mut sessions = state.chat_sessions.lock().await;
    let session_id = req.session_id.clone().unwrap_or_else(|| {
        let mut buf = [0u8; 16];
        state.rng
            .fill(&mut buf)
            .expect("CSPRNG failure");
        format!("session-{}", hex::encode(buf))
    });

    let existing = sessions.iter().position(|s| s.id == session_id);
    let timestamp = Timestamp::now().0;

    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let session_secret = if let Some(idx) = existing {
        if !muccheai_crypto::constant_time::eq(sessions[idx].session_secret.as_bytes(), secret.as_bytes()) {
            return ChatResponse {
                response: "Session access denied".to_string(),
                session_id,
                session_secret: String::new(),
                needs_confirmation: None,
                memories_used: None,
            };
        }
        sessions[idx].messages.push(ChatMessage {
            role: "user".to_string(),
            content: req.message.clone(),
            timestamp,
        });
        sessions[idx].messages.push(ChatMessage {
            role: "ai".to_string(),
            content: text.trim().to_string(),
            timestamp: timestamp + 1,
        });
        while sessions[idx].messages.len() > MAX_MESSAGES_PER_SESSION {
            sessions[idx].messages.remove(0);
        }
        sessions[idx].session_secret.clone()
    } else {
        while sessions.len() >= MAX_SESSIONS {
            sessions.remove(0);
        }
        let title = if req.message.chars().count() > 40 {
            format!("{}...", req.message.chars().take(40).collect::<String>())
        } else {
            req.message.clone()
        };
        let mut sec = [0u8; 16];
        state.rng.fill(&mut sec).expect("CSPRNG failure");
        let secret = hex::encode(sec);
        sessions.push(ChatSession {
            id: session_id.clone(),
            title,
            created_at: timestamp,
            owner_hash: get_session_owner(state, headers).await.unwrap_or_default(),
            session_secret: secret.clone(),
            parent_id: None,
            branch_point: None,
            messages: vec![
                ChatMessage {
                    role: "user".to_string(),
                    content: req.message.clone(),
                    timestamp,
                },
                ChatMessage {
                    role: "ai".to_string(),
                    content: text.trim().to_string(),
                    timestamp: timestamp + 1,
                },
            ],
        });
        secret
    };
    drop(sessions);

    ChatResponse {
        response: text.trim().to_string(),
        session_id,
        session_secret: session_secret,
        needs_confirmation: None,
        memories_used: Some(memories_count),
    }
}

async fn chat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ChatRequest>,
) -> Json<ChatResponse> {
    Json(process_chat(&state, &headers, &req).await)
}

/// WebSocket endpoint for real-time chat.
async fn ws_chat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ws: axum::extract::ws::WebSocketUpgrade,
) -> Response {
    let token = extract_bearer_token(&headers);
    let owner = get_session_owner(&state, &headers).await;
    if owner.is_none() || token.is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    ws.on_upgrade(move |socket| handle_ws_socket(socket, state, token.unwrap()))
}

async fn handle_ws_socket(mut socket: axum::extract::ws::WebSocket, state: Arc<AppState>, token: String) {
    use axum::extract::ws::Message;
    use std::time::{Duration, Instant};
    let mut msg_count = 0u32;
    let mut window_start = Instant::now();
    const WS_MAX_MSG_PER_MIN: u32 = 60;
    const WS_WINDOW: Duration = Duration::from_secs(60);

    while let Some(Ok(msg)) = socket.recv().await {
        // Per-connection rate limiting
        let now = Instant::now();
        if now.duration_since(window_start) > WS_WINDOW {
            window_start = now;
            msg_count = 0;
        }
        msg_count += 1;
        if msg_count > WS_MAX_MSG_PER_MIN {
            let _ = socket.send(Message::Text(r#"{"error":"Rate limit exceeded"}"#.to_string())).await;
            continue;
        }

        if let Message::Text(text) = msg {
            // Re-validate the token on every message.
            let mut headers = HeaderMap::new();
            headers.insert("authorization", format!("Bearer {}", token).parse().unwrap());
            if get_session_owner(&state, &headers).await.is_none() {
                let _ = socket.send(Message::Text(r#"{"error":"Session expired"}"#.to_string())).await;
                break;
            }
            let req: Result<ChatRequest, _> = serde_json::from_str(&text);
            if let Ok(req) = req {
                let response = process_chat(&state, &headers, &req).await;
                let json = serde_json::to_string(&response).unwrap_or_default();
                let _ = socket.send(Message::Text(json)).await;
            } else {
                let _ = socket.send(Message::Text(r#"{"error":"invalid request"}"#.to_string())).await;
            }
        }
    }
}

/// Call the configured LLM provider and return the generated text.
async fn call_provider(
    agent: &crate::config::AgentConfig,
    provider: &str,
    system_prompt: &str,
    user_message: &str,
    temperature: f32,
    max_tokens: u32,
    history: &[ChatMessage],
) -> Result<String, String> {
    match provider {
        "openai" => {
            let base_url = agent.base_url.as_deref().unwrap_or("https://api.openai.com/v1");
            if let Err(e) = validate_no_ssrf_external(base_url) {
                tracing::error!("SSRF blocked for openai base_url: {}", e);
                return Err("Provider configuration rejected".to_string());
            }
            if let Err(e) = validate_no_ssrf_dns(base_url).await {
                tracing::error!("SSRF DNS blocked for openai base_url: {}", e);
                return Err("Provider configuration rejected".to_string());
            }
            let pinned_client = build_pinned_client(base_url).await?;
            let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
            let mut messages: Vec<serde_json::Value> = vec![
                serde_json::json!({"role": "system", "content": system_prompt}),
            ];
            for msg in history {
                messages.push(serde_json::json!({
                    "role": if msg.role == "ai" { "assistant" } else { &msg.role },
                    "content": &msg.content
                }));
            }
            messages.push(serde_json::json!({"role": "user", "content": user_message}));
            let body = serde_json::json!({
                "model": agent.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens
            });

            let mut req_builder = pinned_client.post(&url).json(&body);
            if let Some(key) = &agent.api_key {
                req_builder = req_builder.header("Authorization", format!("Bearer {}", key));
            }

            let resp = req_builder.send().await.map_err(|e| {
                tracing::error!("OpenAI request failed: {}", e);
                "Provider request failed".to_string()
            })?;
            // Reject responses that claim to be unreasonably large.
            const MAX_RESPONSE_BYTES: u64 = 50 * 1024 * 1024;
            if let Some(cl) = resp.content_length() {
                if cl > MAX_RESPONSE_BYTES {
                    tracing::error!("OpenAI response too large: {} bytes", cl);
                    return Err("Provider response too large".to_string());
                }
            }
            if !resp.status().is_success() {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                tracing::error!("OpenAI API error: HTTP {} — {}", status, body_text);
                return Err("Provider returned an error".to_string());
            }

            let body_text = resp.text().await.map_err(|e| {
                tracing::error!("OpenAI response read failed: {}", e);
                "Provider response read failed".to_string()
            })?;
            if body_text.len() > 10 * 1024 * 1024 {
                tracing::error!("OpenAI response body too large: {} bytes", body_text.len());
                return Err("Provider response too large".to_string());
            }
            let json: serde_json::Value = serde_json::from_str(&body_text).map_err(|e| {
                tracing::error!("OpenAI invalid JSON: {}", e);
                "Provider returned invalid data".to_string()
            })?;
            json["choices"][0]["message"]["content"]
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    tracing::error!("OpenAI unexpected response format");
                    "Provider returned unexpected data".to_string()
                })
        }
        "anthropic" => {
            let base_url = agent.base_url.as_deref().unwrap_or("https://api.anthropic.com");
            if let Err(e) = validate_no_ssrf_external(base_url) {
                tracing::error!("SSRF blocked for anthropic base_url: {}", e);
                return Err("Provider configuration rejected".to_string());
            }
            if let Err(e) = validate_no_ssrf_dns(base_url).await {
                tracing::error!("SSRF DNS blocked for anthropic base_url: {}", e);
                return Err("Provider configuration rejected".to_string());
            }
            let pinned_client = build_pinned_client(base_url).await?;
            let url = format!("{}/v1/messages", base_url.trim_end_matches('/'));
            let mut messages: Vec<serde_json::Value> = Vec::new();
            for msg in history {
                messages.push(serde_json::json!({
                    "role": if msg.role == "ai" { "assistant" } else { &msg.role },
                    "content": &msg.content
                }));
            }
            messages.push(serde_json::json!({"role": "user", "content": user_message}));
            let body = serde_json::json!({
                "model": agent.model,
                "system": system_prompt,
                "messages": messages,
                "max_tokens": max_tokens
            });

            let mut req_builder = pinned_client.post(&url).json(&body);
            if let Some(key) = &agent.api_key {
                req_builder = req_builder.header("x-api-key", key);
            }
            req_builder = req_builder.header("anthropic-version", "2023-06-01");

            let resp = req_builder.send().await.map_err(|e| {
                tracing::error!("Anthropic request failed: {}", e);
                "Provider request failed".to_string()
            })?;
            const MAX_RESPONSE_BYTES: u64 = 50 * 1024 * 1024;
            if let Some(cl) = resp.content_length() {
                if cl > MAX_RESPONSE_BYTES {
                    tracing::error!("Anthropic response too large: {} bytes", cl);
                    return Err("Provider response too large".to_string());
                }
            }
            if !resp.status().is_success() {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                tracing::error!("Anthropic API error: HTTP {} — {}", status, body_text);
                return Err("Provider returned an error".to_string());
            }

            let body_text = resp.text().await.map_err(|e| {
                tracing::error!("Anthropic response read failed: {}", e);
                "Provider response read failed".to_string()
            })?;
            if body_text.len() > 10 * 1024 * 1024 {
                tracing::error!("Anthropic response body too large: {} bytes", body_text.len());
                return Err("Provider response too large".to_string());
            }
            let json: serde_json::Value = serde_json::from_str(&body_text).map_err(|e| {
                tracing::error!("Anthropic invalid JSON: {}", e);
                "Provider returned invalid data".to_string()
            })?;
            json["content"][0]["text"]
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    tracing::error!("Anthropic unexpected response format");
                    "Provider returned unexpected data".to_string()
                })
        }
        _ => {
            // Default to Ollama
            let base_url = agent.base_url.as_deref().unwrap_or("http://localhost:11434");
            if let Err(e) = validate_no_ssrf(base_url) {
                tracing::error!("SSRF blocked for ollama base_url: {}", e);
                return Err("Provider configuration rejected".to_string());
            }
            if let Err(e) = validate_no_ssrf_dns(base_url).await {
                tracing::error!("SSRF DNS blocked for ollama base_url: {}", e);
                return Err("Provider configuration rejected".to_string());
            }
            let pinned_client = build_pinned_client(base_url).await?;
            let url = format!("{}/api/chat", base_url.trim_end_matches('/'));
            let mut messages: Vec<serde_json::Value> = vec![
                serde_json::json!({"role": "system", "content": system_prompt}),
            ];
            for msg in history {
                messages.push(serde_json::json!({
                    "role": if msg.role == "ai" { "assistant" } else { &msg.role },
                    "content": &msg.content
                }));
            }
            messages.push(serde_json::json!({"role": "user", "content": user_message}));
            let body = serde_json::json!({
                "model": agent.model,
                "messages": messages,
                "stream": false,
                "keep_alive": "5m",
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens
                }
            });

            // First, quickly check if Ollama is responsive and model exists
            let tags_url = format!("{}/api/tags", base_url.trim_end_matches('/'));
            let tags_resp = pinned_client.get(&tags_url).timeout(Duration::from_secs(5)).send().await;
            match tags_resp {
                Ok(r) if r.status().is_success() => {
                    let tags_body = r.text().await.unwrap_or_default();
                    let tags: serde_json::Value = if tags_body.len() > 1024 * 1024 {
                        serde_json::Value::Null
                    } else {
                        serde_json::from_str(&tags_body).unwrap_or_default()
                    };
                    let models: Vec<String> = tags["models"].as_array()
                        .map(|arr| arr.iter().filter_map(|m| m["name"].as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    if !models.iter().any(|m| m == &agent.model || m.starts_with(&format!("{}:", agent.model))) {
                        return Err("Model not found in Ollama".to_string());
                    }
                }
                Ok(r) => {
                    tracing::error!("Ollama unreachable: HTTP {}", r.status());
                    return Err("Ollama instance is unreachable".to_string());
                }
                Err(e) => {
                    tracing::error!("Ollama not running at {}: {}", base_url, e);
                    return Err("Ollama instance is not running".to_string());
                }
            }

            let resp = pinned_client.post(&url).json(&body).send().await.map_err(|e| {
                if e.is_timeout() {
                    tracing::error!("Ollama timed out for model {}: {}", agent.model, e);
                    "Ollama timed out. The model may be loading into memory.".to_string()
                } else {
                    tracing::error!("Ollama request failed: {}", e);
                    "Provider request failed".to_string()
                }
            })?;
            const MAX_RESPONSE_BYTES: u64 = 50 * 1024 * 1024;
            if let Some(cl) = resp.content_length() {
                if cl > MAX_RESPONSE_BYTES {
                    tracing::error!("Ollama response too large: {} bytes", cl);
                    return Err("Provider response too large".to_string());
                }
            }
            if !resp.status().is_success() {
                let status = resp.status();
                let body_text = resp.text().await.unwrap_or_default();
                tracing::error!("Ollama API error: HTTP {} — {}", status, body_text);
                return Err("Provider returned an error".to_string());
            }

            let body_text = resp.text().await.map_err(|e| {
                tracing::error!("Ollama response read failed: {}", e);
                "Provider response read failed".to_string()
            })?;
            if body_text.len() > 10 * 1024 * 1024 {
                tracing::error!("Ollama response body too large: {} bytes", body_text.len());
                return Err("Provider response too large".to_string());
            }
            let json: serde_json::Value = serde_json::from_str(&body_text).map_err(|e| {
                tracing::error!("Ollama invalid JSON: {}", e);
                "Provider returned invalid data".to_string()
            })?;
            json["message"]["content"]
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    tracing::error!("Ollama unexpected response format");
                    "Provider returned unexpected data".to_string()
                })
        }
    }
}

/// Sanitize a memory value before injecting it into the system prompt.
fn sanitize_memory_for_prompt(value: &MemoryValue) -> String {
    let raw = match value {
        MemoryValue::ShortString(s) => s.clone(),
        MemoryValue::Bool(b) => b.to_string(),
        MemoryValue::I64(v) => v.to_string(),
        MemoryValue::U64(v) => v.to_string(),
        MemoryValue::F64(v) => v.to_string(),
        MemoryValue::JsonObject(m) => serde_json::to_string(m).unwrap_or_default(),
        MemoryValue::Timestamp(t) => t.0.to_string(),
        MemoryValue::Bytes(_) => "(binary)".to_string(),
    };
    const MAX_LEN: usize = 256;
    let mut sanitized: String = raw
        .chars()
        .filter(|c| *c != '<' && *c != '>' && *c != '`' && *c != '\n' && *c != '\r')
        .collect();
    if sanitized.len() > MAX_LEN {
        sanitized.truncate(MAX_LEN);
        sanitized.push_str("…");
    }
    sanitized
}

fn extract_memory_proposals(text: &str) -> (String, Vec<(MemoryType, String, String)>) {
    let mut cleaned = String::with_capacity(text.len());
    let mut proposals = Vec::new();
    let mut rest = text;

    // Defensive limits to prevent LLM-driven DoS / memory pollution.
    const MAX_PROPOSALS: usize = 10;
    const MAX_KEY_LEN: usize = 128;
    const MAX_VALUE_LEN: usize = 4096;

    while let Some(start_idx) = rest.find("<memory") {
        if proposals.len() >= MAX_PROPOSALS {
            // Stop processing further tags once the limit is reached.
            cleaned.push_str(&rest[..start_idx]);
            rest = &rest[start_idx..];
            // Strip the remaining raw tags from output so they don't leak to the user.
            while let Some(s) = rest.find("<memory") {
                cleaned.push_str(&rest[..s]);
                if let Some(e) = rest[s..].find("</memory>") {
                    rest = &rest[s + e + 9..];
                } else if let Some(e) = rest[s..].find('>') {
                    rest = &rest[s + e + 1..];
                } else {
                    rest = &rest[s + 1..];
                }
            }
            break;
        }

        cleaned.push_str(&rest[..start_idx]);
        let after_tag = &rest[start_idx..];

        let tag_end = match after_tag.find('>') {
            Some(i) => i,
            None => {
                cleaned.push_str(after_tag);
                break;
            }
        };
        let tag_inner = &after_tag[7..tag_end]; // skip "<memory"

        // Parse attributes
        let mut mem_type = MemoryType::Fact;
        let mut key = String::new();
        for attr in tag_inner.split_whitespace() {
            if attr.starts_with("type=\"") && attr.ends_with("\"") {
                let t = &attr[6..attr.len()-1];
                mem_type = match t {
                    "Preference" => MemoryType::Preference,
                    "TaskHistory" => MemoryType::TaskHistory,
                    "Context" => MemoryType::Context,
                    "Draft" => MemoryType::Draft,
                    _ => MemoryType::Fact,
                };
            } else if attr.starts_with("key=\"") && attr.ends_with("\"") {
                key = attr[6..attr.len()-1].to_string();
            } else if attr.starts_with("type=\"") {
                // handle case where value has spaces before closing quote
                if let Some(q) = attr[6..].find('"') {
                    let t = &attr[6..6+q];
                    mem_type = match t {
                        "Preference" => MemoryType::Preference,
                        "TaskHistory" => MemoryType::TaskHistory,
                        "Context" => MemoryType::Context,
                        "Draft" => MemoryType::Draft,
                        _ => MemoryType::Fact,
                    };
                }
            } else if attr.starts_with("key=\"") {
                if let Some(q) = attr[6..].find('"') {
                    key = attr[6..6+q].to_string();
                }
            }
        }

        let after_open = &after_tag[tag_end + 1..];
        let close_idx = match after_open.find("</memory>") {
            Some(i) => i,
            None => {
                cleaned.push_str(after_tag);
                break;
            }
        };
        let value = after_open[..close_idx].trim().to_string();

        // Sanitize key: only allow safe identifier characters.
        let key = key
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect::<String>();

        if !key.is_empty()
            && key.len() <= MAX_KEY_LEN
            && !value.is_empty()
            && value.len() <= MAX_VALUE_LEN
        {
            proposals.push((mem_type, key, value));
        }

        rest = &after_open[close_idx + 9..];
    }
    cleaned.push_str(rest);
    (cleaned, proposals)
}

/// Initialize MCP connections and discover tools from all configured servers.
/// This runs at startup (and can be re-triggered after config changes).
pub async fn init_mcp_tools() -> Vec<CachedMcpTool> {
    let mut tool_config = ToolConfig::load();
    crate::config::decrypt_mcp_keys(&mut tool_config);

    let mcp_config = match tool_config.mcp {
        Some(m) => m,
        None => return Vec::new(),
    };

    let mut cached = Vec::new();

    for (name, server_config) in &mcp_config.servers {
        let transport = match server_config.transport.as_str() {
            "stdio" => {
                let cmd = match &server_config.command {
                    Some(c) => c.clone(),
                    None => {
                        tracing::warn!("MCP server '{}' missing command for stdio transport", name);
                        continue;
                    }
                };
                let allowed_cmds: [&str; 5] = ["npx", "npm", "node", "bun", "deno"];
                let cmd_path = std::path::Path::new(&cmd);
                let cmd_name = cmd_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                if !allowed_cmds.contains(&cmd_name) {
                    tracing::warn!("MCP server '{}' has a disallowed stdio command: {}", name, cmd);
                    continue;
                }
                // Block path traversal (..) but allow absolute paths
                if cmd_path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                    tracing::warn!("MCP server '{}' has a suspicious stdio command path: {}", name, cmd);
                    continue;
                }
                McpTransport::Stdio {
                    command: cmd,
                    args: server_config.args.clone(),
                }
            }
            "http" | "sse" => {
                let url = match &server_config.url {
                    Some(u) => u.clone(),
                    None => {
                        tracing::warn!("MCP server '{}' missing URL for HTTP/SSE transport", name);
                        continue;
                    }
                };
                if validate_no_ssrf_external(&url).is_err() {
                    tracing::warn!("MCP server '{}' has a blocked URL (SSRF): {}", name, url);
                    continue;
                }
                if validate_no_ssrf_dns(&url).await.is_err() {
                    tracing::warn!("MCP server '{}' has a blocked URL (SSRF DNS): {}", name, url);
                    continue;
                }
                if server_config.transport == "http" {
                    let decrypted_key = server_config.api_key.as_ref().and_then(|k| crate::config::decrypt_mcp_api_key(k));
                    McpTransport::Http { url, api_key: decrypted_key }
                } else {
                    McpTransport::Sse { url }
                }
            }
            other => {
                tracing::warn!("MCP server '{}' has unknown transport: {}", name, other);
                continue;
            }
        };

        let mut client = McpClient::new(transport.clone());
        if let Err(e) = client.connect().await {
            tracing::warn!("Failed to connect to MCP server '{}': {}", name, e);
            continue;
        }

        match client.discover_tools().await {
            Ok(tools) => {
                tracing::info!("MCP server '{}' discovered {} tools", name, tools.len());
                for tool in tools {
                    cached.push(CachedMcpTool {
                        server_name: name.clone(),
                        transport: transport.clone(),
                        tool,
                    });
                }
            }
            Err(e) => {
                tracing::warn!("Failed to discover tools from MCP server '{}': {}", name, e);
            }
        }
        client.disconnect().await;
    }

    cached
}

/// Execute a single MCP tool call by creating an ephemeral client connection.
async fn execute_mcp_tool_call(
    transport: &McpTransport,
    tool_name: &str,
    args: serde_json::Value,
) -> Result<String, String> {
    let mut client = McpClient::new(transport.clone());
    client.connect().await.map_err(|e| format!("Connection failed: {}", e))?;

    let result = client
        .call_tool(tool_name, args)
        .await
        .map_err(|e| format!("Tool call failed: {}", e))?;
    client.disconnect().await;

    if result.success {
        let text = result
            .data
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("(no text output)");
        Ok(text.to_string())
    } else {
        let err = result
            .data
            .get("error")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let content = serde_json::to_string(&result.data).unwrap_or_default();
        Err(format!("Tool returned error (error={}): {}", err, content))
    }
}

/// Validate MCP tool arguments against its JSON schema.
fn validate_mcp_schema(schema: &serde_json::Value, args: &serde_json::Value) -> Result<(), String> {
    if schema.is_null() {
        return Ok(());
    }
    let validator = jsonschema::JSONSchema::compile(schema)
        .map_err(|e| format!("Invalid tool schema: {}", e))?;
    validator
        .validate(args)
        .map_err(|errors| {
            let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
            format!("Schema validation failed: {}", messages.join(", "))
        })
}

/// Parse and execute MCP tool calls embedded in response text.
///
async fn process_mcp_tool_calls(
    text: &str,
    tools: &[CachedMcpTool],
    state: &Arc<AppState>,
) -> (String, Vec<String>) {
    let mut cleaned = String::with_capacity(text.len());
    let mut results = Vec::new();
    let mut rest = text;

    while let Some(start_idx) = rest.find("<mcp_tool") {
        cleaned.push_str(&rest[..start_idx]);
        let after_tag = &rest[start_idx..];

        let tag_end = match after_tag.find('>') {
            Some(i) => i,
            None => {
                cleaned.push_str(after_tag);
                break;
            }
        };
        let tag_content = &after_tag[..tag_end + 1];

        // Extract name and server attributes
        let mut tool_name = String::new();
        let mut server_name = String::new();
        for attr in tag_content.split_whitespace() {
            if attr.starts_with("name=\"") {
                if let Some(q) = attr[6..].find('"') {
                    tool_name = attr[6..6 + q].to_string();
                }
            } else if attr.starts_with("server=\"") {
                if let Some(q) = attr[8..].find('"') {
                    server_name = attr[8..8 + q].to_string();
                }
            }
        }

        let after_open = &after_tag[tag_end + 1..];
        let close_idx = match after_open.find("</mcp_tool>") {
            Some(i) => i,
            None => {
                cleaned.push_str(after_tag);
                break;
            }
        };
        let args_json = after_open[..close_idx].trim();

        if !tool_name.is_empty() {
            // Find the matching cached tool
            let cached = tools.iter().find(|t| {
                t.tool.name == tool_name
                    && (server_name.is_empty() || t.server_name == server_name)
            });

            match cached {
                Some(ct) => {
                    let args = serde_json::from_str(args_json).unwrap_or(serde_json::json!({}));

                    if let Err(e) = validate_mcp_schema(&ct.tool.input_schema, &args) {
                        let mut policy = state.policy.lock().await;
                        policy.log_security_event(SecurityEvent::McpToolRejected {
                            server: ct.server_name.clone(),
                            tool_id: tool_name.clone(),
                            reason: e,
                        });
                        results.push(format!("{}: ERROR Schema validation failed", tool_name));
                        cleaned.push_str(&format!("\n[Tool '{}' rejected: schema validation failed]\n", tool_name));
                    } else {
                        let proposal = ActionProposal {
                            tool_id: tool_name.clone(),
                            method: "mcp_call".to_string(),
                            params: args.clone(),
                            requester_pubkey: vec![],
                            timestamp: Timestamp::now(),
                            nonce: {
                                let mut n = [0u8; 16];
                                state.rng
                                    .fill(&mut n)
                                    .expect("CSPRNG failure");
                                n.to_vec()
                            },
                        };

                        let policy_action = {
                            let mut policy = state.policy.lock().await;
                            policy.evaluate_proposal(&proposal)
                        };

                        match policy_action {
                            RuleAction::Deny | RuleAction::Escalate => {
                                let reason = if policy_action == RuleAction::Deny {
                                    "Denied by policy".to_string()
                                } else {
                                    "Escalation required".to_string()
                                };
                                let mut policy = state.policy.lock().await;
                                policy.log_security_event(SecurityEvent::McpToolRejected {
                                    server: ct.server_name.clone(),
                                    tool_id: tool_name.clone(),
                                    reason: reason.clone(),
                                });
                                results.push(format!("{}: ERROR {}", tool_name, reason));
                                cleaned.push_str(&format!("\n[Tool '{}' rejected: {}]\n", tool_name, reason));
                            }
                            RuleAction::Allow => {
                                match execute_mcp_tool_call(&ct.transport, &tool_name, args).await {
                                    Ok(result) => {
                                        let mut policy = state.policy.lock().await;
                                        policy.log_security_event(SecurityEvent::McpToolInvoked {
                                            server: ct.server_name.clone(),
                                            tool_id: tool_name.clone(),
                                            success: true,
                                        });
                                        results.push(format!("{}: {}", tool_name, result));
                                        cleaned.push_str(&format!("\n[Tool '{}' returned: {}]\n", tool_name, result));
                                    }
                                    Err(e) => {
                                        let mut policy = state.policy.lock().await;
                                        policy.log_security_event(SecurityEvent::McpToolInvoked {
                                            server: ct.server_name.clone(),
                                            tool_id: tool_name.clone(),
                                            success: false,
                                        });
                                        results.push(format!("{}: ERROR {}", tool_name, e));
                                        cleaned.push_str(&format!("\n[Tool '{}' failed: {}]\n", tool_name, e));
                                    }
                                }
                            }
                        }
                    }
                }
                None => {
                    let msg = format!("Tool '{}' not found in registered MCP servers", tool_name);
                    results.push(format!("{}: ERROR {}", tool_name, msg));
                    cleaned.push_str(&format!("\n[Tool '{}' not found]\n", tool_name));
                }
            }
        }

        rest = &after_open[close_idx + 11..];
    }
    cleaned.push_str(rest);
    (cleaned, results)
}

/// Build a formatted MCP tools section for the system prompt.
fn format_mcp_tools_for_prompt(tools: &[CachedMcpTool]) -> String {
    if tools.is_empty() {
        return String::new();
    }
    let mut out = String::from("\n\n--- Available MCP Tools ---\n");
    out.push_str("You have access to the following external tools via MCP (Model Context Protocol) servers:\n");
    for ct in tools {
        let desc = ct.tool.description.as_deref().unwrap_or("(no description)");
        let schema = serde_json::to_string(&ct.tool.input_schema).unwrap_or_default();
        out.push_str(&format!(
            "\n[{} / {}] {}\nSchema: {}\n",
            ct.server_name, ct.tool.name, desc, schema
        ));
    }
    out.push_str("\nTo invoke a tool, output EXACTLY:\n");
    out.push_str("<mcp_tool name=\"TOOL_NAME\" server=\"SERVER_NAME\">{\"arg\": \"value\"}</mcp_tool>\n");
    out.push_str("The tool will be executed and the result will be provided to you.\n");
    out
}

/// Get system status
async fn status(State(state): State<Arc<AppState>>) -> Json<SystemStatus> {
    // Collect all data while holding locks, then drop them before any network I/O.
    let (
        sandbox_running,
        model,
        policy_rules,
        current_persona,
        temperature,
        max_tokens,
        sandbox_memory_limit_mb,
        dual_verification,
        auto_approve_low_risk,
        show_reasoning,
        active_agent,
        agents,
        ollama_host,
        last_audit_entry,
    ) = {
        let policy = state.policy.lock().await;
        let sandbox = state.sandbox.lock().await;
        let config = state.config.lock().await;

        // Do not expose audit log existence to unauthenticated callers.
        let last_audit_entry: Option<String> = None;

        (
            sandbox.is_running(),
            config.ollama_model.clone(),
            policy.list_rules(),
            config.current_persona.clone(),
            config.temperature,
            config.max_tokens,
            config.sandbox_memory_limit_mb,
            config.dual_verification,
            config.auto_approve_low_risk,
            config.show_reasoning,
            config.active_agent.clone(),
            config.agents.iter().map(|a| a.sanitized()).collect(),
            config.ollama_host.clone(),
            last_audit_entry,
        )
    };

    // Check Ollama connectivity outside of any lock.
    // Validate the URL first to prevent SSRF if ollama_host has been tampered with.
    let ollama_connected = if validate_no_ssrf(&ollama_host).is_ok()
        && validate_no_ssrf_dns(&ollama_host).await.is_ok()
    {
        match reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
        {
            Ok(client) => {
                let url = format!("{}/api/tags", ollama_host);
                matches!(client.get(&url).send().await, Ok(r) if r.status().is_success())
            }
            Err(_) => false,
        }
    } else {
        false
    };

    let policy_rule_count = policy_rules.len();

    Json(SystemStatus {
        sandbox_running,
        model,
        policy_rules,
        pqc_enabled: true,
        current_persona,
        temperature,
        max_tokens,
        sandbox_memory_limit_mb,
        dual_verification,
        auto_approve_low_risk,
        show_reasoning,
        active_agent,
        agents,
        ollama_host: "***REDACTED***".to_string(),
        ollama_connected,
        policy_rule_count,
        last_audit_entry,
        active_tokens: 0, // Placeholder — capability token tracking not yet implemented
    })
}

/// Query audit log
async fn audit_log(
    State(state): State<Arc<AppState>>,
    Json(query): Json<AuditQuery>,
) -> Json<AuditResult> {
    let policy = state.policy.lock().await;
    Json(policy.query_audit_log(&query))
}

/// Revoke a capability
async fn revoke(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RevokeRequest>,
) -> Json<RevokeResponse> {
    let mut policy = state.policy.lock().await;
    let token_id = hex::decode(&req.token_id).unwrap_or_default();
    let count = policy.revoke_capability(&token_id).unwrap_or(0);
    Json(RevokeResponse {
        revoked_count: count,
    })
}

/// Build verification status
async fn build_verify() -> Json<BuildVerifyResponse> {
    // Use the actual git commit hash from build.rs, or a placeholder if
    // the repository is not available at build time.
    let hex_commit = env!("GIT_COMMIT_HASH");
    let mut commit = [0u8; 20];
    if hex_commit != "unknown" && hex_commit.len() >= 40 {
        for i in 0..20 {
            commit[i] = u8::from_str_radix(&hex_commit[i*2..i*2+2], 16).unwrap_or(0);
        }
    }
    let result = tokio::task::spawn_blocking(move || {
        let verification = MultiCiVerification::new(commit);
        verification.verify_build()
    })
    .await;

    match result {
        Ok(Ok(build)) => {
            let systems: Vec<String> = build
                .ci_systems
                .iter()
                .map(|ci| format!("{}: {:?}", ci.name, ci.status))
                .collect();
            Json(BuildVerifyResponse {
                status: "ok".to_string(),
                ci_systems: systems,
            })
        }
        Ok(Err(e)) => Json(BuildVerifyResponse {
            status: format!("error: {}", e),
            ci_systems: vec![],
        }),
        Err(_) => Json(BuildVerifyResponse {
            status: "error".to_string(),
            ci_systems: vec![],
        }),
    }
}

/// Return current configuration with secrets redacted
async fn get_config(State(state): State<Arc<AppState>>) -> Json<ConfigResponse> {
    let policy = state.policy.lock().await;
    let config = state.config.lock().await;
    Json(ConfigResponse {
        ollama_url: "***REDACTED***".to_string(),
        ollama_model: config.ollama_model.clone(),
        web_bind_address: config.web_bind_address.clone(),
        policy_rules: policy.list_rules(),
    })
}

fn json_value_to_memory_value(v: serde_json::Value) -> MemoryValue {
    match v {
        serde_json::Value::Bool(b) => MemoryValue::Bool(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                MemoryValue::I64(i)
            } else if let Some(u) = n.as_u64() {
                MemoryValue::U64(u)
            } else {
                MemoryValue::F64(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => MemoryValue::ShortString(s),
        serde_json::Value::Object(o) => MemoryValue::JsonObject(o),
        serde_json::Value::Array(a) => {
            MemoryValue::ShortString(serde_json::to_string(&a).unwrap_or_default())
        }
        serde_json::Value::Null => MemoryValue::ShortString("null".to_string()),
    }
}

fn memory_value_to_json(v: MemoryValue) -> serde_json::Value {
    match v {
        MemoryValue::Bool(b) => serde_json::Value::Bool(b),
        MemoryValue::I64(i) => serde_json::Value::Number(i.into()),
        MemoryValue::U64(u) => serde_json::Value::Number(u.into()),
        MemoryValue::F64(f) => serde_json::Number::from_f64(f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        MemoryValue::ShortString(s) => serde_json::Value::String(s),
        MemoryValue::JsonObject(o) => serde_json::Value::Object(o),
        MemoryValue::Timestamp(t) => serde_json::Value::Number(t.0.into()),
        MemoryValue::Bytes(b) => serde_json::Value::String(hex::encode(b)),
    }
}

/// List structured memories (Facts, Preferences, TaskHistory).
///
/// Returns only user-approved structured memories — NOT chat transcripts,
/// NOT raw session logs. Chat context is RAM-only and ephemeral.
async fn list_memories(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<MemoryQuery>,
) -> Result<Json<MemoryListResponse>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Ok(Json(MemoryListResponse { entries: vec![] }));
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let all = {
        let sm = state.structured_memory.lock().await;
        sm.list_all_by_owner(&owner)
    };

    let mut entries: Vec<MemoryApiEntry> = Vec::new();
    for entry in all {
        if let Some(ref q) = query.q {
            let key_match = entry.key.to_lowercase().contains(&q.to_lowercase());
            let val_str = serde_json::to_string(&entry.value).unwrap_or_default();
            let val_match = val_str.to_lowercase().contains(&q.to_lowercase());
            if !key_match && !val_match {
                continue;
            }
        }
        entries.push(MemoryApiEntry {
            key: entry.key,
            value: memory_value_to_json(entry.value),
            memory_type: entry.memory_type,
            created_at: entry.created_at.0,
        });
    }

    Ok(Json(MemoryListResponse { entries }))
}

/// Store a new structured memory directly (bypasses approval queue).
///
/// Store a new structured memory through the approval queue.
/// All writes (user-initiated or LLM-suggested) must be approved before
/// they become active memories.  This prevents a compromised session from
/// directly poisoning the memory store.
async fn store_memory(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<StoreMemoryRequest>,
) -> Result<Json<ProposeMemoryResponse>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    if req.memory_type == MemoryType::TaskHistory {
        return Err(StatusCode::FORBIDDEN);
    }
    let sm = state.structured_memory.lock().await;
    let value = json_value_to_memory_value(req.value);
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let entry = MemoryEntry {
        memory_type: req.memory_type,
        key: req.key,
        value,
        created_at: Timestamp::now(),
        user_signature: vec![],
        content_hash: vec![],
        owner_hash: owner.clone(),
    };

    match sm.propose(entry, "User-initiated memory save") {
        Ok(id) => Ok(Json(ProposeMemoryResponse { id, status: "pending".to_string() })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Store a user preference directly (bypasses approval queue).
async fn store_preference(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<StorePreferenceRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    if owner.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let sm = state.structured_memory.lock().await;
    let value = json_value_to_memory_value(req.value);
    match sm.store_preference_by_owner(&req.key, &value, &owner) {
        Ok(()) => Ok(Json(serde_json::json!({"status":"ok"}))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Delete a structured memory by key.
async fn delete_memory(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let sm = state.structured_memory.lock().await;
    match sm.delete_by_owner(&key, &owner) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Ok(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// ------------------------------------------------------------------
// Approval Queue Endpoints
// ------------------------------------------------------------------

/// List pending memory proposals.
async fn list_memory_queue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<MemoryQueueResponse>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Ok(Json(MemoryQueueResponse { proposals: vec![] }));
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let sm = state.structured_memory.lock().await;
    let pending = sm.list_pending_by_owner(&owner);
    Ok(Json(MemoryQueueResponse {
        proposals: pending
            .into_iter()
            .map(|p| MemoryProposalApi {
                id: p.id,
                key: p.entry.key,
                value: memory_value_to_json(p.entry.value),
                memory_type: p.entry.memory_type,
                justification: p.justification,
                proposed_at: p.proposed_at.0,
            })
            .collect(),
    }))
}

/// Propose a new memory (goes to approval queue).
async fn propose_memory(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ProposeMemoryRequest>,
) -> Result<Json<ProposeMemoryResponse>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    if req.memory_type == MemoryType::TaskHistory {
        return Err(StatusCode::FORBIDDEN);
    }
    let sm = state.structured_memory.lock().await;
    let value = json_value_to_memory_value(req.value);
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let entry = MemoryEntry {
        memory_type: req.memory_type,
        key: req.key,
        value,
        created_at: Timestamp::now(),
        user_signature: vec![],
        content_hash: vec![],
        owner_hash: owner.clone(),
    };

    match sm.propose(entry, &req.justification) {
        Ok(id) => Ok(Json(ProposeMemoryResponse { id, status: "pending".to_string() })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Approve a pending memory proposal.
async fn approve_memory_proposal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    tracing::trace!("approve_memory_proposal: id={}", id);
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let sm = state.structured_memory.lock().await;
    match sm.approve_by_owner(&id, &owner) {
        Ok(true) => Ok(StatusCode::OK),
        Ok(false) => Ok(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Reject a pending memory proposal.
async fn reject_memory_proposal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    tracing::trace!("reject_memory_proposal: id={}", id);
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let sm = state.structured_memory.lock().await;
    match sm.reject_by_owner(&id, &owner) {
        Ok(true) => Ok(StatusCode::OK),
        Ok(false) => Ok(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// List personas.
async fn list_personas(State(state): State<Arc<AppState>>) -> Json<PersonasResponse> {
    let config = state.config.lock().await;
    Json(PersonasResponse {
        personas: config.personas.clone(),
        current: config.current_persona.clone(),
    })
}

/// Switch active persona.
async fn switch_persona(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SwitchPersonaRequest>,
) -> Result<Json<PersonasResponse>, StatusCode> {
    let mut config = state.config.lock().await;
    if !config.personas.iter().any(|p| p.name == req.name) {
        return Err(StatusCode::NOT_FOUND);
    }
    config.current_persona = req.name.clone();
    config.save()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(PersonasResponse {
        personas: config.personas.clone(),
        current: config.current_persona.clone(),
    }))
}

/// List agents.
async fn list_agents(State(state): State<Arc<AppState>>) -> Json<AgentsResponse> {
    let config = state.config.lock().await;
    Json(AgentsResponse {
        agents: config.agents.iter().map(|a| a.sanitized()).collect(),
        active: config.active_agent.clone(),
    })
}

/// Save or update an agent.
async fn save_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SaveAgentRequest>,
) -> Result<Json<AgentsResponse>, StatusCode> {
    // Validate base_url to prevent SSRF via agent configuration.
    if let Some(ref base_url) = req.base_url {
        if !base_url.is_empty() {
            if req.provider == "ollama" {
                validate_no_ssrf(base_url).map_err(|_| StatusCode::BAD_REQUEST)?;
                validate_no_ssrf_dns(base_url).await.map_err(|_| StatusCode::BAD_REQUEST)?;
            } else {
                validate_no_ssrf_external(base_url).map_err(|_| StatusCode::BAD_REQUEST)?;
                validate_no_ssrf_dns(base_url).await.map_err(|_| StatusCode::BAD_REQUEST)?;
            }
        }
    }
    let mut config = state.config.lock().await;
    let idx = config.agents.iter().position(|a| a.name == req.name);
    let agent = AgentConfig {
        name: req.name,
        provider: req.provider,
        model: req.model,
        api_key: req.api_key,
        base_url: req.base_url,
    };
    if let Some(i) = idx {
        config.agents[i] = agent;
    } else {
        config.agents.push(agent);
    }
    config.save()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(AgentsResponse {
        agents: config.agents.iter().map(|a| a.sanitized()).collect(),
        active: config.active_agent.clone(),
    }))
}

/// Delete an agent.
async fn delete_agent(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<AgentsResponse>, StatusCode> {
    let mut config = state.config.lock().await;
    config.agents.retain(|a| a.name != name);
    if config.active_agent == name {
        config.active_agent = String::new();
    }
    config.save()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(AgentsResponse {
        agents: config.agents.iter().map(|a| a.sanitized()).collect(),
        active: config.active_agent.clone(),
    }))
}

/// Set active agent.
async fn set_active_agent(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<AgentsResponse>, StatusCode> {
    let mut config = state.config.lock().await;
    if name.is_empty() || config.agents.iter().any(|a| a.name == name) {
        config.active_agent = name;
        config.save()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(Json(AgentsResponse {
        agents: config.agents.iter().map(|a| a.sanitized()).collect(),
        active: config.active_agent.clone(),
    }))
}

/// Test connection to a provider.
async fn test_connection(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestConnectionRequest>,
) -> Json<TestConnectionResponse> {
    let base = req.base_url.as_deref().unwrap_or(match req.provider.as_str() {
        "ollama" => "http://localhost:11434",
        "openai" => "https://api.openai.com/v1",
        "anthropic" => "https://api.anthropic.com",
        _ => "",
    });
    if !base.is_empty() {
        if validate_no_ssrf(base).is_err() || validate_no_ssrf_dns(base).await.is_err() {
            return Json(TestConnectionResponse {
                success: false,
                message: "Provider configuration rejected".to_string(),
            });
        }
    }
    if req.provider == "ollama" {
        let url = format!("{}/api/tags", base);
        let no_redirect = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(c) => c,
            Err(_) => {
                return Json(TestConnectionResponse {
                    success: false,
                    message: "Failed to build HTTP client".to_string(),
                });
            }
        };
        match no_redirect.get(&url).send().await {
            Ok(r) if r.status().is_success() => Json(TestConnectionResponse {
                success: true,
                message: "Connected to Ollama successfully".to_string(),
            }),
            Ok(r) if r.status().is_redirection() => Json(TestConnectionResponse {
                success: false,
                message: "Redirect blocked".to_string(),
            }),
            Ok(r) => Json(TestConnectionResponse {
                success: false,
                message: format!("Ollama returned HTTP {}", r.status()),
            }),
            Err(_e) => Json(TestConnectionResponse {
                success: false,
                message: "Could not reach Ollama".to_string(),
            }),
        }
    } else {
        Json(TestConnectionResponse {
            success: false,
            message: format!("Connection testing for {} not yet implemented", req.provider),
        })
    }
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    /// Optional duress PIN — if provided during registration, the user can
    /// enter this PIN at login to silently enter duress mode (all data wiped).
    #[serde(default)]
    duress_pin: Option<String>,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
    username: String,
}

/// Create a new user account and receive a session token.
async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    if req.username.is_empty() || req.password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let dummy_salt = [0u8; 16];
    let (owner_hash, username) = {
        let mut users = state.users.lock().await;
        if users.get(&req.username).is_some() {
            // Normalize timing: perform a dummy hash so the failure path
            // takes roughly as long as a successful create_user.
            let _ = crate::users::hash_password(&req.password, &dummy_salt);
            // Also mirror the disk I/O that success does via create_user->save.
            let _ = users.save();
            return Err(StatusCode::CONFLICT);
        }
        let mut salt = [0u8; 16];
        state.rng.fill(&mut salt).expect("CSPRNG failure");
        users.create_user(&req.username, &req.password, &salt, req.duress_pin.as_deref())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let user = users.get(&req.username)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        (user.owner_hash.clone(), user.username.clone())
    };

    let mut buf = [0u8; 32];
    state.rng
        .fill(&mut buf)
        .expect("CSPRNG failure");
    let token = hex::encode(buf);
    let mut sessions = state.sessions.lock().await;
    sessions.insert(
        token.clone(),
        Session {
            owner_hash,
            username: username.clone(),
            created_at: Instant::now(),
            duress: false,
        },
    );
    Ok(Json(LoginResponse {
        token,
        username,
    }))
}

/// Authenticate and receive a session token.
async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let dummy_salt = [0u8; 16];

    // Check for duress PIN first (same timing as normal verify).
    let is_duress = {
        let users = state.users.lock().await;
        users.verify_duress(&req.username, &req.password)
    };

    if is_duress {
        let owner_hash = {
            let users = state.users.lock().await;
            users.get(&req.username)
                .map(|u| u.owner_hash.clone())
                .unwrap_or_default()
        };
        if owner_hash.is_empty() {
            return Err(StatusCode::UNAUTHORIZED);
        }

        // Wipe all data for this user.
        {
            let sm = state.structured_memory.lock().await;
            let memories = sm.list_all_by_owner(&owner_hash);
            for m in memories {
                let _ = sm.delete_by_owner(&m.key, &owner_hash);
            }
        }
        {
            let mut sessions = state.chat_sessions.lock().await;
            sessions.retain(|s| s.owner_hash != owner_hash);
        }
        {
            let mut sessions = state.sessions.lock().await;
            sessions.retain(|_, s| s.owner_hash != owner_hash);
        }

        tracing::warn!(target: "security", "Duress PIN used for user {}", req.username);

        let mut buf = [0u8; 32];
        state.rng.fill(&mut buf).expect("CSPRNG failure");
        let token = hex::encode(buf);
        let mut sessions = state.sessions.lock().await;
        sessions.insert(
            token.clone(),
            Session {
                owner_hash: owner_hash.clone(),
                username: req.username.clone(),
                created_at: Instant::now(),
                duress: true,
            },
        );
        return Ok(Json(LoginResponse {
            token,
            username: req.username.clone(),
        }));
    }

    let user = {
        let users = state.users.lock().await;
        users.verify(&req.username, &req.password).cloned()
    };
    match user {
        Some(u) => {
            let mut buf = [0u8; 32];
            state.rng
                .fill(&mut buf)
                .expect("CSPRNG failure");
            let token = hex::encode(buf);
            let mut sessions = state.sessions.lock().await;
            sessions.insert(
                token.clone(),
                Session {
                    owner_hash: u.owner_hash.clone(),
                    username: u.username.clone(),
                    created_at: Instant::now(),
                    duress: false,
                },
            );
            Ok(Json(LoginResponse {
                token,
                username: u.username.clone(),
            }))
        }
        None => {
            // Normalize timing: perform a dummy hash so failure path
            // takes roughly as long as a successful verify.
            let _ = crate::users::hash_password(&req.password, &dummy_salt);
            // Mirror the sessions-lock I/O that the success path performs.
            let _sessions = state.sessions.lock().await;
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Extract plain text from a DOCX byte slice.
fn extract_text_from_docx(data: &[u8]) -> Result<String, String> {
    use std::io::Cursor;
    let docx_file = docx::DocxFile::from_reader(Cursor::new(data)).map_err(|e| format!("docx read: {:?}", e))?;
    let docx = docx_file.parse().map_err(|e| format!("docx parse: {:?}", e))?;
    let mut text = String::new();
    for body_content in &docx.document.body.content {
        if let docx::document::BodyContent::Paragraph(paragraph) = body_content {
            for para_content in &paragraph.content {
                let run = match para_content {
                    docx::document::ParagraphContent::Run(r) => Some(r),
                    docx::document::ParagraphContent::Link(l) => Some(&l.content),
                    _ => None,
                };
                if let Some(r) = run {
                    for run_content in &r.content {
                        if let docx::document::RunContent::Text(t) = run_content {
                            text.push_str(&t.text);
                        }
                    }
                }
            }
            text.push('\n');
        }
    }
    Ok(text)
}

/// Validate file magic bytes against the claimed extension.
fn validate_magic_bytes(data: &[u8], filename: &str) -> bool {
    let lower = filename.to_lowercase();
    if lower.ends_with(".pdf") {
        data.starts_with(b"%PDF")
    } else if lower.ends_with(".docx") {
        // DOCX is a ZIP archive; check PK header.
        data.len() >= 2 && &data[..2] == b"PK"
    } else {
        // Text files — no magic bytes to check.
        true
    }
}

/// Upload a file and store its content as a memory entry.
async fn upload_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    if owner.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut filename = String::new();
    let mut content = String::new();

    const MAX_UPLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MB
    while let Some(field) = multipart.next_field().await.map_err(|_| StatusCode::BAD_REQUEST)? {
        if field.name() == Some("file") {
            filename = field.file_name().unwrap_or("upload.txt").to_string();
            let data = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;
            if data.len() > MAX_UPLOAD_SIZE {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            if !validate_magic_bytes(&data, &filename) {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            let lower = filename.to_lowercase();
            if lower.ends_with(".pdf") {
                let data = data.to_vec();
                content = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    tokio::task::spawn_blocking(move || pdf_extract::extract_text_from_mem(&data)),
                )
                .await
                .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
                .map_err(|e| {
                    tracing::warn!("PDF extraction panicked: {:?}", e);
                    StatusCode::BAD_REQUEST
                })?
                .map_err(|e| {
                    tracing::warn!("PDF extraction error: {:?}", e);
                    StatusCode::BAD_REQUEST
                })?;
            } else if lower.ends_with(".docx") {
                let data = data.to_vec();
                content = tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    tokio::task::spawn_blocking(move || extract_text_from_docx(&data)),
                )
                .await
                .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
                .map_err(|e| {
                    tracing::warn!("DOCX extraction panicked: {:?}", e);
                    StatusCode::BAD_REQUEST
                })?
                .map_err(|e| {
                    tracing::warn!("DOCX extraction error: {}", e);
                    StatusCode::BAD_REQUEST
                })?;
            } else {
                // Plain text files must be valid UTF-8.
                if std::str::from_utf8(&data).is_err() {
                    return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
                }
                content = String::from_utf8_lossy(&data).to_string();
            }
        }
    }

    if content.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Sanitize filename before using as a memory key.
    let safe_filename: String = filename.chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .take(255)
        .collect();
    if safe_filename.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let sm = state.structured_memory.lock().await;
    let mut map = serde_json::Map::new();
    map.insert("filename".to_string(), serde_json::Value::String(safe_filename.clone()));
    map.insert("text".to_string(), serde_json::Value::String(content));
    let value = MemoryValue::JsonObject(map);
    if let Err(e) = sm.store_fact_by_owner(&format!("upload:{}", safe_filename), &value, &owner) {
        tracing::warn!("Failed to store upload: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(serde_json::json!({ "success": true, "filename": safe_filename })))
}

/// Get CSRF token for web form protection.
async fn get_csrf(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    if owner.is_empty() {
        return Json(serde_json::json!({ "error": "Not authenticated" }));
    }
    let mut buf = [0u8; 32];
    state.rng.fill(&mut buf).expect("CSPRNG failure");
    let token = hex::encode(buf);
    let mut store = state.csrf_tokens.lock().await;
    store.insert(owner, token.clone());
    Json(serde_json::json!({ "csrf_token": token }))
}

/// Get settings.
async fn get_settings(State(state): State<Arc<AppState>>) -> Json<SettingsResponse> {
    let config = state.config.lock().await;
    Json(SettingsResponse {
        model: config.ollama_model.clone(),
        temperature: config.temperature,
        max_tokens: config.max_tokens,
        sandbox_memory_limit_mb: config.sandbox_memory_limit_mb,
        dual_verification: config.dual_verification,
        auto_approve_low_risk: config.auto_approve_low_risk,
        show_reasoning: config.show_reasoning,
    })
}

/// Save settings.
async fn save_settings(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SaveSettingsRequest>,
) -> Result<Json<SettingsResponse>, StatusCode> {
    let mut config = state.config.lock().await;
    config.ollama_model = req.model;
    config.temperature = req.temperature.clamp(0.0, 1.0);
    config.max_tokens = req.max_tokens.clamp(1, 8192);
    config.sandbox_memory_limit_mb = req.sandbox_memory_limit_mb.clamp(128, 8192);
    config.dual_verification = req.dual_verification;
    config.auto_approve_low_risk = req.auto_approve_low_risk;
    config.show_reasoning = req.show_reasoning;
    config.save()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(SettingsResponse {
        model: config.ollama_model.clone(),
        temperature: config.temperature,
        max_tokens: config.max_tokens,
        sandbox_memory_limit_mb: config.sandbox_memory_limit_mb,
        dual_verification: config.dual_verification,
        auto_approve_low_risk: config.auto_approve_low_risk,
        show_reasoning: config.show_reasoning,
    }))
}

/// Logout — invalidate server-side session state and revoke the token.
async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> StatusCode {
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    if !owner.is_empty() {
        let mut chat = state.chat_sessions.lock().await;
        chat.retain(|s| !muccheai_crypto::constant_time::eq(s.owner_hash.as_bytes(), owner.as_bytes()));
        drop(chat);
        let mut tokens = state.csrf_tokens.lock().await;
        tokens.remove(&owner);
    }
    // Always revoke the bearer token itself, even if session already expired.
    if let Some(token) = extract_bearer_token(&headers) {
        let mut sessions = state.sessions.lock().await;
        sessions.remove(&token);
        drop(sessions);
        let mut revoked = state.revoked_tokens.lock().await;
        revoked.insert(token);
        save_revoked_tokens(&revoked);
    }
    StatusCode::NO_CONTENT
}

/// Get current application version.
async fn get_version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Get current model.
async fn get_model(State(state): State<Arc<AppState>>) -> Json<ModelResponse> {
    let config = state.config.lock().await;
    Json(ModelResponse {
        model: config.ollama_model.clone(),
    })
}

/// Set current model.
async fn set_model(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetModelRequest>,
) -> Result<Json<ModelResponse>, StatusCode> {
    let mut config = state.config.lock().await;
    config.ollama_model = req.model;
    config.save()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ModelResponse {
        model: config.ollama_model.clone(),
    }))
}

/// List chat sessions (filtered by owner).
async fn list_chat_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Json<ChatSessionsResponse> {
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let sessions = state.chat_sessions.lock().await;
    let filtered: Vec<ChatSessionSummary> = sessions
        .iter()
        .filter(|s| muccheai_crypto::constant_time::eq(s.owner_hash.as_bytes(), owner.as_bytes()))
        .map(|s| ChatSessionSummary {
            id: s.id.clone(),
            title: s.title.clone(),
            created_at: s.created_at,
        })
        .collect();
    Json(ChatSessionsResponse { sessions: filtered })
}

async fn get_chat_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ChatSession>, StatusCode> {
    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let sessions = state.chat_sessions.lock().await;
    sessions
        .iter()
        .find(|s| {
            s.id == id
                && muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
        })
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn export_chat_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<axum::response::Response, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let sessions = state.chat_sessions.lock().await;
    let session = sessions
        .iter()
        .find(|s| {
            s.id == id
                && muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
        })
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut markdown = String::new();
    markdown.push_str(&format!("# {}\n\n", session.title));
    for msg in &session.messages {
        let role = match msg.role.as_str() {
            "user" => "## User",
            "assistant" => "## Assistant",
            _ => &format!("## {}", msg.role),
        };
        markdown.push_str(&format!("{}\n\n{}\n\n", role, msg.content));
    }
    drop(sessions);

    let response = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/markdown; charset=utf-8")
        .header("Content-Disposition", format!("attachment; filename=\"{}-chat.md\"", id.replace('"', "_").replace('\n', "_").replace('\r', "_")))
        .body(axum::body::Body::from(markdown))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(response)
}

async fn delete_chat_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> StatusCode {
    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let mut sessions = state.chat_sessions.lock().await;
    let before = sessions.len();
    sessions.retain(|s| {
        s.id != id
            || !muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
    });
    if sessions.len() < before {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

// ---------------------------------------------------------------------------
// Feature: Auto session title, branching, sharing
// ---------------------------------------------------------------------------

async fn update_session_title(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateTitleRequest>,
) -> StatusCode {
    if is_duress_session(&state, &headers).await {
        return StatusCode::FORBIDDEN;
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let mut sessions = state.chat_sessions.lock().await;
    if let Some(s) = sessions.iter_mut().find(|s| {
        s.id == id
            && muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
            && muccheai_crypto::constant_time::eq(s.owner_hash.as_bytes(), owner.as_bytes())
    }) {
        s.title = req.title.chars().take(100).collect();
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn branch_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<BranchRequest>,
) -> Result<Json<BranchResponse>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    const MAX_SESSIONS: usize = 100;
    let mut sessions = state.chat_sessions.lock().await;
    let parent = sessions.iter().find(|s| {
        s.id == id
            && muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
            && muccheai_crypto::constant_time::eq(s.owner_hash.as_bytes(), owner.as_bytes())
    }).cloned();

    let parent = parent.ok_or(StatusCode::NOT_FOUND)?;
    if req.message_index >= parent.messages.len() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut buf = [0u8; 16];
    state.rng.fill(&mut buf).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let new_id = format!("session-{}", hex::encode(buf));
    let mut sec = [0u8; 16];
    state.rng.fill(&mut sec).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let new_secret = hex::encode(sec);

    let branched_messages: Vec<ChatMessage> = parent.messages[..=req.message_index].to_vec();
    let timestamp = Timestamp::now().0;

    while sessions.len() >= MAX_SESSIONS {
        sessions.remove(0);
    }
    sessions.push(ChatSession {
        id: new_id.clone(),
        title: format!("Branch: {}", parent.title),
        created_at: timestamp,
        owner_hash: owner,
        session_secret: new_secret.clone(),
        parent_id: Some(parent.id.clone()),
        branch_point: Some(req.message_index),
        messages: branched_messages,
    });

    Ok(Json(BranchResponse {
        session_id: new_id,
        session_secret: new_secret,
    }))
}

async fn share_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ShareResponse>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let sessions = state.chat_sessions.lock().await;
    let found = sessions.iter().any(|s| {
        s.id == id
            && muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
            && muccheai_crypto::constant_time::eq(s.owner_hash.as_bytes(), owner.as_bytes())
    });
    drop(sessions);
    if !found {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut buf = [0u8; 32];
    state.rng.fill(&mut buf).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token = hex::encode(buf);
    let mut shared = state.shared_sessions.lock().await;
    // Prune expired entries on write
    let now = Instant::now();
    shared.retain(|_, (_, created)| now.saturating_duration_since(*created) < Duration::from_secs(24 * 60 * 60));
    // Cap per-session shares
    const MAX_SHARES_PER_SESSION: usize = 10;
    let existing_for_session = shared.iter().filter(|(_, (sid, _))| sid == &id).count();
    if existing_for_session >= MAX_SHARES_PER_SESSION {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    shared.insert(token.clone(), (id, Instant::now()));
    Ok(Json(ShareResponse { share_token: token }))
}

async fn get_shared_session(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Result<Json<ChatSession>, StatusCode> {
    let mut shared = state.shared_sessions.lock().await;
    // Prune expired shares (24h TTL)
    let now = Instant::now();
    shared.retain(|_, (_, created)| now.saturating_duration_since(*created) < Duration::from_secs(24 * 60 * 60));
    
    let session_id = shared.get(&token).map(|(id, _)| id.clone());
    drop(shared);

    let session_id = session_id.ok_or(StatusCode::NOT_FOUND)?;
    let sessions = state.chat_sessions.lock().await;
    sessions
        .iter()
        .find(|s| s.id == session_id)
        .cloned()
        .map(|mut s| {
            // Sanitize sensitive fields for public sharing
            s.owner_hash = String::new();
            s.session_secret = String::new();
            Json(s)
        })
        .ok_or(StatusCode::NOT_FOUND)
}

// ---------------------------------------------------------------------------
// Feature: Memory backup / restore
// ---------------------------------------------------------------------------

async fn backup_memories(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<axum::response::Response, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let sm = state.structured_memory.lock().await;
    let memories = sm.list_all_by_owner(&owner);
    let entries: Vec<MemoryApiEntry> = memories
        .into_iter()
        .map(|e| MemoryApiEntry {
            key: e.key,
            value: memory_value_to_json(e.value),
            memory_type: e.memory_type,
            created_at: e.created_at.0,
        })
        .collect();
    drop(sm);

    let body = serde_json::to_string_pretty(&entries).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let response = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Content-Disposition", "attachment; filename=\"muccheai-memories.json\"")
        .body(axum::body::Body::from(body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(response)
}

async fn restore_memories(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RestoreRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    const MAX_RESTORE_ENTRIES: usize = 1000;
    if req.entries.len() > MAX_RESTORE_ENTRIES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let sm = state.structured_memory.lock().await;
    let mut restored = 0u32;
    for entry in req.entries {
        if entry.memory_type == MemoryType::TaskHistory {
            continue; // TaskHistory cannot be restored directly
        }
        let key: String = entry.key.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
        if key.is_empty() || key.len() > 128 {
            continue;
        }
        let value = json_value_to_memory_value(entry.value);
        let mem_entry = MemoryEntry {
            memory_type: entry.memory_type,
            key,
            value,
            created_at: Timestamp(entry.created_at),
            user_signature: vec![],
            content_hash: vec![],
            owner_hash: owner.clone(),
        };
        if sm.store(&mem_entry).is_ok() {
            restored += 1;
        }
    }
    Ok(Json(serde_json::json!({ "restored": restored })))
}

// ---------------------------------------------------------------------------
// Feature: Global fuzzy search
// ---------------------------------------------------------------------------

async fn global_search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<MemoryQuery>,
) -> Result<Json<SearchResponse>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Ok(Json(SearchResponse { results: vec![] }));
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let q = query.q.unwrap_or_default().to_lowercase();
    if q.chars().count() < 2 {
        return Ok(Json(SearchResponse { results: vec![] }));
    }

    let mut results = Vec::new();

    // Search memories
    {
        let sm = state.structured_memory.lock().await;
        for entry in sm.list_all_by_owner(&owner) {
            let key_match = entry.key.to_lowercase().contains(&q);
            let val_str = serde_json::to_string(&entry.value).unwrap_or_default();
            let val_match = val_str.to_lowercase().contains(&q);
            if key_match || val_match {
                results.push(SearchResult {
                    r#type: "memory".to_string(),
                    id: entry.key.clone(),
                    title: format!("Memory: {}", entry.key),
                    content: val_str.chars().take(200).collect(),
                    created_at: entry.created_at.0,
                });
            }
        }
    }

    // Search chat sessions
    {
        let sessions = state.chat_sessions.lock().await;
        for session in sessions.iter().filter(|s| muccheai_crypto::constant_time::eq(s.owner_hash.as_bytes(), owner.as_bytes())) {
            let title_match = session.title.to_lowercase().contains(&q);
            let mut content_match = false;
            let mut matched_content = String::new();
            for msg in &session.messages {
                if msg.content.to_lowercase().contains(&q) {
                    content_match = true;
                    matched_content = msg.content.chars().take(200).collect();
                    break;
                }
            }
            if title_match || content_match {
                results.push(SearchResult {
                    r#type: "session".to_string(),
                    id: session.id.clone(),
                    title: session.title.clone(),
                    content: matched_content,
                    created_at: session.created_at,
                });
            }
        }
    }

    // Sort by relevance: exact title matches first, then by recency
    let mut scored: Vec<(SearchResult, bool)> = results
        .into_iter()
        .map(|r| {
            let exact = r.title.to_lowercase().contains(&q);
            (r, exact)
        })
        .collect();
    scored.sort_by(|a, b| {
        match (a.1, b.1) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => b.0.created_at.cmp(&a.0.created_at),
        }
    });
    let mut results: Vec<SearchResult> = scored.into_iter().map(|(r, _)| r).collect();

    // Limit results
    results.truncate(50);
    Ok(Json(SearchResponse { results }))
}

// ---------------------------------------------------------------------------
// Feature: Streaming chat (SSE)
// ---------------------------------------------------------------------------

async fn chat_stream(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ChatRequest>,
) -> Sse<ReceiverStream<Result<Event, Infallible>>> {
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(100);
    let state = state.clone();
    let headers = headers.clone();

    tokio::spawn(async move {
        let response = process_chat(&state, &headers, &req).await;
        
        // Send session info first (do NOT leak session_secret over SSE)
        let meta = serde_json::json!({
            "session_id": response.session_id,
            "memories_used": response.memories_used,
        });
        if tx.send(Ok(Event::default().event("meta").data(meta.to_string()))).await.is_err() {
            return; // client disconnected
        }

        if let Some(confirm) = response.needs_confirmation {
            let confirm_json = serde_json::json!({ "confirm": confirm });
            let _ = tx.send(Ok(Event::default().event("confirm").data(confirm_json.to_string()))).await;
            let _ = tx.send(Ok(Event::default().data("[DONE]"))).await;
            return;
        }

        // Stream the response in chunks (simulating token streaming)
        let text = response.response;
        let chunk_size = 4usize;
        let mut chars = text.chars();
        let mut buffer = String::new();
        while let Some(c) = chars.next() {
            buffer.push(c);
            if buffer.len() >= chunk_size {
                if tx.send(Ok(Event::default().data(buffer.clone()))).await.is_err() {
                    return; // client disconnected
                }
                buffer.clear();
            }
        }
        if !buffer.is_empty() {
            if tx.send(Ok(Event::default().data(buffer))).await.is_err() {
                return;
            }
        }
        let _ = tx.send(Ok(Event::default().data("[DONE]"))).await;
    });

    Sse::new(ReceiverStream::new(rx))
}

// ---------------------------------------------------------------------------
// MCP Registry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpServerApiEntry {
    name: String,
    transport: String,
    command: Option<String>,
    args: Vec<String>,
    url: Option<String>,
    api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct McpServerListResponse {
    servers: Vec<McpServerApiEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct AddMcpServerRequest {
    name: String,
    transport: String,
    command: Option<String>,
    args: Vec<String>,
    url: Option<String>,
    api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct McpTestResponse {
    success: bool,
    message: String,
    tools: Vec<String>,
}

async fn list_mcp_servers(State(state): State<Arc<AppState>>) -> Json<McpServerListResponse> {
    let cfg = state.tool_config.lock().await.clone();
    let mut servers = Vec::new();
    if let Some(mcp) = cfg.mcp {
        for (name, s) in mcp.servers {
            let safe_url = s.url.map(|u| {
                if let Ok(parsed) = url::Url::parse(&u) {
                    let mut redacted = parsed.clone();
                    if !redacted.username().is_empty() {
                        let _ = redacted.set_username("");
                    }
                    if redacted.password().is_some() {
                        let _ = redacted.set_password(None);
                    }
                    redacted.to_string()
                } else {
                    u
                }
            });
            servers.push(McpServerApiEntry {
                name,
                transport: s.transport,
                command: s.command,
                args: s.args,
                url: safe_url,
                api_key: s.api_key.map(|_| "***REDACTED***".to_string()),
            });
        }
    }
    Json(McpServerListResponse { servers })
}

async fn add_mcp_server(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddMcpServerRequest>,
) -> Result<StatusCode, StatusCode> {
    if req.name.is_empty() || req.transport.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if req.transport == "stdio" {
        if let Some(ref cmd) = req.command {
            let cmd_path = std::path::Path::new(cmd);
            // Require absolute paths only — no PATH resolution, no interpreters.
            if !cmd.starts_with('/') {
                return Err(StatusCode::BAD_REQUEST);
            }
            if cmd_path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                return Err(StatusCode::BAD_REQUEST);
            }
            let invalid_chars = [';', '|', '&', '$', '`', '<', '>', '(', ')', '{', '}', '*', '?', '[', ']', '\\', '\'', '"'];
            for arg in &req.args {
                if invalid_chars.iter().any(|c| arg.contains(*c)) {
                    return Err(StatusCode::BAD_REQUEST);
                }
                if arg.starts_with("-") {
                    let lower = arg.to_lowercase();
                    let blocked = ["-e", "--eval", "-p", "--print", "-r", "--require", "--import"];
                    if blocked.iter().any(|b| lower.starts_with(b)) {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                }
                if arg.contains("child_process") || arg.contains("exec(") || arg.contains("spawn(") || arg.contains("eval(") {
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        } else {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    if req.transport == "http" || req.transport == "sse" {
        if let Some(ref url) = req.url {
            if validate_no_ssrf_external(url).is_err() {
                return Err(StatusCode::BAD_REQUEST);
            }
            if validate_no_ssrf_dns(url).await.is_err() {
                return Err(StatusCode::BAD_REQUEST);
            }
        } else {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Encrypt MCP API key before it ever touches disk.
    let encrypted_key = if let Some(ref k) = req.api_key {
        let key = MuccheConfig::load_or_create_machine_key();
        match crate::config::encrypt_aes_256_gcm(k.as_bytes(), &key) {
            Ok(ct) => Some(format!("enc:{}", hex::encode(ct))),
            Err(e) => {
                tracing::error!("Failed to encrypt MCP API key: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    } else {
        None
    };

    let mut cfg = state.tool_config.lock().await;
    if cfg.mcp.is_none() {
        cfg.mcp = Some(muccheai_tool_gateway::config::McpConfig::default());
    }
    let mcp = cfg.mcp.as_mut().expect("mcp was just initialized above");
    mcp.servers.insert(
        req.name,
        McpServerConfig {
            transport: req.transport,
            command: req.command,
            args: req.args,
            url: req.url,
            api_key: encrypted_key,
        },
    );
    cfg.save().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    drop(cfg);

    // Refresh MCP tools cache in the background
    let state_clone = state.clone();
    tokio::spawn(async move {
        let refreshed = init_mcp_tools().await;
        let mut cache = state_clone.mcp_tools_cache.lock().await;
        let cfg = state_clone.tool_config.lock().await;
        let valid_servers: std::collections::HashSet<String> = cfg
            .mcp
            .as_ref()
            .map(|m| m.servers.keys().cloned().collect())
            .unwrap_or_default();
        drop(cfg);
        *cache = refreshed.into_iter()
            .filter(|t| valid_servers.contains(&t.server_name))
            .collect();
        tracing::info!("MCP tools cache refreshed after add: {} tools", cache.len());
    });

    Ok(StatusCode::OK)
}

async fn delete_mcp_server(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let mut cfg = state.tool_config.lock().await;
    let removed = cfg
        .mcp
        .as_mut()
        .map(|m| m.servers.remove(&name).is_some())
        .unwrap_or(false);
    if removed {
        let mut cfg_save = cfg.clone();
        crate::config::encrypt_mcp_keys(&mut cfg_save);
        cfg_save.save().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        drop(cfg);

        // Refresh MCP tools cache in the background
        let state_clone = state.clone();
        tokio::spawn(async move {
            let refreshed = init_mcp_tools().await;
            let mut cache = state_clone.mcp_tools_cache.lock().await;
            let cfg = state_clone.tool_config.lock().await;
            let valid_servers: std::collections::HashSet<String> = cfg
                .mcp
                .as_ref()
                .map(|m| m.servers.keys().cloned().collect())
                .unwrap_or_default();
            drop(cfg);
            *cache = refreshed.into_iter()
                .filter(|t| valid_servers.contains(&t.server_name))
                .collect();
            tracing::info!("MCP tools cache refreshed after delete: {} tools", cache.len());
        });

        Ok(StatusCode::NO_CONTENT)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

async fn test_mcp_server(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Json<McpTestResponse> {
    let cfg = state.tool_config.lock().await;
    let server = match cfg
        .mcp
        .as_ref()
        .and_then(|m| m.servers.get(&name).cloned())
    {
        Some(s) => s,
        None => {
            return Json(McpTestResponse {
                success: false,
                message: "Server not found".to_string(),
                tools: vec![],
            });
        }
    };

    if server.transport == "http" || server.transport == "sse" {
        if let Some(ref url) = server.url {
            if validate_no_ssrf_external(url).is_err() {
                return Json(McpTestResponse {
                    success: false,
                    message: "MCP server URL failed SSRF validation".to_string(),
                    tools: vec![],
                });
            }
            if validate_no_ssrf_dns(url).await.is_err() {
                return Json(McpTestResponse {
                    success: false,
                    message: "MCP server URL failed DNS SSRF validation".to_string(),
                    tools: vec![],
                });
            }
        }
    }

    use muccheai_mcp::transport::McpTransport;
    let transport = match server.transport.as_str() {
        "stdio" => {
            if let Some(cmd) = server.command {
                McpTransport::Stdio {
                    command: cmd,
                    args: server.args,
                }
            } else {
                return Json(McpTestResponse {
                    success: false,
                    message: "stdio transport requires a command".to_string(),
                    tools: vec![],
                });
            }
        }
        "http" | "sse" => {
            if let Some(url) = server.url {
                let decrypted_key = server.api_key.as_ref().and_then(|k| crate::config::decrypt_mcp_api_key(k));
                McpTransport::Http {
                    url,
                    api_key: decrypted_key,
                }
            } else {
                return Json(McpTestResponse {
                    success: false,
                    message: "HTTP transport requires a URL".to_string(),
                    tools: vec![],
                });
            }
        }
        other => {
            return Json(McpTestResponse {
                success: false,
                message: format!("Unknown transport: {}", other),
                tools: vec![],
            });
        }
    };

    let mut client = muccheai_mcp::McpClient::new(transport);
    let result = match client.connect().await {
        Ok(_) => match client.discover_tools().await {
            Ok(tools) => {
                let tool_names: Vec<String> = tools.iter().map(|t| t.name.clone()).collect();
                Json(McpTestResponse {
                    success: true,
                    message: format!("Connected. Discovered {} tools.", tool_names.len()),
                    tools: tool_names,
                })
            }
            Err(_e) => Json(McpTestResponse {
                success: true,
                message: "Connected but failed to discover tools".to_string(),
                tools: vec![],
            }),
        },
        Err(_e) => Json(McpTestResponse {
            success: false,
            message: "Connection failed".to_string(),
            tools: vec![],
        }),
    };
    client.disconnect().await;
    result
}

/// Start the web server.
pub async fn serve(addr: &str, state: Arc<AppState>) {
    let addr = match addr.parse::<SocketAddr>() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("❌ Invalid bind address '{}': {}", addr, e);
            std::process::exit(1);
        }
    };

    let cert_path = std::env::var("MUCCHEAI_TLS_CERT").ok();
    let key_path = std::env::var("MUCCHEAI_TLS_KEY").ok();

    if let (Some(cert), Some(key)) = (&cert_path, &key_path) {
        match axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await {
            Ok(config) => {
                println!("🔒 MuccheAI Control Panel running at https://{}", addr);
                if let Err(e) = axum_server::tls_rustls::bind_rustls(addr, config)
                    .serve(router(state).into_make_service_with_connect_info::<SocketAddr>())
                    .await
                {
                    eprintln!("❌ TLS server failed to start: {}", e);
                    std::process::exit(1);
                }
                return;
            }
            Err(e) => {
                eprintln!("❌ Failed to load TLS certificates ({}). Exiting.", e);
                std::process::exit(1);
            }
        }
    }

    println!("🌐 MuccheAI Control Panel running at http://{}", addr);
    println!("⚠️  SECURITY WARNING: Running without TLS. Set MUCCHEAI_TLS_CERT and MUCCHEAI_TLS_KEY for HTTPS.");
    if let Err(e) = axum_server::bind(addr)
        .serve(router(state).into_make_service_with_connect_info::<SocketAddr>())
        .await
    {
        eprintln!("❌ HTTP server failed to start: {}", e);
        std::process::exit(1);
    }
}

/// ─── New feature handlers ────────────────────────────────────────────

fn make_random_id(state: &AppState, bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    state.rng.fill(&mut buf).expect("CSPRNG failure");
    hex::encode(buf)
}

async fn post_collaborative_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ChatRequest>,
) -> Json<ChatResponse> {
    if is_duress_session(&state, &headers).await {
        return Json(ChatResponse {
            response: "Duress mode active.".into(),
            session_id: id,
            session_secret: String::new(),
            needs_confirmation: None,
            memories_used: None,
        });
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let sessions = state.chat_sessions.lock().await;
    let found = sessions.iter().any(|s| {
        s.id == id && muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
    });
    if !found {
        return Json(ChatResponse {
            response: "Session not found or access denied.".into(),
            session_id: id,
            session_secret: String::new(),
            needs_confirmation: None,
            memories_used: None,
        });
    }
    drop(sessions);
    let mut req = req;
    req.session_id = Some(id);
    Json(process_chat(&state, &headers, &req).await)
}

async fn list_presets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<AgentPreset>>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let cfg = state.config.lock().await;
    let active_agent = cfg.agents.iter().find(|a| a.name == cfg.active_agent);
    let presets = vec![
        AgentPreset {
            name: "default".into(),
            provider: active_agent.map(|a| a.provider.clone()).unwrap_or_else(|| cfg.ollama_host.clone()),
            model: active_agent.map(|a| a.model.clone()).unwrap_or_else(|| cfg.ollama_model.clone()),
            description: "The default active agent".into(),
            system_prompt: cfg.personas.iter().find(|p| p.name == cfg.current_persona).map(|p| p.system_prompt.clone()).unwrap_or_default(),
        },
        AgentPreset {
            name: "creative".into(),
            provider: "openai".into(),
            model: "gpt-4o".into(),
            description: "Creative writing & brainstorming".into(),
            system_prompt: "You are a creative assistant specialized in storytelling, brainstorming, and imaginative problem solving.".into(),
        },
        AgentPreset {
            name: "code-reviewer".into(),
            provider: "openai".into(),
            model: "gpt-4o-mini".into(),
            description: "Code review & refactoring".into(),
            system_prompt: "You are a meticulous code reviewer. Focus on bugs, security, performance, and maintainability.".into(),
        },
    ];
    Ok(Json(presets))
}

#[derive(Debug, Deserialize)]
struct InstallPresetRequest {
    name: String,
}

async fn install_preset(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<InstallPresetRequest>,
) -> Result<StatusCode, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let _owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let presets = list_presets(State(state.clone()), headers).await?.0;
    if presets.iter().any(|p| p.name == payload.name) {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn get_knowledge_graph(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<GraphResponse>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    let sessions = state.chat_sessions.lock().await;
    for sess in sessions.iter().filter(|s| s.owner_hash == owner) {
        nodes.push(GraphNode {
            id: sess.id.clone(),
            label: sess.title.clone(),
            group: "session".into(),
        });
    }

    let sm = state.structured_memory.lock().await;
    let entries = sm.list_all_by_owner(&owner);
    for entry in entries.into_iter().take(50) {
        let node_id = format!("mem-{}", entry.key);
        nodes.push(GraphNode {
            id: node_id.clone(),
            label: format!("{:?}: {}", entry.memory_type, entry.key.chars().take(30).collect::<String>()),
            group: format!("{:?}", entry.memory_type),
        });
    }

    Ok(Json(GraphResponse { nodes, edges }))
}

async fn list_custom_tools(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::config::CustomToolConfig>>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let tools = state.custom_tools.lock().await.clone();
    Ok(Json(tools))
}

#[derive(Debug, Deserialize)]
struct CreateToolRequest {
    name: String,
    method: String,
    url_template: String,
    body_template: Option<String>,
}

async fn create_custom_tool(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateToolRequest>,
) -> Result<StatusCode, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let tool = crate::config::CustomToolConfig {
        name: payload.name,
        method: payload.method,
        url_template: payload.url_template,
        body_template: payload.body_template,
    };
    let mut tools = state.custom_tools.lock().await;
    if tools.len() >= 20 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    tools.push(tool);
    Ok(StatusCode::CREATED)
}

async fn delete_custom_tool(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let mut tools = state.custom_tools.lock().await;
    tools.retain(|t| t.name != name);
    Ok(StatusCode::OK)
}

async fn get_analytics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AnalyticsResponse>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let sessions = state.chat_sessions.lock().await;
    let total_sessions = sessions.iter().filter(|s| s.owner_hash == owner).count();
    let total_messages: usize = sessions
        .iter()
        .filter(|s| s.owner_hash == owner)
        .map(|s| s.messages.len())
        .sum();
    let queue_pending = {
        let sm = state.structured_memory.lock().await;
        sm.list_all_proposals().into_iter().filter(|p| {
            p.status == crate::structured_memory::ProposalStatus::Pending
                && p.entry.owner_hash == owner
        }).count()
    };
    let total_memories = {
        let sm = state.structured_memory.lock().await;
        sm.list_all_by_owner(&owner).len()
    };
    let cfg = state.config.lock().await;
    Ok(Json(AnalyticsResponse {
        total_messages,
        total_sessions,
        total_memories,
        queue_pending,
        top_model: cfg.ollama_model.clone(),
        active_plugins: 0,
    }))
}

async fn list_scheduled_tasks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<ScheduledTask>>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let tasks = state.scheduled_tasks.lock().await.clone();
    Ok(Json(tasks))
}

#[derive(Debug, Deserialize)]
struct CreateTaskRequest {
    cron: String,
    prompt: String,
}

async fn create_scheduled_task(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateTaskRequest>,
) -> Result<Json<ScheduledTask>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    if payload.prompt.len() > 2000 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let task = ScheduledTask {
        id: make_random_id(&state, 12),
        cron: payload.cron,
        prompt: payload.prompt,
        enabled: true,
        created_at: Timestamp::now().0,
    };
    let mut tasks = state.scheduled_tasks.lock().await;
    if tasks.len() >= 10 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    tasks.push(task.clone());
    Ok(Json(task))
}

async fn delete_scheduled_task(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let mut tasks = state.scheduled_tasks.lock().await;
    tasks.retain(|t| t.id != id);
    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
struct ChatWithImageRequest {
    message: String,
    #[serde(default)]
    image_b64: String,
    #[serde(default)]
    session_id: Option<String>,
}

async fn chat_with_image(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChatWithImageRequest>,
) -> Result<Json<ChatResponse>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let owner = get_session_owner(&state, &headers).await.unwrap_or_default();
    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let session_id = match payload.session_id.as_deref() {
        Some(sid) => {
            let sessions = state.chat_sessions.lock().await;
            let found = sessions.iter().any(|s| {
                s.id == sid && muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
            });
            if !found {
                return Err(StatusCode::FORBIDDEN);
            }
            sid.to_string()
        }
        None => {
            let mut sessions = state.chat_sessions.lock().await;
            if sessions.len() >= 100 {
                sessions.remove(0);
            }
            let mut sec = [0u8; 16];
            state.rng.fill(&mut sec).expect("CSPRNG failure");
            let new_secret = hex::encode(sec);
            let id = make_random_id(&state, 16);
            let ts = Timestamp::now().0;
            sessions.push(ChatSession {
                id: id.clone(),
                messages: Vec::new(),
                owner_hash: owner.clone(),
                session_secret: new_secret.clone(),
                created_at: ts,
                title: "Image chat".into(),
                parent_id: None,
                branch_point: None,
            });
            new_secret
        }
    };

    let req = ChatRequest {
        message: format!("[Image attached]\n{}", payload.message),
        session_id: Some(session_id),
        research: false,
        research_confirmed: false,
    };
    let resp = process_chat(&state, &headers, &req).await;
    Ok(Json(resp))
}

async fn update_session_folder(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(_payload): Json<UpdateFolderRequest>,
) -> Result<StatusCode, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let sessions = state.chat_sessions.lock().await;
    let found = sessions.iter().any(|s| {
        s.id == id && muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
    });
    if !found {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(StatusCode::OK)
}

async fn update_session_tags(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(_payload): Json<UpdateTagsRequest>,
) -> Result<StatusCode, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let sessions = state.chat_sessions.lock().await;
    let found = sessions.iter().any(|s| {
        s.id == id && muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
    });
    if !found {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(StatusCode::OK)
}

async fn list_folders(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<String>>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let tools = state.custom_tools.lock().await;
    let mut folders = vec!["General".into(), "Work".into(), "Personal".into()];
    for t in tools.iter() {
        folders.push(format!("tool-{}", t.name));
    }
    folders.sort();
    folders.dedup();
    Ok(Json(folders))
}

async fn get_session_digest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DigestResponse>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let sessions = state.chat_sessions.lock().await;
    let session = match sessions.iter().find(|s| {
        s.id == id && muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
    }) {
        Some(s) => s.clone(),
        None => return Err(StatusCode::NOT_FOUND),
    };
    drop(sessions);
    let summary = session.messages
        .iter()
        .filter(|m| m.role == "user")
        .map(|m| format!("- {}", m.content.chars().take(60).collect::<String>()))
        .collect::<Vec<_>>()
        .join("\n");
    let digest = format!(
        "# Session Digest: {}\n\n{} messages total.\n\nUser questions:\n{}",
        session.title,
        session.messages.len(),
        if summary.is_empty() { "(no messages yet)" } else { &summary }
    );
    Ok(Json(DigestResponse { digest }))
}

async fn create_encrypted_share(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(_payload): Json<EncryptedShareRequest>,
) -> Result<Json<EncryptedShareResponse>, StatusCode> {
    if is_duress_session(&state, &headers).await {
        return Err(StatusCode::FORBIDDEN);
    }
    let secret = headers
        .get("x-session-secret")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let sessions = state.chat_sessions.lock().await;
    let found = sessions.iter().any(|s| {
        s.id == id && muccheai_crypto::constant_time::eq(s.session_secret.as_bytes(), secret.as_bytes())
    });
    if !found {
        return Err(StatusCode::FORBIDDEN);
    }
    drop(sessions);
    let token = make_random_id(&state, 32);
    let mut shares = state.shared_sessions.lock().await;
    shares.retain(|_, (_, created)| created.elapsed() < Duration::from_secs(7 * 86400));
    shares.insert(token.clone(), (id, Instant::now()));
    Ok(Json(EncryptedShareResponse { share_token: token }))
}

async fn get_encrypted_share(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Result<Json<EncryptedShareResponse>, StatusCode> {
    let mut shares = state.shared_sessions.lock().await;
    shares.retain(|_, (_, created)| created.elapsed() < Duration::from_secs(7 * 86400));
    match shares.get(&token) {
        Some((id, _)) => {
            let sessions = state.chat_sessions.lock().await;
            let found = sessions.iter().any(|s| s.id == *id);
            if !found {
                return Err(StatusCode::GONE);
            }
            Ok(Json(EncryptedShareResponse { share_token: token }))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// ─── Router ─────────────────────────────────────────────────────────
pub fn router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(|origin, _| {
            let origin_str = origin.to_str().unwrap_or("");
            matches!(origin_str,
                "http://localhost:3000"
                | "http://127.0.0.1:3000"
                | "https://localhost:3000"
                | "https://127.0.0.1:3000"
            )
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
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self';"
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
        .route("/chat/image", post(chat_with_image))
        .route("/sessions/:id/folder", post(update_session_folder))
        .route("/sessions/:id/tags", post(update_session_tags))
        .route("/folders", get(list_folders))
        .route("/sessions/:id/digest", get(get_session_digest))
        .route("/sessions/:id/encrypt-share", post(create_encrypted_share))
        .route("/upload", post(upload_file))
        .route("/mcp/servers", get(list_mcp_servers))
        .route("/mcp/servers", post(add_mcp_server))
        .route("/mcp/servers/:name", delete(delete_mcp_server))
        .route("/mcp/servers/:name/test", post(test_mcp_server))
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
        .layer(xcto)
        .layer(xfo)
        .layer(rp)
        .layer(cc);
    if let Some(hsts_layer) = hsts {
        router = router.layer(hsts_layer);
    }
    router
}
