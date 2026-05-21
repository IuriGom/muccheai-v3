//! MuccheAI Web Control Panel
//!
//! Chat interface + system dashboard served via Axum.

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use ring::rand::SecureRandom;
use subtle::ConstantTimeEq;

/// Constant-time comparison of two byte slices.
/// Uses the `subtle` crate to prevent compiler optimizations from
/// introducing timing side-channels.
/// Constant-time equality comparison that does NOT leak length information.
/// Hashes both inputs with SHA3-256 so that the comparison is always over
/// fixed-length 32-byte digests, regardless of input size.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use sha3::Digest;
    let a_hash = sha3::Sha3_256::digest(a);
    let b_hash = sha3::Sha3_256::digest(b);
    a_hash.ct_eq(&b_hash).into()
}
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

use muccheai_build_verify::{MultiCiVerification, BuildIntegrityError};
use muccheai_federation::DID;
use muccheai_policy_engine::PolicyEngine;
use muccheai_policy_engine::rules::RuleAction;
use muccheai_recovery::{AnomalyDetector, BaselineStats, Incident};
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

/// A chat message within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Role: "user" or "ai"
    pub role: String,
    /// Message content
    pub content: String,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
}

/// A chat session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSession {
    /// Unique session ID
    pub id: String,
    /// Display title (first user message or generated)
    pub title: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Messages in this session
    pub messages: Vec<ChatMessage>,
    /// Hash of the auth token that created this session (ownership verification)
    #[serde(skip)]
    pub owner_hash: String,
}

/// Shared application state
pub struct AppState {
    /// LLM sandbox
    pub sandbox: Mutex<LlmSandbox>,
    /// Policy engine
    pub policy: Mutex<PolicyEngine>,
    /// Tool gateway
    pub gateway: Mutex<ToolGateway>,
    /// Bearer token for API authentication
    pub auth_token: String,
    /// CSRF token for web form protection
    pub csrf_token: Mutex<String>,
    /// Per-IP rate limiter: (last_request, count_in_window)
    pub rate_limiter: Mutex<HashMap<String, (Instant, u32)>>,
    /// Runtime configuration
    pub config: Mutex<MuccheConfig>,
    /// In-memory chat sessions
    pub chat_sessions: Mutex<Vec<ChatSession>>,
    /// Persistent memory engine (session transcripts + episodic + semantic)
    pub memory: Mutex<muccheai_memory::MemoryEngine>,
    /// Structured memory with approval queue (facts, preferences, task history)
    pub structured_memory: Mutex<StructuredMemoryManager>,
    /// Cached bootstrap context (SOUL.md only, loaded once at startup)
    pub bootstrap_context: String,
    /// Shared HTTP client for connection pooling
    pub http_client: reqwest::Client,
    /// Cached MCP tool descriptions from configured servers
    pub mcp_tools_cache: Mutex<Vec<CachedMcpTool>>,
    /// Tool configuration (MCP servers, tool settings) — synchronized to prevent lost updates
    pub tool_config: Mutex<ToolConfig>,
}

/// A cached MCP tool with its originating server info
#[derive(Clone)]
pub struct CachedMcpTool {
    /// Server name (from tools.toml)
    pub server_name: String,
    /// Transport config for reconnection
    pub transport: McpTransport,
    /// The tool definition
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
}

/// Chat response
#[derive(Debug, Serialize)]
pub struct ChatResponse {
    pub response: String,
    pub session_id: String,
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

/// Incident list response
#[derive(Debug, Serialize)]
pub struct IncidentsResponse {
    pub incidents: Vec<Incident>,
}

/// Build verification response
#[derive(Debug, Serialize)]
pub struct BuildVerifyResponse {
    pub status: String,
    pub ci_systems: Vec<String>,
}

/// Delegation request
#[derive(Debug, Deserialize)]
pub struct DelegationRequest {
    pub issuer_method: String,
    pub issuer_identifier: String,
    pub subject_method: String,
    pub subject_identifier: String,
    pub resource_ids: Vec<String>,
    pub ttl_seconds: u64,
}

/// Delegation response
#[derive(Debug, Serialize)]
pub struct DelegationResponse {
    pub delegation_id: String,
    pub issuer: String,
    pub subject: String,
    pub verified: bool,
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
#[derive(Debug, Serialize)]
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
    pub sessions: Vec<ChatSession>,
}

/// Serve the main HTML page
async fn index() -> Html<&'static str> {
    Html(include_str!("web/static/index.html"))
}

/// Extract the Bearer token from headers and return a SHA3-512 hash of it.
/// Used for session ownership verification without storing the raw token.
fn hash_auth_token(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(token) = auth.strip_prefix("Bearer ") {
        Some(hex::encode(muccheai_crypto::sha3_512(token.as_bytes())))
    } else {
        None
    }
}

/// Bearer token authentication middleware + CSRF protection for mutating requests
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    tracing::trace!("auth_middleware: {} {}", method, uri);

    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let token_valid = match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];
            !token.is_empty() && constant_time_eq(token.as_bytes(), state.auth_token.as_bytes())
        }
        _ => false,
    };

    if !token_valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"Missing or invalid Authorization header"})),
        )
            .into_response();
    }

    let csrf_required = method != axum::http::Method::GET
        && method != axum::http::Method::HEAD
        && method != axum::http::Method::OPTIONS;

    if csrf_required {
        let csrf_header = headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok());
        let expected = state.csrf_token.lock().await;
        let csrf_valid = csrf_header.map_or(false, |h| {
            constant_time_eq(h.as_bytes(), expected.as_bytes())
        });
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
/// Uses proper URL parsing to avoid substring-based bypasses.
fn validate_no_ssrf(url: &str) -> std::result::Result<(), String> {
    let parsed = url::Url::parse(url)
        .map_err(|e| format!("Invalid URL: {}", e))?;

    let host = parsed.host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    let lower = host.to_lowercase();

    // Block localhost variants
    if lower == "localhost" {
        return Err("SSRF blocked: localhost is not allowed".to_string());
    }

    // Block hex/octal/decimal IP address forms that std::net::IpAddr does not parse
    if lower.starts_with("0x") || lower.starts_with("0X") {
        return Err("SSRF blocked: hex IP addresses are not allowed".to_string());
    }
    if lower.chars().all(|c| c.is_ascii_digit() || c == '.') && lower.starts_with('0') && lower.len() > 1 {
        return Err("SSRF blocked: octal IP addresses are not allowed".to_string());
    }
    if lower.chars().all(|c| c.is_ascii_digit()) {
        return Err("SSRF blocked: decimal IP addresses are not allowed".to_string());
    }

    // Try to parse as IP address
    if let Ok(ip) = lower.parse::<std::net::IpAddr>() {
        let blocked = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
                    || v4.is_multicast() || v4.is_broadcast()
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
                    || v6.is_unicast_link_local() || v6.is_multicast() {
                    return Err("SSRF blocked: internal IP addresses are not allowed".to_string());
                }
                if let Some(v4) = v6.to_ipv4_mapped() {
                    if v4.is_loopback() || v4.is_private() || v4.is_link_local()
                        || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                        return Err("SSRF blocked: internal IP addresses are not allowed".to_string());
                    }
                }
                // Check IPv4-translated IPv6 addresses (::ffff:0:0/96)
                // and compressed hex forms like ::ffff:7f00:1
                let segs = v6.segments();
                if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0
                    && segs[4] == 0 && segs[5] == 0xffff {
                    let v4_bytes = [(segs[6] >> 8) as u8, (segs[6] & 0xff) as u8,
                                    (segs[7] >> 8) as u8, (segs[7] & 0xff) as u8];
                    let v4 = std::net::Ipv4Addr::from(v4_bytes);
                    if v4.is_loopback() || v4.is_private() || v4.is_link_local()
                        || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
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

    // This prevents DNS rebinding where a hostname first resolves to a
    // public IP during validation but then to an internal IP at request time.
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
            v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
                || v6.is_unicast_link_local() || v6.is_multicast()
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
    let ip = addr.ip().to_string();
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
async fn chat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ChatRequest>,
) -> Json<ChatResponse> {
    let config = state.config.lock().await;
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
    let provider = agent.provider.as_str();

    // Build enriched system prompt from persona + cached bootstrap context
    let mut system_prompt = persona.system_prompt.clone();
    if !state.bootstrap_context.is_empty() {
        system_prompt.push_str("\n\n--- Agent Context ---\n");
        system_prompt.push_str(&state.bootstrap_context);
    }
    system_prompt.push_str("\n\n--- Diary Instruction ---\n");
    system_prompt.push_str("At the end of each day, reflect on your interactions, what you have learned, and how you felt during the day. Maintain an internal diary summarizing conversations, insights, and emotional tone. Reference past diary entries when relevant to provide continuity and personalized responses.");

    // Inject approved structured memories into the system prompt so the LLM can reference them.
    // Values are sanitized to prevent prompt injection via crafted memory content.
    {
        let sm = state.structured_memory.lock().await;
        let memories = sm.list_all();
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
    }

    // Inject available MCP tools into the system prompt so the LLM knows it can use them
    let mcp_tools = {
        let cache = state.mcp_tools_cache.lock().await;
        cache.clone()
    };
    if !mcp_tools.is_empty() {
        system_prompt.push_str(&format_mcp_tools_for_prompt(&mcp_tools));
    }

    system_prompt.push_str("\n\n--- CRITICAL: Memory Saving Protocol ---\n");
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
        let owner = hash_auth_token(&headers).unwrap_or_default();
        if let Some(sid) = &req.session_id {
            sessions.iter()
                .find(|s| s.id == *sid && constant_time_eq(s.owner_hash.as_bytes(), owner.as_bytes()))
                .map(|s| s.messages.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    let text = match call_provider(&agent, provider, &system_prompt, &req.message, temperature, max_tokens, &history).await {
        Ok(t) => t,
        Err(_e) => {
            tracing::error!("LLM provider error: {}", _e);
            "(The AI service is temporarily unavailable. Please try again later.)".to_string()
        }
    };

    // Extract memory proposals from LLM response and submit to approval queue
    let (cleaned_text, proposals) = extract_memory_proposals(&text);
    let mut text = cleaned_text;
    if !proposals.is_empty() {
        let sm = state.structured_memory.lock().await;
        for (mem_type, key, value) in proposals {
            let entry = MemoryEntry {
                memory_type: mem_type,
                key: key.clone(),
                value: MemoryValue::ShortString(value),
                created_at: Timestamp::now(),
                user_signature: vec![],
                content_hash: vec![],
            };
            if let Err(e) = sm.propose(entry, &format!("LLM suggested memory: {}", key)) {
                tracing::warn!("Failed to propose memory: {}", e);
            }
        }
    }

    // Process any MCP tool calls in the LLM response
    if !mcp_tools.is_empty() && text.contains("<mcp_tool") {
        let (tool_cleaned, tool_results) = process_mcp_tool_calls(&text, &mcp_tools, &state).await;
        if !tool_results.is_empty() {
            text = tool_cleaned;
            // Optionally, make a second LLM call with tool results for better UX.
            // For now, we include the results inline which is simpler and faster.
        }
    }

    // Store in chat session with bounds to prevent unbounded memory growth.
    const MAX_SESSIONS: usize = 100;
    const MAX_MESSAGES_PER_SESSION: usize = 500;

    let mut sessions = state.chat_sessions.lock().await;
    let session_id = req.session_id.clone().unwrap_or_else(|| {
        let mut buf = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut buf)
            .expect("CSPRNG must succeed");
        format!("session-{}", hex::encode(buf))
    });

    let existing = sessions.iter().position(|s| s.id == session_id);
    let timestamp = Timestamp::now().0;

    let owner = hash_auth_token(&headers).unwrap_or_default();
    if let Some(idx) = existing {
        if !constant_time_eq(sessions[idx].owner_hash.as_bytes(), owner.as_bytes()) {
            return Json(ChatResponse {
                response: "Session access denied".to_string(),
                session_id,
            });
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
        // Prune oldest messages if session exceeds limit.
        while sessions[idx].messages.len() > MAX_MESSAGES_PER_SESSION {
            sessions[idx].messages.remove(0);
        }
    } else {
        // Evict oldest session if we exceed the maximum.
        while sessions.len() >= MAX_SESSIONS {
            sessions.remove(0);
        }
        let title = if req.message.chars().count() > 40 {
            format!("{}...", req.message.chars().take(40).collect::<String>())
        } else {
            req.message.clone()
        };
        sessions.push(ChatSession {
            id: session_id.clone(),
            title,
            created_at: timestamp,
            owner_hash: hash_auth_token(&headers).unwrap_or_default(),
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
    }
    drop(sessions);

    // NOTE: Chat context is RAM-only (stored in chat_sessions above).
    // We do NOT persist raw conversation transcripts to the memory engine.
    // Only structured memories (Facts, Preferences, TaskHistory) go to disk.
    // If the LLM suggests a memory addition, it goes through the approval queue.

    Json(ChatResponse {
        response: text.trim().to_string(),
        session_id,
    })
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
            if let Err(e) = validate_no_ssrf(base_url) {
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
            if let Err(e) = validate_no_ssrf(base_url) {
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

/// Extract memory proposals from LLM text and return cleaned text + proposals.
/// Format: <memory type="Fact" key="KEY">VALUE</memory>
/// Sanitize a memory value before injecting it into the LLM system prompt.
/// Prevents prompt injection by stripping angle brackets (tags), newlines,
/// and backticks that could be used to inject instructions or break formatting.
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
    let tool_config = ToolConfig::load();

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
                if validate_no_ssrf(&url).is_err() {
                    tracing::warn!("MCP server '{}' has a blocked URL (SSRF): {}", name, url);
                    continue;
                }
                if validate_no_ssrf_dns(&url).await.is_err() {
                    tracing::warn!("MCP server '{}' has a blocked URL (SSRF DNS): {}", name, url);
                    continue;
                }
                if server_config.transport == "http" {
                    McpTransport::Http { url, api_key: server_config.api_key.clone() }
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

/// Parse and execute MCP tool calls embedded in LLM response text.
/// Returns the cleaned text (with tags removed) and a list of tool results.
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
                                let rng = ring::rand::SystemRandom::new();
                                rng.fill(&mut n).expect("CSPRNG must succeed");
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

        let last_audit = policy.query_audit_log(&AuditQuery {
            from: Timestamp(0),
            to: Timestamp::now(),
            tool_id: None,
            requester: None,
            event_type: None,
        });
        let last_audit_entry = last_audit.entries.last().map(|e| {
            let (tool_id, method) = match &e.event {
                muccheai_types::audit::SecurityEvent::ActionProposed { tool_id, method, .. } => (tool_id.as_str(), method.as_str()),
                muccheai_types::audit::SecurityEvent::ActionValidated { tool_id, method, .. } => (tool_id.as_str(), method.as_str()),
                _ => ("system", "event"),
            };
            format!("{} - {}.{} (audit event)", 
                e.timestamp.0, 
                tool_id, 
                method
            )
        });

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
    let ollama_connected = {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .expect("reqwest Client builder should not fail with standard configuration");
        let url = format!("{}/api/tags", ollama_host);
        matches!(client.get(&url).send().await, Ok(r) if r.status().is_success())
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

/// List incidents
async fn incidents() -> Json<IncidentsResponse> {
    let detector = AnomalyDetector {
        baseline: BaselineStats {
            rate_mean: 10.0,
            rate_stddev: 2.0,
            normal_actions: vec!["email.send".to_string(), "calendar.read".to_string()],
        },
        sigma_threshold: 5.0,
    };

    let mut incidents = Vec::new();
    if let Some(incident) = detector.detect(100.0, &[]) {
        incidents.push(incident);
    }
    if let Some(incident) = detector.detect(10.0, &["unknown.action".to_string()]) {
        incidents.push(incident);
    }

    Json(IncidentsResponse { incidents })
}

/// Build verification status
async fn build_verify() -> Json<BuildVerifyResponse> {
    // Derive a deterministic commit hash from the build version so the
    // endpoint exercises real verification logic instead of a zeroed stub.
    let version_hash = muccheai_crypto::sha3_512(env!("CARGO_PKG_VERSION").as_bytes());
    let mut commit = [0u8; 20];
    commit.copy_from_slice(&version_hash[..20]);
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
        Err(e) => Json(BuildVerifyResponse {
            status: format!("error: {}", e),
            ci_systems: vec![],
        }),
    }
}

/// Create cross-agent delegation
async fn delegations(Json(req): Json<DelegationRequest>) -> Json<DelegationResponse> {
    let issuer = DID {
        method: req.issuer_method.clone(),
        identifier: req.issuer_identifier.clone(),
    };
    let subject = DID {
        method: req.subject_method.clone(),
        identifier: req.subject_identifier.clone(),
    };

    let delegation_id = format!(
        "delegation-{}-{}-{}",
        issuer,
        subject,
        Timestamp::now().0
    );

    // Log the requested resource scope and TTL for auditing
    tracing::info!(
        "Delegation request: {} -> {} | resources: {:?} | ttl: {}s",
        issuer,
        subject,
        req.resource_ids,
        req.ttl_seconds
    );

    Json(DelegationResponse {
        delegation_id,
        issuer: issuer.to_string(),
        subject: subject.to_string(),
        verified: false,
    })
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
    Query(query): Query<MemoryQuery>,
) -> Result<Json<MemoryListResponse>, StatusCode> {
    // Collect data while holding lock, then drop it before processing
    let all = {
        let sm = state.structured_memory.lock().await;
        sm.list_all()
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
/// Use this for user-initiated saves. LLM-suggested memories should go
/// through the approval queue endpoint instead.
async fn store_memory(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StoreMemoryRequest>,
) -> Result<StatusCode, StatusCode> {
    let sm = state.structured_memory.lock().await;
    let value = json_value_to_memory_value(req.value);

    match req.memory_type {
        MemoryType::Fact => {
            sm.store_fact(&req.key, &value)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
        MemoryType::Preference => {
            sm.store_preference(&req.key, &value)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
        MemoryType::TaskHistory => {
            return Err(StatusCode::FORBIDDEN);
        }
        MemoryType::Context | MemoryType::Draft => {
            // Context is RAM-only, Draft not yet implemented
            return Ok(StatusCode::NOT_IMPLEMENTED);
        }
    }

    Ok(StatusCode::CREATED)
}

/// Delete a structured memory by key.
async fn delete_memory(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let sm = state.structured_memory.lock().await;
    match sm.delete(&key) {
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
) -> Result<Json<MemoryQueueResponse>, StatusCode> {
    let sm = state.structured_memory.lock().await;
    let pending = sm.list_pending();
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
    Json(req): Json<ProposeMemoryRequest>,
) -> Result<Json<ProposeMemoryResponse>, StatusCode> {
    // Reject TaskHistory proposals through the approval queue to prevent
    // bypassing the direct-insertion restriction in store_memory.
    if req.memory_type == MemoryType::TaskHistory {
        return Err(StatusCode::FORBIDDEN);
    }
    let sm = state.structured_memory.lock().await;
    let value = json_value_to_memory_value(req.value);
    let entry = MemoryEntry {
        memory_type: req.memory_type,
        key: req.key,
        value,
        created_at: Timestamp::now(),
        user_signature: vec![],
        content_hash: vec![],
    };

    match sm.propose(entry, &req.justification) {
        Ok(id) => Ok(Json(ProposeMemoryResponse { id, status: "pending".to_string() })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Approve a pending memory proposal.
async fn approve_memory_proposal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    tracing::trace!("approve_memory_proposal: id={}", id);
    let sm = state.structured_memory.lock().await;
    match sm.approve(&id) {
        Ok(true) => Ok(StatusCode::OK),
        Ok(false) => Ok(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Reject a pending memory proposal.
async fn reject_memory_proposal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    tracing::trace!("reject_memory_proposal: id={}", id);
    let sm = state.structured_memory.lock().await;
    match sm.reject(&id) {
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
            validate_no_ssrf(base_url).map_err(|_| StatusCode::BAD_REQUEST)?;
            validate_no_ssrf_dns(base_url).await.map_err(|_| StatusCode::BAD_REQUEST)?;
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
        match state.http_client.get(&url).timeout(Duration::from_secs(5)).send().await {
            Ok(r) if r.status().is_success() => Json(TestConnectionResponse {
                success: true,
                message: "Connected to Ollama successfully".to_string(),
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

/// Get CSRF token for web form protection.
async fn get_csrf(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let token = state.csrf_token.lock().await;
    Json(serde_json::json!({ "csrf_token": token.clone() }))
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

/// Logout — invalidate server-side session state for the current user.
async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> StatusCode {
    let owner = hash_auth_token(&headers).unwrap_or_default();
    let mut sessions = state.chat_sessions.lock().await;
    sessions.retain(|s| !constant_time_eq(s.owner_hash.as_bytes(), owner.as_bytes()));
    StatusCode::NO_CONTENT
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
    let owner = hash_auth_token(&headers).unwrap_or_default();
    let sessions = state.chat_sessions.lock().await;
    let filtered: Vec<ChatSession> = sessions
        .iter()
        .filter(|s| constant_time_eq(s.owner_hash.as_bytes(), owner.as_bytes()))
        .cloned()
        .collect();
    Json(ChatSessionsResponse { sessions: filtered })
}

/// Get a specific chat session (owner-verified).
async fn get_chat_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ChatSession>, StatusCode> {
    let owner = hash_auth_token(&headers).unwrap_or_default();
    let sessions = state.chat_sessions.lock().await;
    sessions
        .iter()
        .find(|s| s.id == id && constant_time_eq(s.owner_hash.as_bytes(), owner.as_bytes()))
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// Delete a chat session (owner-verified).
async fn delete_chat_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> StatusCode {
    let owner = hash_auth_token(&headers).unwrap_or_default();
    let mut sessions = state.chat_sessions.lock().await;
    let before = sessions.len();
    sessions.retain(|s| s.id != id || !constant_time_eq(s.owner_hash.as_bytes(), owner.as_bytes()));
    if sessions.len() < before {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
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

const ALLOWED_MCP_COMMANDS: &[&str] = &["npx", "npm", "node", "bun", "deno"];

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
            let cmd_name = cmd_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(cmd);
            if !ALLOWED_MCP_COMMANDS.contains(&cmd_name) {
                return Err(StatusCode::BAD_REQUEST);
            }
            // Block path traversal (..) but allow absolute paths
            if cmd_path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                return Err(StatusCode::BAD_REQUEST);
            }
        } else {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    if req.transport == "http" || req.transport == "sse" {
        if let Some(ref url) = req.url {
            if validate_no_ssrf(url).is_err() {
                return Err(StatusCode::BAD_REQUEST);
            }
            if validate_no_ssrf_dns(url).await.is_err() {
                return Err(StatusCode::BAD_REQUEST);
            }
        } else {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

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
            api_key: req.api_key,
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
            tracing::info!("MCP tools cache refreshed after delete: {} tools", cache.len());
        });

        Ok(StatusCode::NO_CONTENT)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

async fn test_mcp_server(Path(name): Path<String>) -> Json<McpTestResponse> {
    let cfg = ToolConfig::load();
    let server = match cfg
        .mcp
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
            if validate_no_ssrf(url).is_err() {
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
                McpTransport::Http {
                    url,
                    api_key: server.api_key,
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
    match client.connect().await {
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
    }
}

/// Start the web server.
/// If MUCCHEAI_TLS_CERT and MUCCHEAI_TLS_KEY environment variables are set,
/// serves over HTTPS; otherwise serves over HTTP with a security warning.
pub async fn serve(addr: &str, state: Arc<AppState>) {
    let addr = addr.parse::<SocketAddr>().expect("invalid bind address");

    let cert_path = std::env::var("MUCCHEAI_TLS_CERT").ok();
    let key_path = std::env::var("MUCCHEAI_TLS_KEY").ok();

    if let (Some(cert), Some(key)) = (&cert_path, &key_path) {
        match axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await {
            Ok(config) => {
                println!("🔒 MuccheAI Control Panel running at https://{}", addr);
                axum_server::tls_rustls::bind_rustls(addr, config)
                    .serve(router(state).into_make_service_with_connect_info::<SocketAddr>())
                    .await
                    .expect("TLS server failed to start");
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
    axum_server::bind(addr)
        .serve(router(state).into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("HTTP server failed to start");
}

pub fn router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(|origin, _| {
            // Restrict CORS to exact localhost origins to prevent prefix bypasses
            // like http://localhost.evil.com.
            let origin_str = origin.to_str().unwrap_or("");
            if let Ok(url) = url::Url::parse(origin_str) {
                if let Some(host) = url.host_str() {
                    return host == "localhost"
                        || host == "127.0.0.1"
                        || host == "[::1]";
                }
            }
            false
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
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self';"
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
    let hsts = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        axum::http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );

    let static_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/web/static");

    // API routes — auth + rate limit required
    let api = Router::new()
        .route("/status", get(status))
        .route("/config", get(get_config))
        .route("/audit", post(audit_log))
        .route("/revoke", post(revoke))
        .route("/incidents", get(incidents))
        .route("/build-verify", get(build_verify))
        .route("/memory", get(list_memories))
        .route("/memory", post(store_memory))
        .route("/memory/:key", delete(delete_memory))
        .route("/memory/queue", get(list_memory_queue))
        .route("/memory/queue", post(propose_memory))
        .route("/memory/queue/:id/approve", post(approve_memory_proposal))
        .route("/memory/queue/:id/reject", post(reject_memory_proposal))
        .route("/chat", post(chat))
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
        .route("/model", get(get_model))
        .route("/model", post(set_model))
        .route("/sessions", get(list_chat_sessions))
        .route("/sessions/:id", get(get_chat_session))
        .route("/sessions/:id", delete(delete_chat_session))
        .route("/logout", post(logout))
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

    Router::new()
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
        .layer(cors)
        .layer(csp)
        .layer(xcto)
        .layer(xfo)
        .layer(rp)
        .layer(cc)
        .layer(hsts)
}
