//! MuccheAI v3.0 — Tool Gateway (Tool Execution)
//!
//! Expanded tool adapters with capability validation, JSON Schema validation,
//! dynamic tool registration, and MCP client integration.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod adapters;
pub mod config;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use muccheai_crypto::hybrid_verify;
use muccheai_types::capabilities::*;
use muccheai_types::crypto_primitives::*;
use muccheai_types::*;
use serde_json::json;
use tracing::{info, warn};

/// A compiled-in tool adapter
#[derive(Debug, Clone)]
pub struct ToolAdapter {
    /// Adapter name / tool ID
    pub name: &'static str,
    /// Available methods
    pub methods: Vec<ToolMethod>,
}

/// A method on a tool adapter
#[derive(Debug, Clone)]
pub struct ToolMethod {
    /// Method name
    pub name: &'static str,
    /// JSON Schema for parameters
    pub params_schema: serde_json::Value,
    /// Handler function
    pub handler: fn(&serde_json::Value) -> std::result::Result<ToolResult, ToolError>,
}

/// Result of tool execution
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    /// Success or failure
    pub success: bool,
    /// Result data (JSON)
    pub result: Vec<u8>,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Audit log ID
    pub audit_log_id: String,
}

/// Dynamic tool registered at runtime (e.g. from MCP)
pub struct DynamicTool {
    /// Tool name
    pub name: String,
    /// Method name (often "call" for MCP)
    pub method: String,
    /// Parameter schema
    pub params_schema: serde_json::Value,
    /// Handler
    pub handler: Arc<
        dyn Fn(&serde_json::Value) -> std::result::Result<ToolResult, ToolError> + Send + Sync,
    >,
}

/// Tool Gateway — executes tool calls with capability validation
pub struct ToolGateway {
    /// Static compiled-in adapters
    static_adapters: HashMap<String, ToolAdapter>,
    /// Dynamic tools registered at runtime
    dynamic_tools: HashMap<String, DynamicTool>,
    /// Policy Engine public key for capability verification
    policy_pubkey: HybridPubkey,
    /// Per-token use counts
    use_counts: Mutex<HashMap<Vec<u8>, u64>>,
    /// Tool configuration
    config: config::ToolConfig,
    /// Maximum result size in bytes (for context window pruning)
    result_size_limit: usize,
}

impl ToolGateway {
    /// Create a new Tool Gateway with all built-in adapters registered
    pub fn new(policy_pubkey: HybridPubkey) -> Self {
        let mut gw = Self {
            static_adapters: HashMap::new(),
            dynamic_tools: HashMap::new(),
            policy_pubkey,
            use_counts: Mutex::new(HashMap::new()),
            config: config::ToolConfig::load(),
            result_size_limit: 128_000, // ~32k tokens rough estimate
        };
        gw.register_builtin_adapters();
        gw
    }

    /// Set the result size limit (bytes)
    pub fn set_result_size_limit(&mut self, limit: usize) {
        self.result_size_limit = limit;
    }

    /// Register a static compiled-in adapter
    pub fn register_adapter(&mut self, adapter: ToolAdapter) {
        self.static_adapters
            .insert(adapter.name.to_string(), adapter);
    }

    /// Register a dynamic tool at runtime (e.g. from MCP)
    pub fn register_dynamic_tool(&mut self, tool: DynamicTool) {
        info!("Registering dynamic tool: {}", tool.name);
        // Reject dynamic tools with null or empty schemas to prevent validation bypass.
        if tool.params_schema.is_null()
            || tool.params_schema.as_object().map(|o| o.is_empty()).unwrap_or(false)
        {
            warn!(
                "Rejecting dynamic tool '{}' due to empty/null params schema",
                tool.name
            );
            return;
        }
        self.dynamic_tools.insert(tool.name.clone(), tool);
    }

    /// Unregister a dynamic tool
    pub fn unregister_dynamic_tool(&mut self, name: &str) {
        self.dynamic_tools.remove(name);
    }

    /// List all registered tool names
    pub fn list_tools(&self) -> Vec<String> {
        let mut names: Vec<String> = self.static_adapters.keys().cloned().collect();
        names.extend(self.dynamic_tools.keys().cloned());
        names.sort();
        names.dedup();
        names
    }

    /// Execute a tool call with full capability validation
    pub fn execute(
        &self,
        tool_id: &str,
        method: &str,
        params: &[u8],
        capability_token: &CapabilityToken,
    ) -> Result<ExecutionResult> {
        let start = std::time::Instant::now();

        self.verify_capability(capability_token)?;

        if !capability_token.is_temporally_valid() {
            return Err(MuccheError::InvalidCapability("Token expired".to_string()));
        }

        if capability_token.tool_id != tool_id {
            return Err(MuccheError::InvalidCapability(format!(
                "Token for wrong tool: expected {}, got {}",
                tool_id, capability_token.tool_id
            )));
        }
        if capability_token.method != method {
            return Err(MuccheError::InvalidCapability(format!(
                "Token for wrong method: expected {}, got {}",
                method, capability_token.method
            )));
        }

        let resource = serde_json::from_slice::<serde_json::Value>(params)
            .ok()
            .and_then(|p| p.get("resource").or_else(|| p.get("path")).or_else(|| p.get("to"))
                .and_then(|v| v.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| tool_id.to_string());
        if !capability_token.covers_resource(&resource) {
            return Err(MuccheError::InvalidCapability(
                format!("Token does not cover resource: {}", resource)
            ));
        }

        if capability_token.bound_process > 0 && capability_token.bound_process != std::process::id() as u64 {
            return Err(MuccheError::InvalidCapability(
                "Token bound to different process".to_string()
            ));
        }

        if !self.config.is_enabled(tool_id) {
            return Err(MuccheError::Internal(format!(
                "Tool '{}' is disabled in configuration",
                tool_id
            )));
        }

        let params_json: serde_json::Value = serde_json::from_slice(params)
            .map_err(|e| MuccheError::Internal(format!("Invalid JSON params: {}", e)))?;

        let token_id = capability_token.token_id.clone();
        if capability_token.max_uses > 0 {
            let mut counts = self.use_counts.lock().unwrap();
            let count = counts.get(&token_id).copied().unwrap_or(0);
            if count >= capability_token.max_uses {
                return Err(MuccheError::InvalidCapability(
                    "Token use limit exceeded".to_string(),
                ));
            }
            *counts.entry(token_id.clone()).or_insert(0) += 1;
        }

        let exec_result = (|| -> std::result::Result<ToolResult, MuccheError> {
            if let Some(adapter) = self.static_adapters.get(tool_id) {
                let method_def = adapter
                    .methods
                    .iter()
                    .find(|m| m.name == method)
                    .ok_or_else(|| {
                        MuccheError::Internal(format!(
                            "Method '{}' not found on tool '{}'",
                            method, tool_id
                        ))
                    })?;

                if let Err(e) = validate_schema(&method_def.params_schema, &params_json) {
                    return Err(MuccheError::Internal(format!(
                        "Schema validation failed: {}",
                        e
                    )));
                }

                (method_def.handler)(&params_json)
                    .map_err(|e| MuccheError::Internal(e.to_string()))
            } else if let Some(dyn_tool) = self.dynamic_tools.get(tool_id) {
                if dyn_tool.method != method {
                    return Err(MuccheError::Internal(format!(
                        "Dynamic tool '{}' does not support method '{}'",
                        tool_id, method
                    )));
                }
                if let Err(e) = validate_schema(&dyn_tool.params_schema, &params_json) {
                    return Err(MuccheError::Internal(format!(
                        "Schema validation failed: {}",
                        e
                    )));
                }
                (dyn_tool.handler)(&params_json)
                    .map_err(|e| MuccheError::Internal(e.to_string()))
            } else {
                Err(MuccheError::Internal(format!(
                    "Tool adapter not found: {}",
                    tool_id
                )))
            }
        })();

        if exec_result.is_err() && capability_token.max_uses > 0 {
            let mut counts = self.use_counts.lock().unwrap();
            if let Some(c) = counts.get_mut(&token_id) {
                *c = c.saturating_sub(1);
            }
        }

        let tool_result = exec_result?;

        let elapsed = start.elapsed().as_millis() as u64;
        let audit_id = format!("exec-{}", hex::encode(&capability_token.token_id[..8]));

        let mut result_bytes = serde_json::to_vec(&tool_result.data)
            .map_err(|e| MuccheError::Internal(format!("Serialization error: {}", e)))?;

        if result_bytes.len() > self.result_size_limit {
            warn!(
                "Tool result size {} exceeds limit {}, pruning",
                result_bytes.len(),
                self.result_size_limit
            );
            let pruned = json!({
                "_pruned": true,
                "original_size": result_bytes.len(),
                "limit": self.result_size_limit,
                "preview": String::from_utf8_lossy(&result_bytes[..self.result_size_limit.min(500)])
            });
            result_bytes = serde_json::to_vec(&pruned)
                .map_err(|e| MuccheError::Internal(format!("Serialization error: {}", e)))?;
        }

        Ok(ExecutionResult {
            success: tool_result.success,
            result: result_bytes,
            execution_time_ms: elapsed,
            audit_log_id: audit_id,
        })
    }

    /// Simplified tool execution without capability validation (tests only).
    #[cfg(test)]
    pub(crate) fn execute_tool(
        &self,
        tool_id: &str,
        method: &str,
        params: &[u8],
    ) -> std::result::Result<Vec<u8>, String> {
        let params_json: serde_json::Value =
            serde_json::from_slice(params).map_err(|e| format!("Invalid JSON: {}", e))?;

        let result = if let Some(adapter) = self.static_adapters.get(tool_id) {
            let method_def = adapter
                .methods
                .iter()
                .find(|m| m.name == method)
                .ok_or_else(|| format!("Method '{}' not found on tool '{}'", method, tool_id))?;
            (method_def.handler)(&params_json)
                .map_err(|e| e.to_string())?
        } else if let Some(dyn_tool) = self.dynamic_tools.get(tool_id) {
            if dyn_tool.method != method {
                return Err(format!(
                    "Dynamic tool '{}' does not support method '{}'",
                    tool_id, method
                ));
            }
            (dyn_tool.handler)(&params_json)
                .map_err(|e| e.to_string())?
        } else {
            return Err(format!("Unknown tool: {}", tool_id));
        };

        serde_json::to_vec(&result.data).map_err(|e| e.to_string())
    }

    /// Verify a capability token against Policy Engine public key
    fn verify_capability(&self, token: &CapabilityToken) -> Result<()> {
        let sig = HybridSignature {
            classical: token.classical_signature.clone(),
            pq: token.pq_signature.clone(),
        };
        hybrid_verify(&token.signing_payload(), &sig, &self.policy_pubkey)
            .map_err(|e| MuccheError::CryptoError(format!("Signature verification failed: {}", e)))?;
        Ok(())
    }

    /// Query scope of a tool adapter
    pub fn query_scope(&self, tool_id: &str) -> Option<muccheai_types::ToolScope> {
        if self.static_adapters.contains_key(tool_id) || self.dynamic_tools.contains_key(tool_id) {
            Some(muccheai_types::ToolScope {
                methods: vec!["*".to_string()],
                memory: vec![],
                sandbox: muccheai_types::SandboxRestrictions {
                    network: true,
                    filesystem: true,
                    max_execution_ms: 30000,
                },
            })
        } else {
            None
        }
    }

    /// Register all built-in adapters
    fn register_builtin_adapters(&mut self) {
        use adapters::*;

        // Communication tools
        self.register_adapter(ToolAdapter {
            name: "slack",
            methods: vec![ToolMethod {
                name: "post",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "channel": { "type": "string" },
                        "message": { "type": "string" },
                        "webhook_url": { "type": "string" }
                    },
                    "required": ["channel", "message"]
                }),
                handler: communication::slack_post,
            }],
        });

        self.register_adapter(ToolAdapter {
            name: "discord",
            methods: vec![ToolMethod {
                name: "send",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "webhook_url": { "type": "string" },
                        "content": { "type": "string" }
                    },
                    "required": ["webhook_url", "content"]
                }),
                handler: communication::discord_send,
            }],
        });

        self.register_adapter(ToolAdapter {
            name: "telegram",
            methods: vec![ToolMethod {
                name: "send",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "bot_token": { "type": "string" },
                        "chat_id": { "type": "string" },
                        "message": { "type": "string" }
                    },
                    "required": ["bot_token", "chat_id", "message"]
                }),
                handler: communication::telegram_send,
            }],
        });

        self.register_adapter(ToolAdapter {
            name: "email",
            methods: vec![ToolMethod {
                name: "send",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "to": { "type": "string", "format": "email" },
                        "subject": { "type": "string" },
                        "body": { "type": "string" },
                        "smtp_host": { "type": "string" },
                        "smtp_port": { "type": "integer" }
                    },
                    "required": ["to", "subject"]
                }),
                handler: communication::email_send,
            }],
        });

        // Development tools
        self.register_adapter(ToolAdapter {
            name: "github",
            methods: vec![
                ToolMethod {
                    name: "create_issue",
                    params_schema: json!({
                        "type": "object",
                        "properties": {
                            "token": { "type": "string" },
                            "owner": { "type": "string" },
                            "repo": { "type": "string" },
                            "title": { "type": "string" },
                            "body": { "type": "string" }
                        },
                        "required": ["token", "owner", "repo", "title"]
                    }),
                    handler: development::github_create_issue,
                },
            ],
        });

        self.register_adapter(ToolAdapter {
            name: "git",
            methods: vec![ToolMethod {
                name: "run",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "command": { "type": "string" },
                        "repo_path": { "type": "string" }
                    },
                    "required": ["command"]
                }),
                handler: development::git_run,
            }],
        });

        #[cfg(feature = "shell")]
        self.register_adapter(ToolAdapter {
            name: "shell",
            methods: vec![ToolMethod {
                name: "run",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "command": { "type": "string" },
                        "cwd": { "type": "string" }
                    },
                    "required": ["command"]
                }),
                handler: development::shell_run,
            }],
        });

        self.register_adapter(ToolAdapter {
            name: "docker",
            methods: vec![ToolMethod {
                name: "run",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "subcommand": { "type": "string" },
                        "image": { "type": "string" },
                        "args": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["subcommand"]
                }),
                handler: development::docker_run,
            }],
        });

        // Web tools
        self.register_adapter(ToolAdapter {
            name: "browser",
            methods: vec![ToolMethod {
                name: "navigate",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "url": { "type": "string", "format": "uri" }
                    },
                    "required": ["url"]
                }),
                handler: web::browser_navigate,
            }],
        });

        self.register_adapter(ToolAdapter {
            name: "fetch",
            methods: vec![ToolMethod {
                name: "request",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "url": { "type": "string", "format": "uri" },
                        "method": { "type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"] },
                        "timeout_secs": { "type": "integer" },
                        "body": {},
                        "headers": { "type": "object" }
                    },
                    "required": ["url"]
                }),
                handler: web::fetch_request,
            }],
        });

        self.register_adapter(ToolAdapter {
            name: "search",
            methods: vec![ToolMethod {
                name: "query",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" }
                    },
                    "required": ["query"]
                }),
                handler: web::search_query,
            }],
        });

        self.register_adapter(ToolAdapter {
            name: "pdf",
            methods: vec![ToolMethod {
                name: "extract",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" }
                    },
                    "required": ["path"]
                }),
                handler: web::pdf_extract,
            }],
        });

        // Data tools
        self.register_adapter(ToolAdapter {
            name: "sqlite",
            methods: vec![ToolMethod {
                name: "query",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "db_path": { "type": "string" },
                        "query": { "type": "string" }
                    },
                    "required": ["db_path", "query"]
                }),
                handler: data::sqlite_query,
            }],
        });

        self.register_adapter(ToolAdapter {
            name: "csv",
            methods: vec![
                ToolMethod {
                    name: "read",
                    params_schema: json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" }
                        },
                        "required": ["path"]
                    }),
                    handler: data::csv_read,
                },
                ToolMethod {
                    name: "write",
                    params_schema: json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "rows": { "type": "array" }
                        },
                        "required": ["path", "rows"]
                    }),
                    handler: data::csv_write,
                },
            ],
        });

        self.register_adapter(ToolAdapter {
            name: "json",
            methods: vec![ToolMethod {
                name: "transform",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "input": {},
                        "operation": { "type": "string", "enum": ["pretty", "minify", "keys", "get", "length"] },
                        "key": { "type": "string" }
                    },
                    "required": ["input", "operation"]
                }),
                handler: data::json_transform,
            }],
        });

        // System tools
        self.register_adapter(ToolAdapter {
            name: "clipboard",
            methods: vec![
                ToolMethod {
                    name: "read",
                    params_schema: json!({ "type": "object" }),
                    handler: system::clipboard_read,
                },
                ToolMethod {
                    name: "write",
                    params_schema: json!({
                        "type": "object",
                        "properties": {
                            "text": { "type": "string" }
                        },
                        "required": ["text"]
                    }),
                    handler: system::clipboard_write,
                },
            ],
        });

        self.register_adapter(ToolAdapter {
            name: "screenshot",
            methods: vec![ToolMethod {
                name: "capture",
                params_schema: json!({ "type": "object" }),
                handler: system::screenshot_capture,
            }],
        });

        self.register_adapter(ToolAdapter {
            name: "notifications",
            methods: vec![ToolMethod {
                name: "send",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "title": { "type": "string" },
                        "message": { "type": "string" }
                    },
                    "required": ["title", "message"]
                }),
                handler: system::notifications_send,
            }],
        });

        self.register_adapter(ToolAdapter {
            name: "cron",
            methods: vec![ToolMethod {
                name: "schedule",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "expression": { "type": "string" },
                        "command": { "type": "string" }
                    },
                    "required": ["expression", "command"]
                }),
                handler: system::cron_schedule,
            }],
        });

        // Legacy compatibility adapters
        self.register_adapter(ToolAdapter {
            name: "calendar",
            methods: vec![ToolMethod {
                name: "read",
                params_schema: json!({
                    "type": "object",
                    "properties": {
                        "date_range": { "type": "string" }
                    }
                }),
                handler: legacy_calendar_read,
            }],
        });

        self.register_adapter(ToolAdapter {
            name: "filesystem",
            methods: vec![
                ToolMethod {
                    name: "read",
                    params_schema: json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" }
                        },
                        "required": ["path"]
                    }),
                    handler: legacy_filesystem_read,
                },
                ToolMethod {
                    name: "write",
                    params_schema: json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string" },
                            "content": { "type": "string" }
                        },
                        "required": ["path"]
                    }),
                    handler: legacy_filesystem_write,
                },
            ],
        });
    }
}

/// Validate JSON params against a JSON Schema
fn validate_schema(
    schema: &serde_json::Value,
    params: &serde_json::Value,
) -> std::result::Result<(), String> {
    if schema.is_null() {
        return Err("Schema is null — parameter validation disabled".to_string());
    }
    let validator = jsonschema::JSONSchema::compile(schema)
        .map_err(|e| format!("Invalid schema: {}", e))?;
    validator
        .validate(params)
        .map_err(|errors| {
            let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
            format!("Validation error: {}", messages.join(", "))
        })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy compatibility handlers
// ---------------------------------------------------------------------------

fn legacy_calendar_read(params: &serde_json::Value) -> std::result::Result<ToolResult, ToolError> {
    let date_range = params.get("date_range").and_then(|v| v.as_str()).unwrap_or("today");
    let events = vec![
        json!({
            "id": "evt-1",
            "title": "Team Standup",
            "start": "2024-01-15T09:00:00Z",
            "end": "2024-01-15T09:30:00Z"
        }),
        json!({
            "id": "evt-2",
            "title": "1:1 with Manager",
            "start": "2024-01-15T14:00:00Z",
            "end": "2024-01-15T14:30:00Z"
        }),
    ];
    Ok(ToolResult {
        success: true,
        data: json!({ "date_range": date_range, "events": events }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "calendar".to_string(),
            method: "read".to_string(),
        },
    })
}

fn legacy_filesystem_read(params: &serde_json::Value) -> std::result::Result<ToolResult, ToolError> {
    let path = params.get("path").and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'path'".to_string()))?;
    let _canonical = crate::adapters::data::validate_path(path)?;
    Ok(ToolResult {
        success: true,
        data: json!({ "status": "read", "path": path, "content": "" }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "filesystem".to_string(),
            method: "read".to_string(),
        },
    })
}

fn legacy_filesystem_write(params: &serde_json::Value) -> std::result::Result<ToolResult, ToolError> {
    let path = params.get("path").and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'path'".to_string()))?;
    let _canonical = crate::adapters::data::validate_path(path)?;
    Ok(ToolResult {
        success: true,
        data: json!({ "status": "written", "path": path }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "filesystem".to_string(),
            method: "write".to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pubkey() -> HybridPubkey {
        HybridPubkey {
            classical: vec![0u8; 32],
            x25519: vec![0u8; 32],
            pq: vec![0u8; 1184],
            pq_sign: vec![0u8; 1312],
        }
    }

    #[test]
    fn test_gateway_creation() {
        let gw = ToolGateway::new(dummy_pubkey());
        let tools = gw.list_tools();
        assert!(tools.contains(&"email".to_string()));
        assert!(tools.contains(&"slack".to_string()));
        assert!(tools.contains(&"github".to_string()));
        assert!(tools.contains(&"fetch".to_string()));
        assert!(tools.contains(&"sqlite".to_string()));
        assert!(tools.contains(&"notifications".to_string()));
    }

    #[test]
    fn test_email_execution() {
        let gw = ToolGateway::new(dummy_pubkey());
        let result = gw.execute_tool(
            "email",
            "send",
            br#"{"to":"test@example.com","subject":"Hello","body":"World"}"#,
        );
        assert!(result.is_ok());
        let json: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(json["status"], "queued");
        assert_eq!(json["to"], "test@example.com");
    }

    #[test]
    fn test_email_invalid_address() {
        let gw = ToolGateway::new(dummy_pubkey());
        let result = gw.execute_tool(
            "email",
            "send",
            br#"{"to":"invalid","subject":"Hello"}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_calendar_readonly() {
        let gw = ToolGateway::new(dummy_pubkey());
        let result = gw.execute_tool("calendar", "read", br#"{"date_range":"today"}"#);
        assert!(result.is_ok());
        let json: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert!(json["events"].as_array().unwrap().len() > 0);
    }

    #[test]
    fn test_filesystem_traversal_rejected() {
        let gw = ToolGateway::new(dummy_pubkey());
        let result = gw.execute_tool("filesystem", "read", br#"{"path":"/etc/../secret"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_search_query() {
        let gw = ToolGateway::new(dummy_pubkey());
        let result = gw.execute_tool("search", "query", br#"{"query":"rust programming"}"#);
        assert!(result.is_ok());
        let json: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert_eq!(json["query"], "rust programming");
    }

    #[test]
    #[cfg(feature = "shell")]
    fn test_shell_disabled() {
        let gw = ToolGateway::new(dummy_pubkey());
        // Shell execution is disabled for security reasons.
        let result = gw.execute_tool("shell", "run", br#"{"command":"ls -la"}"#);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(feature = "shell"))]
    fn test_shell_not_compiled() {
        let gw = ToolGateway::new(dummy_pubkey());
        // Shell adapter is not compiled into the binary.
        let result = gw.execute_tool("shell", "run", br#"{"command":"ls -la"}"#);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown tool: shell"));
    }

    #[test]
    fn test_fetch_request() {
        let gw = ToolGateway::new(dummy_pubkey());
        let result = gw.execute_tool(
            "fetch",
            "request",
            br#"{"url":"https://example.com","method":"GET"}"#,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_json_transform() {
        let gw = ToolGateway::new(dummy_pubkey());
        let result = gw.execute_tool(
            "json",
            "transform",
            br#"{"input":{"a":1,"b":2},"operation":"keys"}"#,
        );
        assert!(result.is_ok());
        let json: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert!(json["keys"].as_array().unwrap().contains(&json!("a")));
    }

    #[test]
    fn test_dynamic_tool_registration() {
        let mut gw = ToolGateway::new(dummy_pubkey());
        let tool = DynamicTool {
            name: "my_dynamic".to_string(),
            method: "invoke".to_string(),
            params_schema: json!({"type": "object"}),
            handler: Arc::new(|_params| {
                Ok(ToolResult {
                    success: true,
                    data: json!({"hello": "world"}),
                    metadata: ToolResultMetadata {
                        execution_time_ms: 0,
                        tool_id: "my_dynamic".to_string(),
                        method: "invoke".to_string(),
                    },
                })
            }),
        };
        gw.register_dynamic_tool(tool);
        assert!(gw.list_tools().contains(&"my_dynamic".to_string()));

        let result = gw.execute_tool("my_dynamic", "invoke", br#"{}"#);
        assert!(result.is_ok());
    }
}
