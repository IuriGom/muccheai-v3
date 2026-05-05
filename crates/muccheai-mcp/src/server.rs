//! MCP Server implementation
//!
//! Exposes MuccheAI's tools as an MCP server.

use std::collections::HashMap;
use std::sync::Arc;

use crate::types::{
    CallToolParams, CallToolResult, Implementation, InitializeParams,
    InitializeResult, JsonRpcError, JsonRpcRequest, JsonRpcResponse, ListToolsResult, McpTool,
    ServerCapabilities, MCP_PROTOCOL_VERSION,
};

/// A handler function for an MCP tool
pub type McpToolHandler = Arc<
    dyn Fn(serde_json::Value) -> Result<CallToolResult, String> + Send + Sync,
>;

/// MCP Server that exposes MuccheAI tools
pub struct McpServer {
    name: String,
    version: String,
    tools: HashMap<String, (McpTool, McpToolHandler)>,
    /// Optional auth token. If set, all non-initialize requests must include
    /// `{"_auth": "<token>"}` in their params.
    auth_token: Option<String>,
}

impl McpServer {
    /// Create a new MCP server
    pub fn new(name: &str, version: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            tools: HashMap::new(),
            auth_token: None,
        }
    }

    /// Set an auth token that clients must provide for non-initialize requests.
    pub fn set_auth_token(&mut self, token: &str) {
        self.auth_token = Some(token.to_string());
    }

    /// Register a tool with the server
    pub fn register_tool(
        &mut self,
        tool: McpTool,
        handler: McpToolHandler,
    ) {
        self.tools.insert(tool.name.clone(), (tool, handler));
    }

    /// Handle a raw JSON-RPC request string and return a response string.
    /// Returns `None` for notifications (requests without an id), which
    /// the caller should treat as "no response to send".
    pub fn handle_request(&self, request_json: &str) -> Option<String> {
        const MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024;
        if request_json.len() > MAX_REQUEST_SIZE {
            return serde_json::to_string(&JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: None,
                result: None,
                error: Some(JsonRpcError {
                    code: -32600,
                    message: "Request too large".to_string(),
                    data: None,
                }),
            }).unwrap()
        }
        let req: JsonRpcRequest = match serde_json::from_str(request_json) {
            Ok(r) => r,
            Err(e) => {
                return serde_json::to_string(&JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: None,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                        data: None,
                    }),
                }).unwrap()
            }
        };

        // Notifications (no id) don't require a response per JSON-RPC 2.0 spec.
        let is_notification = req.id.is_none();

        // Auth check: if an auth token is configured, non-initialize requests
        // must include `{"_auth": "<token>"}` in their params.
        if let Some(ref token) = self.auth_token {
            if req.method != "initialize" {
                let authenticated = req.params.as_ref()
                    .and_then(|p| p.get("_auth"))
                    .and_then(|v| v.as_str())
                    == Some(token.as_str());
                if !authenticated {
                    return serde_json::to_string(&JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32001,
                            message: "Unauthorized: invalid or missing auth token".to_string(),
                            data: None,
                        }),
                    }).unwrap()
                }
            }
        }

        let result = match req.method.as_str() {
            "initialize" => self.handle_initialize(req.params),
            "tools/list" => self.handle_tools_list(),
            "tools/call" => self.handle_tools_call(req.params),
            _ => Err(JsonRpcError {
                code: -32601,
                message: format!("Method not found: {}", req.method),
                data: None,
            }),
        };

        // For notifications, process the method but don't return a response.
        if is_notification {
            return None;
        }

        let resp = match result {
            Ok(value) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: Some(value),
                error: None,
            },
            Err(err) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(err),
            },
        };

        serde_json::to_string(&resp).ok()
    }

    fn handle_initialize(
        &self,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, JsonRpcError> {
        let _params: InitializeParams =
            serde_json::from_value(params.unwrap_or(serde_json::Value::Null))
                .map_err(|e| JsonRpcError {
                    code: -32602,
                    message: format!("Invalid params: {}", e),
                    data: None,
                })?;

        let result = InitializeResult {
            protocol_version: MCP_PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities {
                tools: Some(serde_json::Value::Object(Default::default())),
                ..Default::default()
            },
            server_info: Implementation {
                name: self.name.clone(),
                version: self.version.clone(),
            },
        };

        Ok(serde_json::to_value(result).unwrap())
    }

    fn handle_tools_list(&self) -> Result<serde_json::Value, JsonRpcError> {
        let tools: Vec<McpTool> = self.tools.values().map(|(t, _)| t.clone()).collect();
        let result = ListToolsResult {
            tools,
            next_cursor: None,
        };
        Ok(serde_json::to_value(result).unwrap())
    }

    fn handle_tools_call(
        &self,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, JsonRpcError> {
        let params: CallToolParams =
            serde_json::from_value(params.unwrap_or(serde_json::Value::Null))
                .map_err(|e| JsonRpcError {
                    code: -32602,
                    message: format!("Invalid params: {}", e),
                    data: None,
                })?;

        let (_, handler) = self.tools.get(&params.name).ok_or_else(|| JsonRpcError {
            code: -32602,
            message: format!("Tool not found: {}", params.name),
            data: None,
        })?;

        let args = params.arguments.unwrap_or(serde_json::Value::Null);
        match handler(args) {
            Ok(result) => serde_json::to_value(result).map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("Serialization error: {}", e),
                data: None,
            }),
            Err(msg) => Err(JsonRpcError {
                code: -32603,
                message: msg,
                data: None,
            }),
        }
    }
}
