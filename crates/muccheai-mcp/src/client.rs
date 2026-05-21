//! MCP Client implementation
//!
//! Connects to MCP servers, discovers tools, and invokes them.

use muccheai_types::{ToolResult, ToolResultMetadata};
use tracing::{debug, info};

use crate::transport::{McpTransport, TransportHandle};
use crate::types::{
    CallToolParams, CallToolResult, InitializeParams, InitializeResult, Implementation,
    ListToolsParams, ListToolsResult, McpTool, MCP_PROTOCOL_VERSION,
};

/// MCP Client for connecting to external MCP servers
pub struct McpClient {
    transport: McpTransport,
    handle: Option<TransportHandle>,
    tools: Vec<McpTool>,
    initialized: bool,
    /// Optional auth token for request signing.
    auth_token: Option<String>,
}

impl McpClient {
    /// Create a new MCP client with the given transport
    pub fn new(transport: McpTransport) -> Self {
        Self {
            transport,
            handle: None,
            tools: Vec::new(),
            initialized: false,
            auth_token: None,
        }
    }

    /// Set an auth token that will be included in all JSON-RPC requests.
    pub fn set_auth_token(&mut self, token: &str) {
        self.auth_token = Some(token.to_string());
    }

    /// Connect to the MCP server and perform initialization handshake
    pub async fn connect(&mut self) -> anyhow::Result<()> {
        let mut handle = self.transport.connect().await?;

        let init_params = InitializeParams {
            protocol_version: MCP_PROTOCOL_VERSION.to_string(),
            capabilities: Default::default(),
            client_info: Implementation {
                name: "muccheai-mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };

        let result: InitializeResult = {
            let value = handle
                .request("initialize", Some(serde_json::to_value(&init_params)?))
                .await?;
            serde_json::from_value(value)?
        };

        info!(
            "MCP server initialized: {} v{}",
            result.server_info.name, result.server_info.version
        );

        // Send initialized notification
        handle.notify("notifications/initialized", None).await?;

        self.handle = Some(handle);
        self.initialized = true;
        Ok(())
    }

    /// Wrap JSON-RPC params with auth token if configured.
    fn wrap_params(&self, params: Option<serde_json::Value>) -> Option<serde_json::Value> {
        let token = match &self.auth_token {
            Some(t) => t,
            None => return params,
        };
        match params {
            Some(serde_json::Value::Object(mut map)) => {
                map.insert("_auth".to_string(), serde_json::Value::String(token.clone()));
                Some(serde_json::Value::Object(map))
            }
            None => {
                let mut map = serde_json::Map::new();
                map.insert("_auth".to_string(), serde_json::Value::String(token.clone()));
                Some(serde_json::Value::Object(map))
            }
            other => other,
        }
    }

    /// Discover available tools from the MCP server
    pub async fn discover_tools(&mut self) -> anyhow::Result<Vec<McpTool>> {
        let params = ListToolsParams::default();
        let wrapped = self.wrap_params(Some(serde_json::to_value(&params)?));
        let handle = self
            .handle
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("MCP client not connected"))?;

        let value = handle
            .request("tools/list", wrapped)
            .await?;
        let result: ListToolsResult = serde_json::from_value(value)?;

        debug!("Discovered {} MCP tools", result.tools.len());
        self.tools = result.tools.clone();
        Ok(result.tools)
    }

    /// Call an MCP tool by name with parameters
    pub async fn call_tool(
        &mut self,
        name: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<ToolResult> {
        let call_params = CallToolParams {
            name: name.to_string(),
            arguments: Some(params),
        };
        let wrapped = self.wrap_params(Some(serde_json::to_value(&call_params)?));
        let handle = self.handle.as_mut()
            .ok_or_else(|| anyhow::anyhow!("MCP client not connected"))?;

        let start = std::time::Instant::now();

        let value = handle
            .request("tools/call", wrapped)
            .await?;
        let result: CallToolResult = serde_json::from_value(value)?;

        let elapsed = start.elapsed().as_millis() as u64;

        let data = if result.is_error {
            serde_json::json!({
                "error": true,
                "content": result.content
            })
        } else {
            let text: Vec<String> = result
                .content
                .iter()
                .filter_map(|c| c.text.clone())
                .collect();
            serde_json::json!({
                "text": text.join("\n"),
                "content": result.content
            })
        };

        Ok(ToolResult {
            success: !result.is_error,
            data,
            metadata: ToolResultMetadata {
                execution_time_ms: elapsed,
                tool_id: format!("mcp:{}", name),
                method: "call".to_string(),
            },
        })
    }

    /// Get the list of cached tools (requires discover_tools first)
    pub fn tools(&self) -> &[McpTool] {
        &self.tools
    }

    /// Whether the client is connected and initialized
    pub fn is_connected(&self) -> bool {
        self.initialized
    }
}
