//! MCP (Model Context Protocol) integration.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod server;
pub mod transport;
pub mod types;

pub use client::McpClient;
pub use server::McpServer;
pub use transport::McpTransport;
pub use types::McpTool;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_transport_clone() {
        let t = McpTransport::Http {
            url: "http://localhost:3000".to_string(),
            api_key: Some("test-api-key-placeholder-12345".to_string()),
        };
        let cloned = match &t {
            McpTransport::Http { url, api_key } => {
                assert_eq!(url, "http://localhost:3000");
                assert_eq!(api_key, &Some("test-api-key-placeholder-12345".to_string()));
                true
            }
            _ => false,
        };
        assert!(cloned);
    }

    #[test]
    fn test_mcp_server_creation() {
        let server = McpServer::new("test-server", "1.0.0");
        let resp = server.handle_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#,
        );
        let parsed: serde_json::Value = serde_json::from_str(&resp.unwrap()).unwrap();
        assert!(parsed["result"].is_object());
        assert_eq!(parsed["id"], 1);
    }
}
