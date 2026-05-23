//! MCP transport implementations
//!
//! Supports stdio, SSE, and HTTP transports.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, trace};

use crate::types::{JsonRpcRequest, JsonRpcResponse};

/// MCP transport variants
#[derive(Clone)]
pub enum McpTransport {
    /// Stdio transport: spawn a subprocess and communicate over stdin/stdout
    Stdio {
        /// Command to spawn
        command: String,
        /// Arguments
        args: Vec<String>,
    },
    /// Server-Sent Events transport
    Sse {
        /// SSE endpoint URL
        url: String,
    },
    /// HTTP POST transport
    Http {
        /// API endpoint
        url: String,
        /// Optional API key
        api_key: Option<String>,
    },
}

/// A connected transport handle
pub struct TransportHandle {
    /// Underlying transport kind
    kind: TransportKind,
    /// HTTP client (shared)
    http_client: reqwest::Client,
    /// Request ID counter
    id_counter: std::sync::atomic::AtomicI64,
}

enum TransportKind {
    Stdio {
        stdin: tokio::process::ChildStdin,
        stdout: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
        child: tokio::process::Child,
    },
    Sse {
        url: String,
    },
    Http {
        url: String,
        api_key: Option<String>,
    },
}

impl TransportHandle {
    /// Graceful shutdown: close stdin (signalling EOF to the child) and
    /// wait up to 2 seconds for the process to exit before force-killing.
    pub async fn shutdown(&mut self) {
        if let TransportKind::Stdio { child, stdin, .. } = &mut self.kind {
            // Close stdin to signal EOF; many MCP servers exit on stdin close.
            let _ = stdin.shutdown().await;
            // Give the child a grace period to exit cleanly.
            match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                child.wait(),
            )
            .await
            {
                Ok(Ok(_status)) => {
                    tracing::debug!("MCP child exited gracefully");
                }
                Ok(Err(e)) => {
                    tracing::warn!("MCP child wait error: {}", e);
                    let _ = child.start_kill();
                }
                Err(_) => {
                    tracing::warn!("MCP child did not exit within grace period; force-killing");
                    let _ = child.start_kill();
                }
            }
        }
    }
}

impl Drop for TransportHandle {
    fn drop(&mut self) {
        if let TransportKind::Stdio { child, .. } = &mut self.kind {
            // Safety net: if shutdown() was not called, force-kill immediately.
            let _ = child.start_kill();
        }
    }
}

/// Check whether a URL points to an internal / non-routable address.
fn is_internal_url(url: &str) -> bool {
    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return true,
    };

    let host = match parsed.host_str() {
        Some(h) => h.to_lowercase(),
        None => return true,
    };

    if host == "localhost" {
        return true;
    }

    if host.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    if host.starts_with("0x") || host.starts_with("0X") {
        return true;
    }
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') && host.starts_with('0') && host.len() > 1 && host != "0.0.0.0" {
        return true;
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let blocked = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local()
                    || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
                    || v6.is_unicast_link_local() || v6.is_multicast() {
                    return true;
                }
                if let Some(v4) = v6.to_ipv4_mapped() {
                    if v4.is_loopback() || v4.is_private() || v4.is_link_local()
                        || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                        return true;
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
                        return true;
                    }
                }
                false
            }
        };
        if blocked {
            return true;
        }
    }

    if host.starts_with("127.") || host.starts_with("0.") || host.starts_with("10.")
        || host.starts_with("192.168.") || host.starts_with("169.254.")
        || host == "[::1]" || host.starts_with("[::ffff:")
        || host.starts_with("[fc") || host.starts_with("[fd")
        || host.starts_with("[fe80:") || host.starts_with("[ff")
    {
        return true;
    }

    false
}

impl McpTransport {
    /// Connect and return a handle for sending/receiving JSON-RPC messages
    pub async fn connect(&self) -> anyhow::Result<TransportHandle> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let kind = match self {
            McpTransport::Stdio { command, args } => {
                if !std::path::Path::new(command).is_absolute() {
                    return Err(anyhow::anyhow!(
                        "MCP stdio command must be an absolute path, got: {}", command
                    ));
                }
                match std::fs::symlink_metadata(command) {
                    Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {}
                    _ => {
                        return Err(anyhow::anyhow!(
                            "MCP stdio command does not exist or is not a regular file: {}", command
                        ));
                    }
                }
                // Verify the command is in a trusted system directory.
                // The absolute-path and symlink checks above already prevent most
                // impersonation attacks; the prefix check is the final guard.
                let trusted_prefixes = ["/usr/bin/", "/usr/local/bin/", "/bin/", "/opt/homebrew/bin/"];
                if !trusted_prefixes.iter().any(|p| command.starts_with(p)) {
                    return Err(anyhow::anyhow!(
                        "MCP stdio command must be in a trusted system directory: {}", command
                    ));
                }
                let invalid_chars = [';', '|', '&', '$', '`', '<', '>', '(', ')', '{', '}', '*', '?', '[', ']', '\\', '\'', '"'];
                if command.is_empty() || invalid_chars.iter().any(|c| command.contains(*c)) {
                    return Err(anyhow::anyhow!(
                        "MCP stdio command contains invalid characters"
                    ));
                }
                for arg in args {
                    if invalid_chars.iter().any(|c| arg.contains(*c)) {
                        return Err(anyhow::anyhow!(
                            "MCP stdio argument contains invalid characters"
                        ));
                    }
                    if arg.starts_with('-') {
                        return Err(anyhow::anyhow!(
                            "MCP stdio arguments starting with '-' are not allowed: {}", arg
                        ));
                    }
                }
                debug!("Spawning MCP stdio transport: {} {:?}", command, args);
                let mut child = tokio::process::Command::new(command)
                    .args(args)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .spawn()?;

                let stdin = child.stdin.take().ok_or_else(|| {
                    anyhow::anyhow!("Failed to open child stdin")
                })?;
                let stdout = child.stdout.take().ok_or_else(|| {
                    anyhow::anyhow!("Failed to open child stdout")
                })?;
                let reader = BufReader::new(stdout);
                TransportKind::Stdio {
                    stdin,
                    stdout: reader.lines(),
                    child,
                }
            }
            McpTransport::Sse { url } => {
                debug!("Connecting MCP SSE transport: {}", url);
                if is_internal_url(url) {
                    return Err(anyhow::anyhow!(
                        "MCP SSE URL points to an internal address: {}", url
                    ));
                }
                TransportKind::Sse { url: url.clone() }
            }
            McpTransport::Http { url, api_key } => {
                debug!("Connecting MCP HTTP transport: {}", url);
                if is_internal_url(url) {
                    return Err(anyhow::anyhow!(
                        "MCP HTTP URL points to an internal address: {}", url
                    ));
                }
                TransportKind::Http {
                    url: url.clone(),
                    api_key: api_key.clone(),
                }
            }
        };

        Ok(TransportHandle {
            kind,
            http_client,
            id_counter: std::sync::atomic::AtomicI64::new(1),
        })
    }
}

impl TransportHandle {
    /// Send a JSON-RPC request and await the response
    pub async fn request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        let id = self
            .id_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(crate::types::RequestId::Number(id)),
            method: method.to_string(),
            params,
        };

        trace!("MCP -> {}: {:?}", method, req);

        match &mut self.kind {
            TransportKind::Stdio { stdin, stdout, .. } => {
                let payload = serde_json::to_string(&req)?;
                let line = format!("{}\n", payload);
                stdin.write_all(line.as_bytes()).await?;
                stdin.flush().await?;

                let line = stdout
                    .next_line()
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("MCP stdio stream closed"))?;

                const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
                if line.len() > MAX_RESPONSE_SIZE {
                    return Err(anyhow::anyhow!("MCP response too large"));
                }
                trace!("MCP <- {}", line);
                let resp: JsonRpcResponse = serde_json::from_str(&line)?;
                Self::extract_result(resp)
            }
            TransportKind::Http { url, api_key } => {
                let mut request = self.http_client.post(&**url).json(&req);
                if let Some(key) = api_key {
                    request = request.header("Authorization", format!("Bearer {}", key));
                }
                let resp = request.send().await?;
                let status = resp.status();
                const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
                if let Some(len) = resp.content_length() {
                    if len as usize > MAX_RESPONSE_SIZE {
                        return Err(anyhow::anyhow!("MCP response too large"));
                    }
                }
                let body = resp.text().await?;
                if body.len() > MAX_RESPONSE_SIZE {
                    return Err(anyhow::anyhow!("MCP response too large"));
                }
                if !status.is_success() {
                    return Err(anyhow::anyhow!("HTTP {}: {}", status, body));
                }
                trace!("MCP <- {}", body);
                let resp: JsonRpcResponse = serde_json::from_str(&body)?;
                Self::extract_result(resp)
            }
            TransportKind::Sse { url } => {
                // For SSE, we POST to the messages endpoint
                let messages_url = format!("{}/messages", url.trim_end_matches('/'));
                let request = self.http_client.post(&messages_url).json(&req);
                let resp = request.send().await?;
                let status = resp.status();
                const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
                if let Some(len) = resp.content_length() {
                    if len as usize > MAX_RESPONSE_SIZE {
                        return Err(anyhow::anyhow!("MCP response too large"));
                    }
                }
                let body = resp.text().await?;
                if body.len() > MAX_RESPONSE_SIZE {
                    return Err(anyhow::anyhow!("MCP response too large"));
                }
                if !status.is_success() {
                    return Err(anyhow::anyhow!("HTTP {}: {}", status, body));
                }
                trace!("MCP <- {}", body);
                let resp: JsonRpcResponse = serde_json::from_str(&body)?;
                Self::extract_result(resp)
            }
        }
    }

    /// Send a notification (no response expected)
    pub async fn notify(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: method.to_string(),
            params,
        };

        match &mut self.kind {
            TransportKind::Stdio { stdin, .. } => {
                let payload = serde_json::to_string(&req)?;
                let line = format!("{}\n", payload);
                stdin.write_all(line.as_bytes()).await?;
                stdin.flush().await?;
                Ok(())
            }
            TransportKind::Http { url, api_key } => {
                let mut request = self.http_client.post(&**url).json(&req);
                if let Some(key) = api_key {
                    request = request.header("Authorization", format!("Bearer {}", key));
                }
                let _resp = request.send().await?;
                Ok(())
            }
            TransportKind::Sse { url } => {
                let messages_url = format!("{}/messages", url.trim_end_matches('/'));
                let _resp = self.http_client.post(&messages_url).json(&req).send().await?;
                Ok(())
            }
        }
    }

    fn extract_result(resp: JsonRpcResponse) -> anyhow::Result<serde_json::Value> {
        if let Some(err) = resp.error {
            let data_str = err.data.as_ref().map(|d| d.to_string()).unwrap_or_default();
            if data_str.is_empty() {
                Err(anyhow::anyhow!("JSON-RPC error {}: {}", err.code, err.message))
            } else {
                Err(anyhow::anyhow!("JSON-RPC error {}: {} — {}", err.code, err.message, data_str))
            }
        } else {
            resp.result.ok_or_else(|| anyhow::anyhow!("Empty JSON-RPC response"))
        }
    }
}
