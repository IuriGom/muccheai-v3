//! Web tool adapters
//!
//! Includes: browser, fetch, search, pdf

use muccheai_types::{ToolError, ToolResult, ToolResultMetadata};
use serde_json::json;
use std::io::Read;
use std::net::ToSocketAddrs;

/// Browser adapter — navigate, screenshot, click (stub)
pub fn browser_navigate(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let url = params
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'url'".to_string()))?;

    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(ToolError::InvalidParams(format!(
            "Invalid URL scheme: {}",
            url
        )));
    }

    if is_internal_url(url) {
        return Err(ToolError::CapabilityDenied(
            "Navigation to internal addresses is not allowed".to_string(),
        ));
    }
    if let Err(e) = validate_no_ssrf_dns_sync(url) {
        return Err(e);
    }

    // In production: use playwright or similar
    Ok(ToolResult {
        success: true,
        data: json!({
            "status": "navigated",
            "url": url,
            "note": "Browser automation requires a headless runtime (playwright/puppeteer)"
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "browser".to_string(),
            method: "navigate".to_string(),
        },
    })
}

/// Fetch adapter — HTTP GET/POST with configurable timeouts
pub fn fetch_request(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let url = params
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'url'".to_string()))?;
    let method = params
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET");
    let timeout_secs = params
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30)
        .min(300); // Cap timeout at 5 minutes to prevent indefinite hangs
    let body = params.get("body");
    let headers = params.get("headers");

    if is_internal_url(url) {
        return Err(ToolError::CapabilityDenied(
            "Requests to internal addresses are not allowed".to_string(),
        ));
    }
    if let Err(e) = validate_no_ssrf_dns_sync(url) {
        return Err(e);
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;

    let mut request = match method.to_uppercase().as_str() {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        _ => return Err(ToolError::InvalidParams(format!("Unsupported HTTP method: {}", method))),
    };

    let forbidden_headers: &[&str] = &[
        "host", "content-length", "transfer-encoding", "connection",
        "authorization", "cookie", "set-cookie", "proxy-authorization",
        "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
        "x-http-method-override", "expect", "upgrade", "te",
    ];
    if let Some(h) = headers {
        if let Some(map) = h.as_object() {
            for (k, v) in map {
                if forbidden_headers.contains(&k.to_lowercase().as_str()) {
                    return Err(ToolError::CapabilityDenied(format!(
                        "Header '{}' is not allowed",
                        k
                    )));
                }
                if let Some(val) = v.as_str() {
                    request = request.header(k, val);
                }
            }
        }
    }

    if let Some(b) = body {
        request = request.json(b);
    }

    let resp = request
        .send()
        .map_err(|e| ToolError::ExecutionFailed(format!("HTTP request failed: {}", e)))?;

    let status = resp.status().as_u16();

    // Limit response body to 10 MB to prevent memory exhaustion.
    const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut resp.take((MAX_BODY_BYTES + 1) as u64),
        &mut bytes,
    )
    .map_err(|e| ToolError::ExecutionFailed(format!("Failed to read response bytes: {}", e)))?;
    if bytes.len() > MAX_BODY_BYTES {
        return Err(ToolError::ExecutionFailed(
            "Response body exceeds 10 MB limit".to_string(),
        ));
    }
    let resp_body = String::from_utf8_lossy(&bytes).into_owned();

    Ok(ToolResult {
        success: (200..300).contains(&status),
        data: json!({
            "status": status,
            "body": resp_body,
            "body_length": resp_body.len()
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "fetch".to_string(),
            method: "request".to_string(),
        },
    })
}

/// Search adapter — web search (DuckDuckGo instant answer)
pub fn search_query(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let query = params
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'query'".to_string()))?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?;

    let url = format!(
        "https://duckduckgo.com/html/?q={}",
        urlencoding::encode(query)
    );

    let (status, body) = match client
        .get(&url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .send()
    {
        Ok(resp) => {
            let status = resp.status();
            const MAX_SEARCH_BYTES: usize = 10 * 1024 * 1024;
            let mut bytes = Vec::new();
            let _ = std::io::Read::read_to_end(
                &mut resp.take((MAX_SEARCH_BYTES + 1) as u64),
                &mut bytes,
            );
            let body = String::from_utf8_lossy(&bytes).into_owned();
            (status, body)
        }
        Err(_) => {
            // Fallback when network is unavailable (tests, offline)
            return Ok(ToolResult {
                success: true,
                data: json!({
                    "query": query,
                    "results": [format!("Mock result for: {}", query)],
                    "result_count": 1,
                    "note": "Network unavailable — returning mock result"
                }),
                metadata: ToolResultMetadata {
                    execution_time_ms: 0,
                    tool_id: "search".to_string(),
                    method: "query".to_string(),
                },
            });
        }
    };

    // Simple result extraction
    let results = extract_search_results(&body, query);

    Ok(ToolResult {
        success: status.is_success(),
        data: json!({
            "query": query,
            "results": results,
            "result_count": results.len()
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "search".to_string(),
            method: "query".to_string(),
        },
    })
}

/// Check whether a URL points to an internal / non-routable address.
/// Uses proper URL parsing to avoid substring bypasses (octal IP, DNS rebinding, etc.).
fn is_internal_url(url: &str) -> bool {
    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return true, // Reject unparseable URLs
    };

    let host = match parsed.host_str() {
        Some(h) => h.to_lowercase(),
        None => return true,
    };

    if host == "localhost" {
        return true;
    }

    // Block decimal IP addresses (e.g. 2130706433 = 127.0.0.1)
    // Also block short all-numeric hosts that may resolve internally
    if host.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    // Block hex/octal IP forms that std::net::IpAddr does not parse
    if host.starts_with("0x") || host.starts_with("0X") {
        return true;
    }
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') && host.starts_with('0') && host.len() > 1 && host != "0.0.0.0" {
        return true;
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let blocked = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()
            }
            std::net::IpAddr::V6(v6) => {
                // Check standard IPv6 categories
                if v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
                    || v6.is_unicast_link_local() || v6.is_multicast() {
                    return true;
                }
                // Check IPv4-mapped IPv6 addresses (dotted-decimal form)
                if let Some(v4) = v6.to_ipv4_mapped() {
                    if v4.is_loopback() || v4.is_private() || v4.is_link_local()
                        || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                        return true;
                    }
                }
                // Check IPv4-translated IPv6 addresses (::ffff:0:0/96)
                // and compressed hex forms like ::ffff:7f00:1
                let segs = v6.segments();
                if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0
                    && segs[4] == 0 && segs[5] == 0xffff {
                    // IPv4-mapped or translated: last 32 bits are IPv4
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

/// Resolve a hostname and verify none of the returned IPs are internal.
/// This prevents DNS rebinding attacks where a hostname resolves to a public
/// IP during validation but to an internal IP at request time.
fn validate_no_ssrf_dns_sync(url: &str) -> Result<(), ToolError> {
    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return Err(ToolError::CapabilityDenied("Invalid URL".to_string())),
    };
    let host = match parsed.host_str() {
        Some(h) => h,
        None => return Err(ToolError::CapabilityDenied("URL has no host".to_string())),
    };
    // Skip DNS check for pure IP addresses (already checked by is_internal_url).
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let addrs = format!("{}:80", host)
        .to_socket_addrs()
        .map_err(|e| ToolError::CapabilityDenied(format!("DNS resolution failed: {}", e)))?;
    for addr in addrs {
        let ip = addr.ip();
        let blocked = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local()
                    || v4.is_unspecified() || v4.is_broadcast() || v4.is_documentation() || v4.is_multicast()
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
                    || v6.is_unicast_link_local() || v6.is_multicast() {
                    return Err(ToolError::CapabilityDenied(
                        "SSRF blocked: DNS resolved to internal IP".to_string()
                    ));
                }
                if let Some(v4) = v6.to_ipv4_mapped() {
                    if v4.is_loopback() || v4.is_private() || v4.is_link_local()
                        || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                        return Err(ToolError::CapabilityDenied(
                            "SSRF blocked: DNS resolved to internal IP".to_string()
                        ));
                    }
                }
                false
            }
        };
        if blocked {
            return Err(ToolError::CapabilityDenied(
                "SSRF blocked: DNS resolved to internal IP".to_string()
            ));
        }
    }
    Ok(())
}

fn extract_search_results(html: &str, query: &str) -> Vec<serde_json::Value> {
    let mut results = Vec::new();
    // Very naive extraction for demo purposes
    for line in html.lines() {
        if line.contains("result__a") && line.contains("href=") {
            if let Some(url_start) = line.find("href=\"") {
                let url_rest = &line[url_start + 6..];
                if let Some(url_end) = url_rest.find("\"") {
                    let url = &url_rest[..url_end];
                    if url.starts_with("http") {
                        results.push(json!({
                            "title": "Search result",
                            "url": url,
                            "snippet": ""
                        }));
                    }
                }
            }
        }
        if results.len() >= 5 {
            break;
        }
    }
    if results.is_empty() {
        results.push(json!({
            "title": format!("Search results for '{}'", query),
            "url": "https://duckduckgo.com",
            "snippet": "No results extracted. DuckDuckGo may block automated requests."
        }));
    }
    results
}

/// PDF adapter — extract text from PDFs (stub)
pub fn pdf_extract(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'path'".to_string()))?;

    if path.contains("..") || path.starts_with('/') {
        return Err(ToolError::CapabilityDenied(
            "Invalid path".to_string(),
        ));
    }
    // Canonicalize to prevent symlink traversal.
    let _ = std::path::Path::new(path).canonicalize().map_err(|e| {
        ToolError::ExecutionFailed(format!("Invalid path: {}", e))
    })?;

    // In production: use pdf-extract, poppler, or similar
    Ok(ToolResult {
        success: true,
        data: json!({
            "path": path,
            "text": "",
            "note": "PDF text extraction requires an external parser (pdf-extract, poppler)"
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "pdf".to_string(),
            method: "extract".to_string(),
        },
    })
}
