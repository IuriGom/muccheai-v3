//! Weather Plugin — MuccheAI Example
//!
//! Build:
//!   rustup target add wasm32-wasi
//!   cargo build --target wasm32-wasi --release
//!
//! Install:
//!   muccheai plugin install ./
//!
//! Test in chat:
//!   "What's the weather in London?"

use serde::{Deserialize, Serialize};

// ── Input from the host ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct PluginInput {
    /// The full user message that triggered this plugin.
    message: String,
    /// Active session ID (plugins can use it for their own storage keys).
    session_id: String,
    /// The user who sent the message.
    owner_hash: String,
}

// ── Output back to the host ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct PluginOutput {
    /// Short label shown in the UI (e.g. "Weather: London").
    label: String,
    /// The actual data to inject into the LLM context.
    content: String,
    /// Optional: error message if something went wrong.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ── Host call ABI ────────────────────────────────────────────────────────────
//
// The runtime provides these extern functions. They are capability-gated:
// if plugin.toml does not list a host in http_hosts, the call is rejected.

extern "C" {
    /// Make an HTTP GET request. Returns a JSON blob: {"status":200,"body":"..."}
    fn host_http_get(url_ptr: *const u8, url_len: usize, out_ptr: *mut u8, out_len: usize) -> i32;

    /// Write to the plugin log (visible in ~/.muccheai/logs/plugins/weather.log)
    fn host_log(msg_ptr: *const u8, msg_len: usize);
}

fn log(msg: &str) {
    unsafe { host_log(msg.as_ptr(), msg.len()) };
}

fn http_get(url: &str) -> Result<String, String> {
    let mut buf = vec![0u8; 8192];
    let ret = unsafe { host_http_get(url.as_ptr(), url.len(), buf.as_mut_ptr(), buf.len()) };
    if ret < 0 {
        return Err(format!("HTTP request blocked or failed (code {})", ret));
    }
    let len = ret as usize;
    let json = String::from_utf8_lossy(&buf[..len]);
    // The host returns {"status": N, "body": "..."}
    #[derive(Deserialize)]
    struct Resp {
        status: u16,
        body: String,
    }
    let resp: Resp = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    if resp.status != 200 {
        return Err(format!("HTTP {}: {}", resp.status, resp.body));
    }
    Ok(resp.body)
}

// ── Plugin logic ─────────────────────────────────────────────────────────────

/// Extract a city name from a message like "weather in London" or "London weather"
fn extract_city(msg: &str) -> Option<String> {
    let lower = msg.to_lowercase();
    let patterns = [
        "weather in ",
        "weather for ",
        "forecast for ",
        "temp in ",
        "temperature in ",
    ];
    for pat in &patterns {
        if let Some(pos) = lower.find(pat) {
            let start = pos + pat.len();
            let rest = &msg[start..];
            // Take until punctuation or end
            let city = rest
                .split(|c: char| c.is_ascii_punctuation() && c != '\'' && c != '-')
                .next()
                .unwrap_or(rest)
                .trim()
                .to_string();
            if !city.is_empty() {
                return Some(city);
            }
        }
    }
    // Fallback: try "<city> weather"
    if let Some(pos) = lower.find(" weather") {
        let city = msg[..pos].trim().to_string();
        if !city.is_empty() && city.len() < 40 {
            return Some(city);
        }
    }
    None
}

fn format_weather(city: &str, raw: &str) -> String {
    // wttr.in returns a multi-line text report. Summarise it.
    let lines: Vec<&str> = raw.lines().take(8).collect();
    format!(
        "Weather report for {}:\n{}\n[Source: wttr.in]",
        city,
        lines.join("\n")
    )
}

// ── Exported entry point ─────────────────────────────────────────────────────

/// Called by the host runtime. `input_ptr` points to a JSON `PluginInput`.
/// Writes a JSON `PluginOutput` back to the host-allocated `out_ptr` buffer.
/// Returns the number of bytes written, or a negative error code.
#[no_mangle]
pub extern "C" fn process(input_ptr: *const u8, input_len: usize, out_ptr: *mut u8, out_len: usize) -> i32 {
    // Decode input
    let input_bytes = unsafe { std::slice::from_raw_parts(input_ptr, input_len) };
    let input: PluginInput = match serde_json::from_slice(input_bytes) {
        Ok(i) => i,
        Err(e) => {
            let out = PluginOutput {
                label: "Weather".into(),
                content: String::new(),
                error: Some(format!("Bad input: {}", e)),
            };
            return write_output(out, out_ptr, out_len);
        }
    };

    log(&format!("Processing message: {}", input.message));

    let Some(city) = extract_city(&input.message) else {
        let out = PluginOutput {
            label: "Weather".into(),
            content: String::new(),
            error: Some("Could not determine city. Try: 'weather in London'".into()),
        };
        return write_output(out, out_ptr, out_len);
    };

    // Build URL. Note: wttr.in is in our http_hosts allowlist.
    let url = format!("https://wttr.in/{}?format=v2&lang=en", urlencoding::encode(&city));

    match http_get(&url) {
        Ok(body) => {
            let content = format_weather(&city, &body);
            log(&format!("Fetched weather for {}", city));
            let out = PluginOutput {
                label: format!("Weather: {}", city),
                content,
                error: None,
            };
            write_output(out, out_ptr, out_len)
        }
        Err(e) => {
            let out = PluginOutput {
                label: "Weather".into(),
                content: String::new(),
                error: Some(e),
            };
            write_output(out, out_ptr, out_len)
        }
    }
}

fn write_output(out: PluginOutput, ptr: *mut u8, max_len: usize) -> i32 {
    let json = serde_json::to_string(&out).unwrap_or_default();
    let bytes = json.as_bytes();
    if bytes.len() > max_len {
        return -2; // buffer too small
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
    }
    bytes.len() as i32
}
