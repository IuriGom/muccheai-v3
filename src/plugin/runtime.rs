//! Plugin WASM runtime using wasmtime.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use wasmtime::{Engine, Linker, Module, Store, TypedFunc};

use super::manifest::{PluginManifest, PluginRole};

pub struct PluginRuntime {
    engine: Engine,
    module_cache: std::sync::Mutex<HashMap<PathBuf, Module>>,
    /// Plugin name -> (request_count, bytes_transferred)
    http_counters: Option<Arc<std::sync::Mutex<HashMap<String, (u64, u64)>>>>,
}

impl PluginRuntime {
    pub fn new() -> Self {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        Self {
            engine: Engine::new(&config).unwrap_or_else(|_| Engine::default()),
            module_cache: std::sync::Mutex::new(HashMap::new()),
            http_counters: None,
        }
    }

    pub fn with_counters(counters: Arc<std::sync::Mutex<HashMap<String, (u64, u64)>>>) -> Self {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        Self {
            engine: Engine::new(&config).unwrap_or_else(|_| Engine::default()),
            module_cache: std::sync::Mutex::new(HashMap::new()),
            http_counters: Some(counters),
        }
    }

    /// Execute a plugin with the given input JSON.
    /// Returns the output JSON string.
    ///
    /// **Important:** This function performs blocking I/O and WASM compilation.
    /// Callers from async context MUST wrap this in `tokio::task::spawn_blocking`.
    pub fn execute(
        &self,
        wasm_path: &Path,
        manifest: &PluginManifest,
        wasm_hash: &str,
        role: PluginRole,
        input_json: &str,
    ) -> anyhow::Result<String> {
        let module = {
            let mut cache = self.module_cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(m) = cache.get(wasm_path) {
                m.clone()
            } else {
                let m = Module::from_file(&self.engine, wasm_path)?;
                cache.insert(wasm_path.to_path_buf(), m.clone());
                m
            }
        };

        let mut linker: Linker<PluginState> = Linker::new(&self.engine);
        let mut wasi_builder = wasmtime_wasi::WasiCtxBuilder::new();
        wasi_builder.inherit_stdout().inherit_stderr();

        // Enforce env capability.
        match manifest.capabilities.env.as_str() {
            "none" => {
                // Default WasiCtxBuilder has no env vars.
            }
            "readonly" => {
                // Only expose a curated allowlist of safe env vars.
                let allowed = ["LANG", "LC_ALL", "TZ", "PATH"];
                let vars: Vec<(String, String)> = allowed
                    .iter()
                    .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
                    .collect();
                wasi_builder.envs(&vars);
            }
            "all" | _ => {
                wasi_builder.inherit_env();
            }
        }

        // Restrict filesystem access to a plugin-specific sandbox directory.
        if manifest.capabilities.filesystem != "none" {
            let safe_name = manifest.plugin.name
                .replace('/', "_")
                .replace("\\", "_")
                .replace("..", "_");
            let sandbox_dir = dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".muccheai")
                .join("plugin-data")
                .join(format!("{}-{}", safe_name, &wasm_hash[..8.min(wasm_hash.len())]));
            let _ = std::fs::create_dir_all(&sandbox_dir);
            let (dir_perms, file_perms) = if manifest.capabilities.filesystem == "readonly" {
                (wasmtime_wasi::DirPerms::READ, wasmtime_wasi::FilePerms::READ)
            } else {
                (
                    wasmtime_wasi::DirPerms::READ | wasmtime_wasi::DirPerms::MUTATE,
                    wasmtime_wasi::FilePerms::READ | wasmtime_wasi::FilePerms::WRITE,
                )
            };
            let _ = wasi_builder.preopened_dir(
                &sandbox_dir,
                "/data",
                dir_perms,
                file_perms,
            );
        }

        let wasi = wasi_builder.build_p1();

        wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;

        // Add capability-gated host functions
        Self::add_host_functions(&mut linker, manifest, wasm_hash)?;

        // Build resource limits before creating the store.
        let mut limits_builder = wasmtime::StoreLimitsBuilder::new();
        if let Some(mem_mb) = manifest.capabilities.max_memory_mb {
            limits_builder = limits_builder.memory_size(mem_mb.saturating_mul(1024 * 1024) as usize);
        }
        let limits = limits_builder.build();

        let state = PluginState {
            wasi,
            http_hosts: manifest.capabilities.http_hosts.clone(),
            http_client: if role.may_network() {
                reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .ok()
            } else {
                None
            },
            log_buffer: Vec::new(),
            http_counters: self.http_counters.clone(),
            plugin_name: manifest.plugin.name.clone(),
            role,
            limits,
        };

        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);

        // Enforce CPU limits via fuel (each WASM instruction consumes 1 fuel).
        if let Some(cpu_pct) = manifest.capabilities.max_cpu_percent {
            if cpu_pct > 0 && cpu_pct <= 100 {
                let budget = (10_000_000u64).saturating_mul(cpu_pct as u64);
                store.set_fuel(budget).ok();
            }
        }

        let instance = linker.instantiate(&mut store, &module)?;

        // Try to get the `process` export
        let process: TypedFunc<(i32, i32, i32, i32), i32> = instance
            .get_typed_func::<(i32, i32, i32, i32), i32>(&mut store, "process")
            .map_err(|_| anyhow::anyhow!("Plugin does not export 'process' function"))?;

        // Allocate memory for input
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow::anyhow!("Plugin does not export 'memory'"))?;

        let input_bytes = input_json.as_bytes();
        let out_len = 8192;
        let input_ptr = 1024;
        let output_ptr = input_ptr + input_bytes.len() + 1024;

        // Bounds check against WASM memory size to prevent runtime crash
        let mem_size = memory.data_size(&store);
        if input_ptr + input_bytes.len() > mem_size {
            return Err(anyhow::anyhow!("Plugin input ({} bytes) exceeds WASM memory ({} bytes)", input_bytes.len(), mem_size));
        }
        if output_ptr + out_len > mem_size {
            return Err(anyhow::anyhow!("Plugin output buffer would exceed WASM memory ({} bytes)", mem_size));
        }

        memory.write(&mut store, input_ptr, input_bytes)?;

        let ret = process.call(&mut store, (input_ptr as i32, input_bytes.len() as i32, output_ptr as i32, out_len as i32))?;

        if ret < 0 {
            return Err(anyhow::anyhow!("Plugin execution failed with code {}", ret));
        }

        const MAX_PLUGIN_OUTPUT: usize = 1024 * 1024; // 1 MiB
        let len = ret as usize;
        if len > MAX_PLUGIN_OUTPUT {
            return Err(anyhow::anyhow!("Plugin returned output length {} exceeding maximum {}", len, MAX_PLUGIN_OUTPUT));
        }
        let mut buf = vec![0u8; len];
        memory.read(&store, output_ptr, &mut buf)?;
        let output = String::from_utf8_lossy(&buf).to_string();

        // Print captured logs
        let logs = std::mem::take(&mut store.data_mut().log_buffer);
        for log in logs {
            tracing::info!(target: "plugin", "{}", log);
        }

        Ok(output)
    }

    fn add_host_functions(linker: &mut Linker<PluginState>, manifest: &PluginManifest, wasm_hash: &str) -> anyhow::Result<()> {
        let allowed_hosts: std::sync::Arc<Vec<String>> = std::sync::Arc::new(manifest.capabilities.http_hosts.clone());
        let max_body_size = manifest.capabilities.max_body_size;
        let rate_limit = manifest.capabilities.max_requests_per_minute;
        let plugin_hash = wasm_hash.to_string();
        let plugin_name = manifest.plugin.name.clone();

        // Simple per-plugin rate limiter: token bucket refilled every 60s.
        let rate_bucket: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, u32)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        // host_http_get(url_ptr, url_len, out_ptr, out_len) -> i32
        linker.func_wrap(
            "env",
            "host_http_get",
            move |mut caller: wasmtime::Caller<'_, PluginState>, url_ptr: i32, url_len: i32, out_ptr: i32, out_len: i32| -> i32 {
                let mem = match caller.get_export("memory") {
                    Some(wasmtime::Extern::Memory(m)) => m,
                    _ => return -1,
                };
                let mut url_buf = vec![0u8; url_len as usize];
                if mem.read(&caller, url_ptr as usize, &mut url_buf).is_err() {
                    return -1;
                }
                let url = match String::from_utf8(url_buf) {
                    Ok(s) => s,
                    Err(_) => return -1,
                };

                // Validate URL structure and SSRF
                let parsed = match url::Url::parse(&url) {
                    Ok(u) => u,
                    Err(_) => return -1,
                };
                // Enforce HTTPS only
                if parsed.scheme() != "https" {
                    tracing::warn!(target: "plugin", "HTTP request blocked: non-HTTPS URL {}", url);
                    return -1;
                }
                // DNS rebinding guard: resolve hostname and block internal IPs.
                if let Some(host_str) = parsed.host_str() {
                    use std::net::ToSocketAddrs;
                    if let Ok(addrs) = (host_str, 0u16).to_socket_addrs() {
                        for addr in addrs {
                            if is_internal_ip(addr.ip()) {
                                tracing::warn!(target: "plugin", "HTTP request blocked: DNS rebinding to internal IP {} for {}", addr.ip(), url);
                                return -1;
                            }
                        }
                    }
                }
                let host = parsed.host_str().unwrap_or("").to_string();
                if !allowed_hosts.iter().any(|h| h == &host) {
                    tracing::warn!(target: "plugin", "HTTP request to {} blocked by capability manifest", host);
                    return -1;
                }
                // Reject userinfo tricks (e.g. http://example.com@127.0.0.1/)
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    tracing::warn!(target: "plugin", "HTTP request with credentials blocked: {}", url);
                    return -1;
                }
                // Block literal internal IPs; rely on allowed_hosts for hostnames
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    let blocked = match ip {
                        std::net::IpAddr::V4(v4) => {
                            v4.is_loopback() || v4.is_private() || v4.is_link_local()
                                || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()
                                || v4.is_documentation()
                        }
                        std::net::IpAddr::V6(v6) => {
                            v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
                                || v6.is_unicast_link_local() || v6.is_multicast()
                        }
                    };
                    if blocked {
                        tracing::warn!(target: "plugin", "HTTP request to literal internal IP {} blocked", ip);
                        return -1;
                    }
                }

                let state = caller.data();
                if !state.role.may_network() {
                    tracing::warn!(target: "plugin", "HTTP blocked: plugin '{}' role '{:?}' has no network access", state.plugin_name, state.role);
                    return -1;
                }

                // Rate limit check (keyed by wasm_hash so renamed plugins don't steal quota)
                {
                    let mut bucket = rate_bucket.lock().unwrap_or_else(|e| e.into_inner());
                    let (last, tokens) = bucket.entry(plugin_hash.clone()).or_insert((std::time::Instant::now(), rate_limit));
                    let elapsed = last.elapsed().as_secs() as u32;
                    let refill = elapsed.saturating_mul(rate_limit) / 60;
                    if refill > 0 {
                        *tokens = (*tokens + refill).min(rate_limit);
                        *last = std::time::Instant::now();
                    }
                    if *tokens == 0 {
                        tracing::warn!(target: "plugin", "HTTP rate limit exceeded for plugin '{}'", plugin_name);
                        return -1;
                    }
                    *tokens -= 1;
                }

                let client = match &state.http_client {
                    Some(c) => c.clone(),
                    None => return -1,
                };

                match client.get(&url).send() {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = match resp.text() {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::warn!(target: "plugin", "HTTP response encoding error: {}", e);
                                String::new()
                            }
                        };
                        // Body size cap
                        if body.len() > max_body_size as usize {
                            tracing::warn!(target: "plugin", "HTTP response body too large for plugin '{}' ({} > {})", plugin_name, body.len(), max_body_size);
                            return -1;
                        }
                        // Update audit counters
                        if let Some(ref counters) = caller.data().http_counters {
                            if let Ok(mut map) = counters.lock() {
                                let name = caller.data().plugin_name.clone();
                                let entry = map.entry(name).or_insert((0, 0));
                                entry.0 += 1;
                                entry.1 += body.len() as u64;
                            }
                        }
                        let json = serde_json::json!({"status": status, "body": body});
                        let bytes = json.to_string().into_bytes();
                        let to_write = std::cmp::min(bytes.len(), out_len as usize);
                        let _ = mem.write(&mut caller, out_ptr as usize, &bytes[..to_write]);
                        to_write as i32
                    }
                    Err(e) => {
                        tracing::warn!(target: "plugin", "HTTP request failed: {}", e);
                        -1
                    }
                }
            },
        )?;

        // host_log(msg_ptr, msg_len)
        linker.func_wrap(
            "env",
            "host_log",
            |mut caller: wasmtime::Caller<'_, PluginState>, msg_ptr: i32, msg_len: i32| {
                let mem = match caller.get_export("memory") {
                    Some(wasmtime::Extern::Memory(m)) => m,
                    _ => return,
                };
                let mut buf = vec![0u8; msg_len as usize];
                if mem.read(&caller, msg_ptr as usize, &mut buf).is_err() {
                    return;
                }
                let msg = String::from_utf8_lossy(&buf).to_string();
                caller.data_mut().log_buffer.push(msg);
            },
        )?;

        Ok(())
    }
}

struct PluginState {
    wasi: wasmtime_wasi::preview1::WasiP1Ctx,
    http_hosts: Vec<String>,
    http_client: Option<reqwest::blocking::Client>,
    log_buffer: Vec<String>,
    http_counters: Option<Arc<std::sync::Mutex<HashMap<String, (u64, u64)>>>>,
    plugin_name: String,
    role: PluginRole,
    limits: wasmtime::StoreLimits,
}

fn is_internal_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
                || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()
                || v4.is_documentation()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
                || v6.is_unicast_link_local() || v6.is_multicast()
        }
    }
}
