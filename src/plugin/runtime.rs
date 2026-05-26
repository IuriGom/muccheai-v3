//! Plugin WASM runtime using wasmtime.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use wasmtime::{Engine, Linker, Module, Store, TypedFunc};

use super::manifest::PluginManifest;

pub struct PluginRuntime {
    engine: Engine,
    module_cache: std::sync::Mutex<HashMap<PathBuf, Module>>,
}

impl PluginRuntime {
    pub fn new() -> Self {
        Self {
            engine: Engine::default(),
            module_cache: std::sync::Mutex::new(HashMap::new()),
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
        input_json: &str,
    ) -> anyhow::Result<String> {
        let module = {
            let mut cache = self.module_cache.lock().unwrap();
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

        // Restrict filesystem access to a plugin-specific sandbox directory.
        if manifest.capabilities.filesystem != "none" {
            let sandbox_dir = dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".muccheai")
                .join("plugin-data")
                .join(format!("{}-{}", &manifest.plugin.name, &wasm_hash[..8.min(wasm_hash.len())]));
            let _ = std::fs::create_dir_all(&sandbox_dir);
            let _ = wasi_builder.preopened_dir(
                &sandbox_dir,
                "/data",
                wasmtime_wasi::DirPerms::READ | wasmtime_wasi::DirPerms::MUTATE,
                wasmtime_wasi::FilePerms::READ | wasmtime_wasi::FilePerms::WRITE,
            );
        }

        let wasi = wasi_builder.build_p1();

        wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;

        // Add capability-gated host functions
        Self::add_host_functions(&mut linker, manifest)?;

        let mut state = PluginState {
            wasi,
            http_hosts: manifest.capabilities.http_hosts.clone(),
            http_client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .ok(),
            log_buffer: Vec::new(),
        };

        let mut store = Store::new(&self.engine, state);

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
        // Simple allocation: input at offset 0, output at offset after input (aligned)
        let input_ptr = 1024;
        let output_ptr = input_ptr + input_bytes.len() + 1024;

        memory.write(&mut store, input_ptr, input_bytes)?;

        let ret = process.call(&mut store, (input_ptr as i32, input_bytes.len() as i32, output_ptr as i32, out_len as i32))?;

        if ret < 0 {
            return Err(anyhow::anyhow!("Plugin execution failed with code {}", ret));
        }

        let len = ret as usize;
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

    fn add_host_functions(linker: &mut Linker<PluginState>, manifest: &PluginManifest) -> anyhow::Result<()> {
        let allowed_hosts: std::sync::Arc<Vec<String>> = std::sync::Arc::new(manifest.capabilities.http_hosts.clone());

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

                // Validate host against allowlist
                let host = match url::Url::parse(&url) {
                    Ok(u) => u.host_str().unwrap_or("").to_string(),
                    Err(_) => return -1,
                };
                if !allowed_hosts.iter().any(|h| h == &host) {
                    tracing::warn!(target: "plugin", "HTTP request to {} blocked by capability manifest", host);
                    return -1;
                }

                let client = match &caller.data().http_client {
                    Some(c) => c.clone(),
                    None => return -1,
                };

                match client.get(&url).send() {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.text().unwrap_or_default();
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
}
