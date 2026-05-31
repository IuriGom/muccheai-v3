# MuccheAI v3

A self-hosted, privacy-first AI assistant with multi-model fallback, per-user authentication, encrypted secrets, WebSocket chat, file uploads, structured memory, and a capability-sandboxed plugin system.

Built in Rust. No cloud lock-in. Your data stays on your machine.

---

## Table of Contents

- [What’s New in 3.2](#whats-new-in-32)
- [Features](#features)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [Duress PIN](#duress-pin)
- [Research Mode](#research-mode)
- [Plugin System](#plugin-system)
  - [How to Create a Plugin](#how-to-create-a-plugin)
  - [Plugin Security Model](#plugin-security-model)
- [Commands](#commands)
- [Configuration](#configuration)
- [Security](#security)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## What’s New in 3.2

| Feature | Description |
|---------|-------------|
| **Per-user auth** | Argon2id password hashing with per-user salts. No more single shared API key. |
| **Duress PIN** | A secondary PIN that creates a fake session and silently wipes your data on first use. |
| **Research mode** | When external (non-local) AI providers are active, the backend asks for confirmation before sending chat history. |
| **Encrypted config** | API keys and agent credentials are encrypted with AES-256-GCM. Master key is derived via Argon2id (optional password via `MUCCHEAI_KEY_PASSWORD`). |
| **Self-update** | `muccheai update` pulls the latest release and rebuilds automatically. |
| **File upload** | Drag-and-drop PDF, DOCX, and text files. Extracted content is injected into the chat context. |
| **Voice input** | Web Speech API in the frontend — click the microphone icon. |
| **Memory search** | Live fuzzy filtering of memories in the web UI. |
| **WebSocket chat** | Real-time streaming feel via `/api/chat/ws` with per-message auth re-validation. |
| **Plugin system** | WASM-based plugins with capability manifests. See [Plugin System](#plugin-system). |

---

## Features

- **Multi-model fallback** — If your primary AI agent fails, MuccheAI automatically tries every other configured agent until one responds.
- **Structured memory** — The LLM extracts facts, preferences, and tasks from conversations. You can view, search, and delete them.
- **MCP tool gateway** — Connect to Model Context Protocol servers (stdio or HTTP) to give the LLM access to external tools.
- **Rate limiting** — Per-IP rate limits (60 messages/minute) with trusted-proxy CIDR support.
- **CSRF protection** — All mutating API endpoints require a CSRF nonce obtained at login.
- **Session revocation** — Log out from any device; sessions are checked against a revocation list.
- **Owner isolation** — Every piece of data (memories, chat sessions, uploaded files) is tied to a user hash. Users cannot see each other’s data.

---

## Quick Start

### Prerequisites

- Rust 1.80+ (`rustup update stable`)
- `make` and `git`

### Install

```bash
git clone https://github.com/IuriGom/muccheai-v3.git
cd muccheai-v3
make install
```

This compiles in release mode (`strip = true`, `lto = true`) and runs `muccheai setup` if this is your first install.

### First Run (Setup Wizard)

```bash
muccheai setup
```

You will be guided through:

1. **System check** — verifies Rust version and connectivity.
2. **AI connection** — configure Ollama (local), OpenAI, Anthropic, or other providers.
3. **Local key password** *(optional)* — protect your encryption key with a password.
4. **Tools** — enable/disable MCP servers.
5. **Security preferences** — set your duress PIN.
6. **Vault** — create encrypted storage for users and memories.
7. **Persona** — choose a system prompt style.

After setup, start the server:

```bash
muccheai
```

Open `http://localhost:3000` in your browser. You will see a login modal.

### Default Credentials

If you are migrating from a version before v3.2, the setup wizard creates a user called **`admin`** whose password is your **legacy API key**.

To find it:

```bash
muccheai config reveal-key
```

You can then log in as `admin` / `<your-api-key>` and create new users from the web UI.

---

## Authentication

MuccheAI uses **session-based authentication** with Argon2id password hashing.

### Login Flow

1. `POST /api/login` → receives a Bearer token + CSRF token.
2. The frontend stores both in `localStorage`.
3. Every API call includes `Authorization: Bearer <token>`.
4. Mutating requests (`POST`, `PUT`, `DELETE`) also include `X-CSRF-Token: <csrf>`.
5. The backend validates the session, checks the CSRF nonce, and verifies the session has not been revoked.

### Registration

`POST /api/register` creates a new account. The duress PIN field is optional.

### Token Revocation

Clicking **Logout** hits `POST /api/logout`, which adds the token to a revocation list. Revoked tokens are rejected immediately, even before expiry.

---

## Duress PIN

A **duress PIN** is a fake password you can enter under coercion. It behaves like a normal login but triggers data destruction.

### How it works

1. You set a duress PIN during setup (or in Settings).
2. If someone forces you to log in, enter the duress PIN instead of your real password.
3. The session looks normal — the attacker sees an empty account with no data.
4. On the first authenticated request, **all memories and chat sessions for your owner hash are permanently deleted**.
5. Every subsequent data request returns empty results.

### Setting or changing your duress PIN

- During first-time setup, the wizard asks for it.
- After login, go to **Settings → Security → Duress PIN**.

> ⚠️ The duress PIN is **irreversible**. There is no confirmation dialog. Once entered, data is gone.

---

## Research Mode

When you enable the **Research** toggle in chat, MuccheAI may send your message (and recent chat history) to external AI providers (OpenAI, Anthropic, etc.) if your local Ollama instance cannot answer.

### Privacy protection

If any external provider is configured and active:

1. The backend returns `needs_confirmation` instead of sending data.
2. The frontend shows a browser `confirm()` dialog explaining exactly what will be sent and to whom.
3. Only if you click **OK** does the frontend resend with `research_confirmed: true`.

If you only use **Ollama** (local), research mode works without confirmation.

---

## Plugin System

MuccheAI v3 supports **WASM plugins** — small Rust programs that run inside a sandboxed runtime. There are two kinds:

| Type | Needs network? | Use cases |
|------|---------------|-----------|
| **Online plugins** | Yes (specific hosts only) | Weather, news, API lookups, web search |
| **Offline plugins** | No | Calculator, text formatter, regex tester, local note storage |

Offline plugins are **first-class citizens**. They work on air-gapped systems, consume no battery for radio, and have mathematically zero data exfiltration surface when `http_hosts = []` and `llm_callback = false`.

### How it works

1. You write a plugin in Rust.
2. You compile it to `wasm32-wasi`.
3. You write a `plugin.toml` manifest declaring exactly what the plugin is allowed to do.
4. You install it with `muccheai plugin install ./my-plugin`.
5. The runtime loads the WASM, reads the manifest, and **enforces every capability boundary**.

### Plugin anatomy

```
my-plugin/
├── plugin.toml      # Capability manifest (required)
├── Cargo.toml       # Rust package
└── src/
    └── lib.rs       # Plugin code
```

### Capabilities (plugin.toml)

| Field | Values | Description |
|-------|--------|-------------|
| `http_hosts` | `["api.example.com"]` | Exact host allowlist. No wildcards. Empty = offline. |
| `filesystem` | `"none"` / `"read-only"` | Host filesystem access. |
| `env` | `"none"` / `"read"` | Environment variable access. |
| `exec` | `"none"` | Subprocess spawning (always none for now). |
| `llm_callback` | `true` / `false` | Whether the plugin can prompt the host LLM. |
| `storage_dir` | `"data"` | A private directory the plugin can read/write. |

---

## How to Create a Plugin

This is a complete, step-by-step guide. By the end you will have a working plugin installed in MuccheAI.

### Step 1 — Copy the example

```bash
cp -r examples/plugins/weather ~/my-weather-plugin
cd ~/my-weather-plugin
```

### Step 2 — Build it

```bash
# Add the WASM target (one-time)
rustup target add wasm32-wasi

# Compile
cargo build --target wasm32-wasi --release
```

You now have `target/wasm32-wasi/release/weather_plugin.wasm`.

### Step 3 — Customize it

Open `plugin.toml` and change the metadata:

```toml
[plugin]
name = "my-weather"
version = "0.1.0"
author = "Your Name <you@example.com>"
description = "My custom weather plugin"
wasm_path = "target/wasm32-wasi/release/weather_plugin.wasm"
```

Open `src/lib.rs` and modify `extract_city()` or `format_weather()` to change the behaviour.

### Step 4 — Install it

```bash
muccheai plugin install ~/my-weather-plugin
```

This command:
1. Reads `plugin.toml`.
2. Verifies the WASM file exists.
3. Computes a SHA-256 hash of the WASM.
4. Prompts you to review the capabilities.
5. If you approve, copies the plugin to `~/.muccheai/plugins/my-weather/` and records the hash.

### Step 5 — Use it

Start (or restart) MuccheAI and open the web UI. Send a message like:

> "What's the weather in Tokyo?"

The plugin triggers on the keyword "weather", fetches live data from `wttr.in`, and injects it into the LLM context before the response is generated.

### Step 6 — Iterate

After changing code:

```bash
cargo build --target wasm32-wasi --release
muccheai plugin reinstall ~/my-weather-plugin
```

The reinstall command updates the stored hash after prompting you to confirm.

---

## Plugin Security Model

### The problem with signatures alone

Tag signatures (e.g., git tag + GPG or Ed25519) prove that a specific person signed a specific commit. But **signatures can be stolen** if a private key is compromised. A stolen signature does not prove the code is safe.

### MuccheAI’s layered approach

| Layer | Protection |
|-------|-----------|
| **1. Source review** | Plugins are open-source Rust. You read the code before building. |
| **2. Reproducible builds** | Build the plugin yourself; do not trust pre-built `.wasm` files from strangers. |
| **3. Hash pinning** | After you approve a plugin, its SHA-256 hash is stored. If the file changes, it is blocked until you re-approve. |
| **4. Capability manifest** | Even if a plugin is malicious, `plugin.toml` hard-limits what it can touch. A plugin with `http_hosts = ["wttr.in"]` **cannot** talk to any other server, no matter what the code says. |
| **5. No floating tags** | The CLI installs from a local path or a pinned git commit hash, not a mutable tag. |

### What an attacker with a stolen signature can do

- Publish a new signed tag → **Irrelevant.** You install from a commit hash you audited, not a tag.
- Replace a `.wasm` file → **Blocked.** The hash does not match the approved one.
- Convince you to install a new plugin → **Contained.** The capability manifest limits damage to whatever you explicitly allowed.

### Offline plugin example

```toml
# plugin.toml for a calculator — no network, no filesystem, pure math
[plugin]
name = "calc"
version = "1.0.0"
wasm_path = "target/wasm32-wasi/release/calc_plugin.wasm"

[capabilities]
http_hosts = []       # ← empty = fully offline
filesystem = "none"
env = "none"
exec = "none"
llm_callback = false
storage_dir = "history"

[triggers]
keywords = ["calculate", "compute", "math", "="]
```

This plugin evaluates expressions like `2 + 2 * sin(pi/4)` entirely inside the WASM sandbox. It works on an airplane.

### Recommended workflow for installing third-party plugins

```bash
# 1. Clone and audit the source
git clone https://github.com/someone/cool-plugin.git
cd cool-plugin
git log --oneline -5          # review recent commits
cat src/lib.rs                # read the code
cat plugin.toml               # check capabilities

# 2. Build it yourself
cargo build --target wasm32-wasi --release

# 3. Install from the local path you just audited
muccheai plugin install ./
```

> **Golden rule:** If you did not read the source and build it yourself, treat the plugin as untrusted — even if it has a signature.

### Community publishing

Plugins are distributed through a **decentralized, source-first registry**. There is no central app store, no signing authority, and no pre-built binaries. Plugins are ranked by community audit tiers (Unreviewed → Community → Reviewed → Core). See [`docs/PLUGIN_DISTRIBUTION.md`](docs/PLUGIN_DISTRIBUTION.md) for the full model including reproducible builds, audit attestations, and the update mechanism.

---

## Commands

| Command | Description |
|---------|-------------|
| `muccheai` | Start the web server (default command). |
| `muccheai setup` | Run the first-time interactive wizard. |
| `muccheai config reveal-key` | Print the decrypted master API key. |
| `muccheai update` | Check for updates on GitHub and rebuild. |
| `muccheai plugin install <path>` | Install a plugin from a local directory. |
| `muccheai plugin reinstall <path>` | Update an installed plugin after changes. |
| `muccheai plugin list` | Show installed plugins and their capabilities. |
| `muccheai plugin remove <name>` | Remove a plugin. |
| `muccheai --version` | Print version. |
| `muccheai --help` | Show all options. |

### Makefile targets

| Target | Description |
|--------|-------------|
| `make install` | Build release binary and run setup if first install. |
| `make test` | Run `cargo test --workspace`. |
| `make reset` | **Delete all data** (`~/.muccheai`), run `cargo clean`, and print next steps. Use this when switching branches or if the database schema changed. |
| `make deep-clean` | `make reset` plus nuking Cargo registry caches. |

---

## Configuration

Configuration lives in `~/.muccheai/config.toml`. Sensitive fields (API keys, agent keys) are stored in separate encrypted sidecar files (`*.enc`) and never written to the TOML.

### Environment variables

| Variable | Description |
|----------|-------------|
| `MUCCHEAI_KEY_PASSWORD` | Password for encrypting/decrypting secrets. If `~/.muccheai/.password_required` exists, the server will refuse to start without it. |
| `PORT` | HTTP server port (default: 3000). |
| `RUST_LOG` | Log level, e.g. `info`, `debug`. |

### Key files in `~/.muccheai/`

| File | Purpose |
|------|---------|
| `config.toml` | Main configuration (no secrets). |
| `.api_key_enc` | Encrypted master API key. |
| `.keypair_enc` | Encrypted keypair for internal crypto. |
| `.agent_keys_enc` | Encrypted per-agent API keys. |
| `users.json` | Encrypted user database. |
| `salt` | Per-installation Argon2id salt. |
| `.password_required` | Flag file; if present, `MUCCHEAI_KEY_PASSWORD` is mandatory. |
| `uploads/` | Uploaded files (owner-isolated). |
| `plugins/` | Installed plugins (one directory per plugin). |

---

## Security

### Encryption

- **AES-256-GCM** for all sidecar files.
- **Argon2id** for password hashing (users) and key derivation (machine key).
- **Per-installation salt** — the `salt` file is generated once and never changes, so Argon2id hashes are bound to your machine.
- **Per-user salt** — every user account has its own random salt.

### Network

- **SSRF validation** on all MCP tool HTTP requests.
- **CORS** is restricted to the configured host.
- **Rate limiting** at 60 messages/minute per IP.
- **X-Forwarded-For** parsing with trusted-proxy CIDR support (right-to-left, first non-trusted IP).

### Secrets hygiene

- API keys are never logged.
- Error messages are generic to avoid leaking internal state.
- Session tokens expire and can be revoked.
- Duress sessions destroy data instead of exposing it.

### Audit trail

Security-sensitive operations are logged to `~/.muccheai/audit.log`:

- Logins (success and failure)
- Registration
- File uploads
- Memory modifications
- MCP server additions
- Plugin installs/removals

---

## Development

```bash
# Run tests
cargo test --workspace

# Run in debug mode with logging
RUST_LOG=debug cargo run

# Format and lint
cargo fmt
cargo clippy --workspace

# Build release binary
cargo build --release
```

### Project structure

```
├── src/
│   ├── main.rs              # Entry point, version check, password enforcement
│   ├── config.rs            # Encrypted config + machine key derivation
│   ├── web.rs               # Axum server: auth, REST, WebSocket, upload
│   ├── users.rs             # Argon2id user database
│   ├── memory_store.rs      # Raw memory storage
│   ├── structured_memory.rs # LLM-driven memory extraction
│   ├── style.rs             # Persona/system prompt styles
│   ├── notify.rs            # Desktop notifications
│   ├── cli/                 # CLI subcommands (setup, update, config, plugin)
│   └── web/static/          # Frontend SPA (HTML, CSS, JS)
├── crates/                  # Workspace crates
│   ├── muccheai-crypto/     # AES-GCM, Argon2id, constant-time utils
│   ├── muccheai-types/      # Shared types
│   ├── muccheai-sandbox/    # WASM plugin runtime (future)
│   └── ...
├── proto/                   # gRPC/protobuf definitions
└── examples/plugins/        # Example plugins
```

---

## Troubleshooting

### "Server refuses to start: MUCCHEAI_KEY_PASSWORD not set"

You enabled password protection during setup. Set the environment variable:

```bash
export MUCCHEAI_KEY_PASSWORD="your-password"
muccheai
```

To disable password protection, delete `~/.muccheai/.password_required`.

### "Cannot log in after switching branches"

Database schemas may change between versions. Run:

```bash
make reset
muccheai setup
```

This deletes all data and re-runs the wizard. Use `muccheai config reveal-key` first if you need to save your legacy API key.

### "Connect button does nothing"

1. Open the browser console (F12 → Console).
2. Look for `MuccheAI login:` log lines.
3. If you see `401 Unauthorized`, check your username and password.
4. If you see no logs, hard-refresh with `Ctrl+Shift+R` (cache-busting is automatic but some browsers are stubborn).

### "Research mode keeps asking for confirmation"

This is by design. Confirmation is required whenever an external provider (OpenAI, Anthropic, etc.) is active. Switch your primary agent to **Ollama** for local-only, confirmation-free research.

### "Plugin install fails with hash mismatch"

The plugin’s WASM file changed after you first approved it. Run:

```bash
muccheai plugin reinstall <path>
```

and approve the new hash.

---

## License

MIT / Apache-2.0 dual license. See `LICENSE-MIT` and `LICENSE-APACHE`.

---

*Built with Rust, paranoia, and too much coffee.*
