# MuccheAI v3

A security-focused local AI agent written in Rust. Designed with defense-in-depth to limit the blast radius of a compromised or misbehaving LLM.

## What It Does

MuccheAI is a personal AI assistant that runs locally on your machine. It chats with you, remembers facts and preferences across conversations, executes tools on your behalf, and enforces strict security policies so the AI cannot do anything you did not explicitly approve.

## Features

- Local-first — runs entirely on your machine.
- Multiple LLM providers — Ollama (local), OpenAI, Anthropic.
- Capability-based security — tool calls require cryptographically signed capability tokens (default-deny policy).
- User approval tiers — configurable friction from simple dialog to hardware-token approval.
- Forward-secure audit logging — security events are signed with an evolving key chain.
- Hybrid cryptography — Ed25519 + X25519 keypairs; ML-KEM/ML-DSA structures staged for future integration.
- Shamir's Secret Sharing vault — 3-of-5 threshold for local secret storage.
- MCP server integration — connect to external Model Context Protocol servers.
- Multi-layer memory — session transcripts, episodic daily notes, semantic long-term memory, and hybrid SQLite/FTS5 search.

## Installation

Requires Rust 1.80+. Tested on macOS.

```bash
git clone https://github.com/IuriGom/muccheai-v3
cd muccheai-v3
make install
```

Or manually:

```bash
cargo build --release
cargo install --path . --force
```

## Quick Start

Run the setup wizard on first launch:

```bash
muccheai setup
```

### Chat from the terminal

```bash
muccheai chat
```

Or send a single message:

```bash
muccheai run "What is the capital of France?"
```

### Launch the web control panel

```bash
muccheai web
```

Then open http://127.0.0.1:3000 in your browser.

## CLI Commands

- `muccheai setup` — first-run interactive setup wizard
- `muccheai chat` — interactive chat REPL
- `muccheai run <prompt>` — execute a single prompt
- `muccheai web` — launch web control panel
- `muccheai status` — system status and health
- `muccheai doctor` — run system health check
- `muccheai demo` — run end-to-end security demonstration
- `muccheai audit` — query the forward-secure audit log
- `muccheai policy list` — list active policy rules
- `muccheai policy add ...` — add a new policy rule
- `muccheai vault create` — create a Shamir vault
- `muccheai vault unlock` — unlock the vault
- `muccheai persona list` — list AI personas
- `muccheai daemon start` — start background daemon
- `muccheai daemon stop` — stop background daemon
- `muccheai complete <shell>` — generate shell completions

## Security Architecture

MuccheAI is designed around the principle that the LLM itself is untrusted. Every tool execution goes through this pipeline:

1. LLM proposes an action
2. Proposal is validated against cryptographically signed capability tokens
3. Policy rules are evaluated (default-deny)
4. User approves through the configured friction tier
5. Tool executes with schema-validated arguments
6. Event is appended to the forward-secure audit log

The security architecture aims to ensure that a compromised LLM cannot execute tools without passing policy checks and user approval. This is a continuous work in progress.

### Policy Rules

Default rules:
- Allow `email.send`
- Allow `calendar.read`
- Deny `filesystem.delete`

You can add custom rules with `muccheai policy add`.

### Approval Tiers

- **Standard** — dialog with 3-second delay
- **Secure** — re-type summary, 5-second delay
- **Hardware** — YubiKey or hardware token required (planned)
- **Multi-Device** — M-of-N devices must approve (planned)

## Configuration

Config lives at `~/.muccheai/config.toml`. Key settings:

```toml
[agent.default]
provider = "ollama"
model = "qwen3:14b"

[web]
bind_address = "127.0.0.1:3000"

[[persona]]
name = "Assistant"
description = "A friendly, helpful general-purpose AI assistant"
```

### LLM Providers

- **Ollama** — install from [ollama.com](https://ollama.com), run `ollama serve`
- **OpenAI** — set API key in `muccheai setup`
- **Anthropic** — set API key in `muccheai setup`

## MCP Servers

Connect to external tools via the Model Context Protocol:

```toml
[mcp.servers.myserver]
transport = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/docs"]
```

MCP tool calls are validated against JSON Schema and evaluated by the policy engine before execution.

## Web API

The web control panel exposes a REST API at `http://127.0.0.1:3000`:

- `POST /chat` — send a message
- `GET /status` — system status
- `GET /config` — current configuration
- `GET/POST /memory` — list/store memories
- `GET /memory/queue` — list approval queue
- `GET /personas` — list personas
- `GET/POST /agents` — list/save agents
- `POST /audit` — query audit log
- `GET /csrf` — get CSRF token

All API endpoints require Bearer token authentication. Mutating endpoints also require a CSRF token.

## Development

```bash
# Build
cargo build --release

# Run tests
cargo test --workspace

# Run the demo
muccheai demo
```

## Contributing

Contributions are welcome. Please open an issue or pull request.

Security issues, bugs, and mistakes are welcome — this is a learning project.

## Security Considerations

This project implements defense-in-depth mechanisms but is not formally verified and does not provide hardware isolation. Known limitations:

- The LLM sandbox uses process-level isolation (rlimits), not VMs or containers.
- The machine encryption key is stored in `~/.muccheai/.machine_key` with filesystem permissions — not a hardware security module.
- Build verification and warrant canary signatures use placeholder data until real maintainer keys are configured.
- Some components use `unsafe` blocks for `pre_exec` resource limits (documented with safety comments).

Do not use this to protect high-value targets without additional hardening.

## License

MIT
