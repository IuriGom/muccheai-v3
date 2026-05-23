# MuccheAI v3

A security-focused local AI agent written in Rust. Designed with defense-in-depth to limit the blast radius of a compromised or misbehaving LLM.

## What It Does

MuccheAI is a personal AI assistant that runs locally on your machine. It chats with you, remembers facts and preferences across conversations, executes tools on your behalf, and enforces strict security policies so the AI cannot do anything you did not explicitly approve.

## Key Features

- **Local-first** — Runs entirely on your machine. No data leaves unless you configure it to.
- **Multiple LLM providers** — Supports Ollama (local), OpenAI, and Anthropic.
- **Capability-based security** — Tool calls require cryptographically signed capability tokens (default-deny policy).
- **User approval tiers** — Configurable friction from simple dialog to hardware-token approval.
- **Forward-secure audit logging** — Security events are signed with an evolving key chain.
- **Hybrid cryptography** — Ed25519 + X25519 keypairs; ML-KEM/ML-DSA structures staged for future integration.
- **Shamir's Secret Sharing vault** — 3-of-5 threshold for local secret storage.
- **MCP server integration** — Connect to external Model Context Protocol servers with JSON Schema validation and policy enforcement.
- **Multi-layer memory** — Session transcripts, episodic daily notes, semantic long-term memory, and hybrid SQLite/FTS5 search.

## Installation

Requires Rust 1.80+. Tested on macOS — Linux and Windows support is planned (focus on Linux because I don't have a microslop machine).

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

This configures your LLM provider, model, and security preferences.

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

| Command | Description |
|---------|-------------|
| `muccheai setup` | First-run interactive setup wizard |
| `muccheai chat` | Interactive chat REPL |
| `muccheai run <prompt>` | Execute a single prompt |
| `muccheai web` | Launch web control panel |
| `muccheai status` | System status and health |
| `muccheai doctor` | Run system health check |
| `muccheai demo` | Run end-to-end security demonstration |
| `muccheai audit` | Query the forward-secure audit log |
| `muccheai policy list` | List active policy rules |
| `muccheai policy add ...` | Add a new policy rule |
| `muccheai vault create` | Create a Shamir vault |
| `muccheai vault unlock` | Unlock the vault |
| `muccheai persona list` | List AI personas |
| `muccheai daemon start` | Start background daemon |
| `muccheai daemon stop` | Stop background daemon |
| `muccheai complete <shell>` | Generate shell completions |

## Security Architecture

MuccheAI is designed around the principle that the LLM itself is untrusted. Every tool execution goes through this pipeline:

1. LLM proposes an action
2. Proposal is validated against cryptographically signed capability tokens
3. Policy rules are evaluated (default-deny)
4. User approves through the configured friction tier
5. Tool executes with schema-validated arguments
6. Event is appended to the forward-secure audit log

The security architecture aims to ensure that a compromised LLM cannot execute tools without passing policy checks and user approval. This is a continuous work in progress — see [Security Considerations](#security-considerations).

### Policy Rules

Default rules:
- Allow `email.send`
- Allow `calendar.read`
- Deny `filesystem.delete`

You can add custom rules with `muccheai policy add`.

### Approval Tiers

| Tier | Status | Friction |
|------|--------|----------|
| Standard | ✅ Implemented | Dialog with 3-second delay |
| Secure | ✅ Implemented | Re-type summary, 5-second delay |
| Hardware | 🚧 Planned | YubiKey or hardware token required |
| Multi-Device | 🚧 Planned | M-of-N devices must approve |

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

| Provider | Setup |
|----------|-------|
| Ollama | Install from [ollama.com](https://ollama.com), run `ollama serve` |
| OpenAI | Set API key in `muccheai setup` |
| Anthropic | Set API key in `muccheai setup` |

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

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/chat` | POST | Send a message |
| `/status` | GET | System status |
| `/config` | GET | Current configuration |
| `/memory` | GET/POST | List/store memories |
| `/memory/queue` | GET | List approval queue |
| `/personas` | GET | List personas |
| `/agents` | GET/POST | List/save agents |
| `/audit` | POST | Query audit log |
| `/csrf` | GET | Get CSRF token |

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

If you build something cool and want to be credited as a proper part of this project, open a pull request or issue.

Security issues, bugs, and mistakes are welcome — this is a learning project. Please open an issue or submit a fix.

## Security Considerations

This project implements defense-in-depth mechanisms but is **not formally verified** and does **not** provide "maximum assurance" or hardware isolation. Known limitations include:

- The LLM sandbox uses **process-level isolation** (rlimits), not VMs or containers.
- The machine encryption key is stored in `~/.muccheai/.machine_key` with filesystem permissions — not a hardware security module.
- Build verification and warrant canary signatures use placeholder data until real maintainer keys are configured.
- Some components use `unsafe` blocks for `pre_exec` resource limits (documented with safety comments).

**Do not use this to protect high-value targets without additional hardening.**

## License

MIT
