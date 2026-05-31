# Plugin Distribution & Community Publishing

This document describes how offline plugins work and how the MuccheAI community will publish, discover, and trust plugins in the long term.

---

## Offline Plugins

Not every plugin needs to call the internet. **Offline plugins** run entirely inside the WASM sandbox using only local computation and the host's resources.

### What offline plugins can do

| Capability | Example use cases |
|-----------|-------------------|
| **Pure computation** | Calculator, regex tester, base64 encoder, UUID generator, dice roller |
| **Text processing** | Markdown formatter, CSV/JSON pretty-printer, text diff tool, word counter |
| **Local storage** | Habit tracker, simple note pad, flashcards, bookmark manager |
| **LLM callbacks** | Prompt templates, chain-of-thought helpers, local RAG over plugin storage |
| **File analysis** | Read a file the user explicitly shares and analyze it locally |

### What offline plugins cannot do (by design)

- Reach the network (`http_hosts = []`)
- Read host files outside their own `storage_dir`
- Spawn subprocesses
- Access environment variables

### Example: a calculator plugin

```toml
# plugin.toml
[plugin]
name = "calc"
version = "1.0.0"
author = "community"
description = "Evaluate mathematical expressions"
wasm_path = "target/wasm32-wasi/release/calc_plugin.wasm"

[capabilities]
http_hosts = []          # NONE — fully offline
filesystem = "none"
env = "none"
exec = "none"
llm_callback = false
storage_dir = "history"  # keeps a local history of calculations

[triggers]
keywords = ["calculate", "compute", "=", "math"]
require_mention = false

[output]
mode = "append"
```

The entire plugin is a ~50 KB WASM blob that parses expressions with `meval` or similar, writes history to `storage_dir/history.json`, and returns the result. It works on an airplane.

### Why offline plugins matter

1. **Air-gapped systems** — users on isolated networks still get utility.
2. **Zero trust surface** — no DNS, no TLS, no certificate validation, no data exfiltration vector.
3. **Instant execution** — no network latency, no API keys, no rate limits.
4. **Battery life** — on laptops, avoiding radio usage saves power.
5. **Privacy guarantee** — mathematically impossible to leak data if `http_hosts` is empty and `llm_callback` is false.

---

## Community Publishing Model

MuccheAI does not have a central app store, a signing authority, or a paywall. The model is **decentralized, source-first, and trust-but-verify**.

### Core principles

1. **Source is the artifact** — Plugins are distributed as **source code**, not pre-built binaries. The user builds the `.wasm` locally.
2. **No central signing authority** — There is no single organization that blesses plugins. Trust emerges from transparency and community audit.
3. **Hash pinning, not signature pinning** — What matters is the exact bytes you approved, not who claims to have written them.
4. **Capability manifests are public contracts** — A plugin's `plugin.toml` is a legally-binding (in the security sense) declaration of what it will and will not do.

### The registry

The registry is a **git repository** (or a set of federated git repositories) containing:

```
registry/
├── README.md
├── index.toml              # Master index of all known plugins
├── plugins/
│   ├── weather/
│   │   ├── metadata.toml   # Name, description, author, source URL
│   │   ├── audits/         # Community audit attestations
│   │   │   ├── alice.asc
│   │   │   └── bob.asc
│   │   └── builds/         # Reproducible build hashes from CI
│   │       ├── v1.0.0.sha256
│   │       └── v1.1.0.sha256
│   └── calc/
│       └── ...
```

#### `index.toml`

```toml
[[plugin]]
name = "weather"
description = "Real-time weather via wttr.in"
source_url = "https://github.com/community/muccheai-weather"
latest_version = "1.2.0"
category = "utilities"

[[plugin]]
name = "calc"
description = "Offline mathematical expression evaluator"
source_url = "https://github.com/community/muccheai-calc"
latest_version = "3.0.1"
category = "productivity"
```

### Trust tiers

Plugins are not binary "trusted / untrusted." They have tiers based on audit history:

| Tier | Requirements | User risk level |
|------|-------------|-----------------|
| **Unreviewed** | Listed in registry, automated CI passes | High — audit it yourself |
| **Community** | At least 1 independent community auditor signed `audit.toml` | Medium — someone you don't know read the code |
| **Reviewed** | At least 2 independent auditors from different orgs/jurisdictions | Low — multiple eyes, hard to collude |
| **Core** | Maintained by the MuccheAI core team | Lowest — but still verify if paranoid |

An **audit attestation** is a signed TOML file:

```toml
# audits/alice.asc (detached GPG signed)
plugin = "weather"
version = "1.2.0"
commit = "abc123def456"
auditor = "Alice <alice@example.com>"
public_key = "0xA1B2C3D4"
date = "2025-06-01"

[findings]
code_review = true
capabilities_match = true      # plugin.toml claims match actual code
no_hardcoded_secrets = true
no_suspicious_networking = true
no_obfuscation = true
notes = "Clean, well-structured. HTTP host allowlist is exact."
```

### Reproducible builds

The CI pipeline (GitHub Actions, or your own) builds every tagged release in a **deterministic container**:

```dockerfile
FROM rust:1.80-slim
RUN rustup target add wasm32-wasi
WORKDIR /src
COPY . .
RUN cargo build --target wasm32-wasi --release
RUN sha256sum target/wasm32-wasi/release/*.wasm > build.sha256
```

The resulting hash is published to `registry/plugins/{name}/builds/{version}.sha256`.

When you build the same source locally, you should get the **exact same hash**. If you don't, something is non-deterministic (timestamps, paths, etc.) and that is treated as a bug in the plugin's build process.

### Installation flow

#### From the registry (discover mode)

```bash
# Search for plugins
muccheai plugin search weather
#> weather    v1.2.0    Real-time weather via wttr.in    [reviewed]
#> meteo      v0.9.0    Multi-provider weather           [community]

# View source before installing
muccheai plugin show weather --source
#> Cloning https://github.com/community/muccheai-weather.git...
#> Showing src/lib.rs:
#> ...

# Install (downloads source, builds locally, prompts for hash approval)
muccheai plugin install weather
#> Building from source...
#> Reproducible build hash: a3f7b2...
#> Registry attested hash:  a3f7b2 ✓
#> Capabilities:
#>   HTTP hosts: wttr.in
#>   Filesystem: none
#>   LLM callback: false
#> Approve this plugin? [y/N] y
#> Installed weather v1.2.0
```

#### From any git URL (direct mode)

```bash
# Install a specific commit (recommended)
muccheai plugin install https://github.com/alice/muccheai-cool-plugin.git#abc123def456

# Install a tag (warns you that tags are mutable)
muccheai plugin install https://github.com/alice/muccheai-cool-plugin.git#v1.0.0
#> ⚠️  Tags can be force-pushed. Consider using a commit hash instead.
#> Continue? [y/N]
```

#### From a local path (development mode)

```bash
muccheai plugin install ./my-plugin
```

### Update model

Plugins **never auto-update**. You must explicitly approve each new version.

```bash
# Check for updates
muccheai plugin outdated
#> weather   1.2.0 → 1.3.0    [reviewed]
#> calc      3.0.1 → 3.1.0    [community]

# Update a specific plugin (shows changelog, rebuilds, re-prompts)
muccheai plugin update weather
#> Changelog for weather 1.3.0:
#> - Added wind speed
#> - Changed HTTP host from wttr.in to api.open-meteo.com
#> ⚠️  Capabilities changed! New HTTP host: api.open-meteo.com
#> Approve new hash e4c9d1...? [y/N] y
#> Updated weather → 1.3.0
```

If capabilities change (e.g., a new HTTP host is added), the prompt is **red and requires explicit confirmation**.

### Handling compromise scenarios

| Scenario | Mitigation |
|----------|-----------|
| **Author's git account hacked** | Attacker can push new commits, but users install from **pinned commits**. Old installs are unaffected. |
| **Registry maintainer compromised** | Registry is just an index. Malicious entries point to code that still requires local build + hash approval. |
| **Auditor key stolen** | A fraudulent attestation is published. Other auditors' attestations still exist. Users can require N-of-M attestations. |
| **Build server compromised** | Reproducible builds mean users detect the mismatch when their local hash differs from the published one. |
| **User installs unreviewed plugin** | Capability manifest still limits damage. A malicious calculator cannot exfiltrate data if `http_hosts = []`. |

### FAQ

**Q: Why not just sign the `.wasm` binaries and distribute those?**

A: Because signatures prove authorship, not safety. A stolen key can sign malware. By distributing source and building locally, you verify the exact code you audited is what runs. The hash you approve is the hash of the bytes you yourself compiled.

**Q: What if I don't know Rust and can't audit the code?**

A: Use plugins from the **Reviewed** or **Core** tiers. The community audit process exists precisely so non-Rust users don't have to read code. You still get the protection of hash pinning and capability manifests.

**Q: Can I run my own private registry?**

A: Yes. The registry is just a git repo. Point your MuccheAI config to it:

```toml
[plugins]
registry_url = "https://git.mycompany.com/muccheai-registry"
```

**Q: Can plugins be paid / proprietary?**

A: The registry only indexes open-source plugins. The build system requires source. If you want to distribute a closed-source plugin, users must manually install a pre-built `.wasm` and take full responsibility for auditing the binary (which is nearly impossible). This is discouraged.

**Q: What about plugin dependencies?**

A: Plugins are single `.wasm` files with no external dependencies. If a plugin needs a library, it is compiled into the WASM blob. The runtime does not support dynamic linking to prevent dependency confusion attacks.

---

## Summary

| Aspect | MuccheAI approach |
|--------|-------------------|
| **Artifact** | Source code (Rust), not binaries |
| **Build** | Local, deterministic, reproducible |
| **Trust** | Community audit + capability sandbox |
| **Distribution** | Decentralized git-based registry |
| **Updates** | Manual, hash-reapproved |
| **Offline support** | First-class; many plugins need no network |
| **Compromise recovery** | Pin commits, revoke attestations, capability limits contain blast radius |
