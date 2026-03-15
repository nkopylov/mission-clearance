# Mission Clearance

<!-- Badges placeholder -->
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/crates/v/mission-clearance.svg)](https://crates.io/crates/mission-clearance)

**Kernel-level permission management for autonomous AI agents.**

Mission Clearance brings an OS-kernel metaphor to AI agent orchestration:
missions are processes, capabilities are file descriptors, and policies are
syscall filters. Every external action an agent takes is checked, logged, and
auditable before it reaches the outside world.

## Key Features

- **Two-dimensional permission model** -- structural _capabilities_ define what
  resources an agent may touch; behavioral _policies_ decide whether a specific
  action is appropriate in context.
- **Multi-stage policy pipeline** -- deterministic rules run in-process; when
  uncertain, the pipeline returns _Escalate_ and the integration layer (e.g.
  Claude Code hook) asks the host LLM to judge -- no separate API key needed.
- **Encrypted credential vault** -- AES-256-GCM encryption with Argon2id key
  derivation. Credentials are bound to resource patterns and injected only when
  policy allows.
- **Append-only tamper-evident trace log** -- every event is SHA-256 chained so
  post-hoc audits can detect tampering.
- **Mission delegation with monotonic narrowing** -- child missions can never
  exceed their parent's permissions, enforced structurally.
- **Protocol adapters** -- normalize HTTP, SQL, shell, and tool-call traffic
  into a unified operation model.
- **Content analysis** -- detects reverse shells, data exfiltration attempts,
  obfuscation patterns, and prompt injection in operation payloads.

## Architecture

```
 Agent / Orchestrator
        |
        v
 +------+-------+      +-----------+
 |   mc-sdk      |----->|  mc-api   |  (axum HTTP server)
 | (Rust client  |      +-----------+
 |  or embedded) |            |
 +------+--------+            v
        |          +----------+----------+
        +--------->|     mc-kernel       |
                   | classifier          |
                   | capability checker  |
                   | content analyzer    |
                   +----------+----------+
                              |
              +---------------+---------------+
              |               |               |
        +-----+----+   +-----+-----+   +-----+-----+
        | mc-policy |   | mc-vault  |   | mc-trace  |
        | pipeline  |   | AES-256   |   | SHA-256   |
        | rules     |   | Argon2id  |   | chained   |
        +-----------+   +-----------+   +-----------+
              |
     +--------+--------+
     |   mc-adapters    |
     | HTTP | SQL |     |
     | shell| tool_call |
     +------------------+
              |
        +-----+-----+
        |  mc-core   |
        | domain types|
        +------------+
```

## Quick Start

### Install from source

```bash
cargo install --path crates/mc-cli
```

### Start the server

```bash
mission-clearance start
```

The API server listens on `http://localhost:9090` by default.

### Create a mission and submit an operation

```bash
# Create a root mission
curl -X POST http://localhost:9090/api/v1/missions \
  -H "Content-Type: application/json" \
  -H "x-api-key: $MC_API_KEY" \
  -d '{
    "goal": "deploy-service",
    "capabilities": [{
      "resource_pattern": "http://api.github.com/**",
      "operations": ["Read"],
      "delegatable": true
    }],
    "policies": []
  }'

# Submit an operation for clearance
curl -X POST http://localhost:9090/api/v1/operations/request \
  -H "Content-Type: application/json" \
  -H "x-api-key: $MC_API_KEY" \
  -d '{
    "mission_token": "<token-from-above>",
    "resource": "http://api.github.com/repos/org/repo",
    "operation": "Read",
    "context": {},
    "justification": "fetch repo metadata for deployment"
  }'
```

### Use the Rust SDK (embedded mode)

```rust
use mc_sdk::EmbeddedKernel;

let kernel = EmbeddedKernel::new(10)?; // max delegation depth

// Create a mission
let mission = kernel.create_mission("deploy", vec![cap], vec![])?;

// Submit an operation for clearance
let decision = kernel.submit_operation(
    &mission.token,
    "http://api.github.com/repos/org/repo",
    "Read",
    Default::default(),
    "fetch repo metadata",
)?;

assert_eq!(decision.decision, "allowed");
```

### CLI commands

```bash
# Vault management
mission-clearance vault add --name gh-token --secret-type ApiKey \
  --value "ghp_..." --resource "http://api.github.com/**"
mission-clearance vault list

# Mission management
mission-clearance mission create --goal "deploy-service"
mission-clearance mission inspect <mission-id>
mission-clearance mission revoke <mission-id>

# Trace and audit
mission-clearance trace show <mission-id>
mission-clearance trace denials
mission-clearance trace anomalies

# Policy inspection
mission-clearance policy list
```

## Crate Map

| Crate | Description |
|---|---|
| **mc-core** | Core domain types: missions, capabilities, operations, policies, resources |
| **mc-kernel** | Operation classifier, capability checker, content analyzer, session tracker |
| **mc-policy** | Deterministic policy pipeline with escalation to host LLM via integration layer |
| **mc-trace** | Append-only event log with SHA-256 chaining and mission delegation graph |
| **mc-vault** | AES-256-GCM encrypted credential store with Argon2id key derivation |
| **mc-adapters** | Protocol adapters for HTTP, SQL, shell, and tool-call traffic |
| **mc-api** | Axum HTTP API server with auth middleware and REST endpoints |
| **mc-sdk** | Rust SDK providing both an HTTP client and an embedded kernel mode |
| **mc-cli** | CLI binary (`mission-clearance`) for server, vault, mission, trace, and policy management |
| **mc-integration-tests** | End-to-end integration tests |

## Configuration

Create a `mission-clearance.toml` file (or pass `--config <path>`):

```toml
[kernel]
max_delegation_depth = 10

[server]
port = 9090
```

## Current Status

Mission Clearance is in early development (`0.1.0`). The following components
are implemented and tested:

- Deterministic policy evaluation (pattern matching, content analysis rules)
- Capability-based structural permission model
- Encrypted vault with rotation and revocation
- Tamper-evident trace log and mission graph
- HTTP API and CLI
- Protocol adapters for HTTP, SQL, shell, and tool calls
- Content analysis (reverse shell detection, exfiltration detection, obfuscation detection, prompt injection detection)

**LLM judge architecture:** When the deterministic pipeline returns `Escalate`,
the integration layer handles LLM-based judgment. In the Claude Code plugin,
the pre-tool-use hook asks the host Claude instance to evaluate the operation
and call `mc_approve_escalation` or `mc_deny_escalation`. This means no
separate LLM API key or HTTP call is needed -- the host agent _is_ the judge.

**Planned for future releases:**

- Persistent storage backends (currently in-memory / SQLite)
- Policy hot-reloading
- Metrics and observability integration

## License

Licensed under the [MIT License](LICENSE).
