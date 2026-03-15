# Mission Clearance

**Security harness for Claude Code**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)

## What It Does

Mission Clearance is a Claude Code plugin that acts as a security kernel for
your coding sessions. It intercepts every tool call Claude makes -- file writes,
shell commands, HTTP requests -- and evaluates them against capability-scoped
policies before allowing execution.

Think of it as an OS kernel for your AI agent: missions are processes,
capabilities are file descriptors, and policies are syscall filters. Every
external action is checked, classified, and logged in a tamper-evident trace
before it reaches the outside world. Dangerous operations are blocked outright;
ambiguous ones are escalated to Claude itself for judgment.

Once started, Mission Clearance runs transparently. A pre-tool-use hook
intercepts all tool calls, sends them to a local policy server, and blocks
anything that violates the mission's constraints. You keep working normally --
Mission Clearance stays out of your way until something suspicious happens.

## How It Works

```
Claude Code ──tool call──> PreToolUse Hook ──> MC Server
                                                  │
                                          Classify + Evaluate
                                                  │
                              ┌─────────┬─────────┼─────────┐
                            Allow     Deny     Escalate
                              │         │         │
                           proceed    block    Claude judges
                                               (via MCP tools)
```

1. Claude Code attempts a tool call (Bash, Edit, Write, etc.)
2. The **PreToolUse hook** intercepts it, expands context (script contents,
   package.json lifecycle hooks, cross-file function bodies), and sends the
   enriched operation to the MC server
3. The **kernel** classifies the operation: resource type, destructiveness,
   data flow direction, pattern matching
4. The **policy pipeline** evaluates deterministic rules:
   - **Allow** -- operation proceeds normally
   - **Deny** -- operation is blocked with an explanation
   - **Escalate** -- Claude itself acts as the LLM judge, reviewing the
     operation and calling `mc_approve_escalation` or `mc_deny_escalation`
5. Every decision is recorded in a **tamper-evident trace** (SHA-256 chained)

## Getting Started

### 1. Build

```bash
cd /path/to/mission-clearance
cargo build --release
```

### 2. Install the plugin

The plugin lives at `~/.claude/plugins/local/mission-clearance/` and contains:

```
~/.claude/plugins/local/mission-clearance/
  .claude-plugin/plugin.json    # Plugin manifest
  .mcp.json                     # MCP server configuration
  hooks/
    hooks.json                  # Hook registration
    pre-tool-use.py             # PreToolUse hook script
  commands/
    start.md                    # /mission-clearance:start
    stop.md                     # /mission-clearance:stop
    status.md                   # /mission-clearance:status
    trace.md                    # /mission-clearance:trace
    vault.md                    # /mission-clearance:vault
    delegate.md                 # /mission-clearance:delegate
  scripts/
    mc-mcp-server.py            # MCP server (stdio JSON-RPC)
    mc-session.sh               # Session helper
```

Ensure the `mission-clearance` binary is on your PATH or available at
`target/release/mission-clearance`.

### 3. Start a session

```
/mission-clearance:start "implement user authentication"
```

This launches the MC server (if not already running), creates a root mission
scoped to your goal, and saves session state to `.claude/mc-session.json`.

### 4. Work normally

All tool calls are now checked automatically. You do not need to do anything
differently. The hook runs transparently on every tool call.

### 5. Check status

```
/mission-clearance:status
```

Shows the active mission, server health, recent decisions, and any anomalies.

### 6. Stop

```
/mission-clearance:stop
```

Revokes the mission and deactivates gating.

## What Gets Checked

Mission Clearance detects and blocks a range of attack patterns:

- **Dangerous shell commands** -- `rm -rf /`, fork bombs, disk wiping, and
  other catastrophic destructive operations
- **Data exfiltration** -- `curl`/`wget` to unknown hosts, DNS exfiltration,
  environment variable harvesting sent to external endpoints
- **Privilege escalation** -- `sudo`, `chmod`, `chown`, and operations that
  modify security controls or the permission system itself
- **Reverse shells** -- Python, Bash, PHP, Ruby, and Perl reverse shell patterns
  (socket + dup2/exec combinations, `/dev/tcp`, `fsockopen`, etc.)
- **Obfuscated code** -- base64 decode + exec/eval chains, `atob` + `eval`,
  `Buffer.from` + `eval`, chr() character-by-character construction,
  `String.fromCharCode` chains
- **Credential harvesting** -- code that reads SSH keys, AWS credentials,
  Docker configs, `.netrc`, and other sensitive files
- **Cross-file taint tracking** -- resolves function calls across files to
  detect benign-looking code that invokes malicious functions defined elsewhere
- **Package manager attacks** -- expands `npm install` / `yarn install`
  lifecycle scripts and Makefile recipes to detect hidden payloads in
  `postinstall`, `preinstall`, etc.
- **Session write-then-execute** -- tracks files written during a session and
  detects subsequent execution of those files
- **Goal drift** -- escalates operations that appear unrelated or contradictory
  to the stated mission goal

## Slash Commands

| Command | Description |
|---|---|
| `/mission-clearance:start [goal]` | Launch MC server, create a root mission, activate gating |
| `/mission-clearance:stop` | Revoke the active mission and deactivate gating |
| `/mission-clearance:status` | Show session status, server health, recent decisions, anomalies |
| `/mission-clearance:trace [events\|denials\|anomalies\|graph]` | View trace events, denied operations, detected anomalies, or mission graph |
| `/mission-clearance:vault <add\|list\|rotate\|revoke>` | Manage encrypted credentials in the vault |
| `/mission-clearance:delegate <goal>` | Create a sub-mission with narrowed permissions |

## MCP Tools

These tools are exposed via the MCP server and used by Claude during sessions.

| Tool | Description |
|---|---|
| `mc_create_mission` | Create a root mission with a goal and capabilities |
| `mc_get_mission` | Get details of a mission by ID |
| `mc_delegate_mission` | Delegate a sub-mission with narrowed permissions |
| `mc_revoke_mission` | Revoke a mission and all its sub-missions |
| `mc_submit_operation` | Submit an operation for policy evaluation |
| `mc_vault_add` | Add a credential to the encrypted vault |
| `mc_vault_list` | List credentials (metadata only, no secrets) |
| `mc_vault_revoke` | Revoke a vault credential |
| `mc_trace_events` | Get trace events, optionally filtered by mission |
| `mc_trace_anomalies` | Get detected anomalies (taint, goal drift, prompt injection) |
| `mc_policy_test` | Dry-run a policy evaluation without a mission context |
| `mc_server_status` | Check if the MC server is running and healthy |
| `mc_approve_escalation` | LLM Judge: approve an escalated operation (time-limited, 5 min) |
| `mc_deny_escalation` | LLM Judge: deny an escalated operation |

## Configuration

Mission Clearance uses a TOML config file (`mission-clearance.toml` or
`config/default.toml`). Key settings:

```toml
[kernel]
max_delegation_depth = 10
fail_closed = true

[api]
listen = "127.0.0.1:9090"
```

### Environment variables

| Variable | Purpose |
|---|---|
| `MC_VAULT_PASSPHRASE` | Passphrase for the AES-256-GCM encrypted vault (Argon2id key derivation) |
| `MC_API_KEY` | API key for server authentication (defaults to open dev mode) |

### Default policies

Built-in deterministic rules are defined in `config/default-policies.toml`:

- **no-catastrophic-destruction** -- deny catastrophic + irreversible operations
- **no-exfiltration** -- deny suspected data exfiltration
- **no-self-modification** -- deny operations targeting the permission system
- **no-privilege-escalation** -- deny known malicious patterns
- **unknown-destination-review** -- escalate outbound requests to unknown hosts
- **goal-drift-detection** -- escalate operations unrelated to the mission goal

## Architecture

```
~/.claude/plugins/local/mission-clearance/
  hooks/pre-tool-use.py          ← intercepts all Claude Code tool calls
  scripts/mc-mcp-server.py       ← MCP tools for Claude to manage sessions
        │
        ▼
mission-clearance binary (Rust)
        │
  ┌─────┴─────────────────────────────┐
  │            mc-kernel               │
  │  classifier · checker · analyzer  │
  │  session tracker · pipe chains     │
  └─────┬─────────┬──────────┬────────┘
        │         │          │
   mc-policy   mc-vault   mc-trace
   pipeline    AES-256    SHA-256
   rules       Argon2id   chained
        │
     mc-core
     domain types
```

| Crate | Role |
|---|---|
| **mc-core** | Domain types: missions, capabilities, operations, policies, resources |
| **mc-kernel** | Classifier, capability checker, content analyzer, session tracker |
| **mc-policy** | Deterministic policy pipeline with escalation support |
| **mc-trace** | Append-only SHA-256 chained event log and mission delegation graph |
| **mc-vault** | AES-256-GCM encrypted credential store with Argon2id key derivation |
| **mc-api** | Internal HTTP server (axum) used by the hook and MCP tools |
| **mc-sdk** | Embedded kernel used internally by the server |
| **mc-cli** | Binary that runs the server (`mission-clearance start`) |

## License

Licensed under the [MIT License](LICENSE).
