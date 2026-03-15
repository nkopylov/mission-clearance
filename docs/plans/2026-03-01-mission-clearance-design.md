**Note:** This is an archived design document from the initial implementation. The current architecture positions Mission Clearance as a Claude Code security harness. See the main README.md for current documentation.

---

# Mission Clearance: Design Document

**Date:** 2026-03-01
**Status:** Archived

## Overview

Mission Clearance is a Rust-based autonomous agent permission and credential management system. It acts as a transparent proxy/interceptor that sits between agents and external services, gating every operation through a two-dimensional permission model: structural capabilities (what resources exist in your world) and behavioral operation policies (what actions are safe/appropriate in context).

The system uses an OS kernel metaphor: missions are processes, capabilities are file descriptors, policies are syscall filters, protocol adapters are device drivers, and the trace graph is the audit subsystem.

## Requirements

| Decision | Choice |
|---|---|
| Language | Rust |
| Integration | Transparent proxy/interceptor |
| Protocols | HTTP, DB, shell, LLM tool calls |
| Missions | Hierarchical delegation with permission narrowing |
| Policy engine | Pipeline: deterministic -> LLM -> human-in-the-loop |
| Vault | Built-in encrypted credential store |
| Tracing | Append-only event log + materialized graph database |
| API | CLI + HTTP API + Rust SDK |
| Scope | Full system |

## Architecture: Hybrid Kernel

Combines capability tokens (structural, fast) with contextual policy evaluation (behavioral, graduated). Chosen over pure capability-token (too rigid) and pure policy-engine (too slow) approaches.

```
+------------------------------------------------------------------+
|                        Agent Process(es)                          |
|  (any language, any framework - unmodified)                      |
+----------+----------+----------+----------+----------------------+
           | HTTP     | DB       | Shell    | Tool Calls
           v          v          v          v
+------------------------------------------------------------------+
|                    Protocol Adapter Layer                         |
|  +----------+ +----------+ +----------+ +---------------+        |
|  |HTTP Proxy| |DB Proxy  | |Shell Hook| |Tool Call Gate |        |
|  +----+-----+ +----+-----+ +----+-----+ +------+-------+        |
|       +-------------+------------+--------------+                |
|                          |                                       |
|               Normalized OperationRequest                        |
+------------------------------------------------------------------+
                           |
                           v
+------------------------------------------------------------------+
|                         Kernel Core                               |
|                                                                   |
|  +---------------------+    +------------------------------+     |
|  |  Mission Manager     |    |  Capability Checker          |     |
|  |  (process tree)      |--->|  (fast path: O(1) lookup)   |     |
|  +---------------------+    +----------+-------------------+     |
|                                        |                          |
|                              +---------v----------+               |
|                              |  Policy Pipeline    |               |
|                              |  +---------------+  |               |
|                              |  | Deterministic  |  |               |
|                              |  | (rules, ACLs)  |  |               |
|                              |  +-------+-------+  |               |
|                              |  +-------v-------+  |               |
|                              |  | LLM Judge     |  |               |
|                              |  | (contextual)  |  |               |
|                              |  +-------+-------+  |               |
|                              |  +-------v-------+  |               |
|                              |  | Human-in-Loop |  |               |
|                              |  | (escalation)  |  |               |
|                              |  +---------------+  |               |
|                              +--------------------+               |
|                                        |                          |
|  +---------------------+    +---------v----------+               |
|  |  Vault               |    |  Trace Engine      |               |
|  |  (encrypted store)   |    |  (events + graph)  |               |
|  +---------------------+    +--------------------+               |
+------------------------------------------------------------------+
                           |
                           v
+------------------------------------------------------------------+
|                    External Services                              |
|  (APIs, databases, filesystems, LLM providers, ...)              |
+------------------------------------------------------------------+
```

## Core Domain Model

### 1. Resource

Anything an agent might access, identified by a URI scheme.

```
http://api.github.com/repos/*
db://postgres/production/users
shell://localhost/bin/git
llm://openai/gpt-4/chat
file:///etc/config/*
```

Resources form a hierarchy via URI path segments, enabling wildcard matching.

### 2. Capability

A bounded permission over a resource. Like a file descriptor - an opaque handle granting specific operations on a specific resource scope.

```rust
Capability {
    id: CapabilityId,
    resource_pattern: ResourcePattern,  // e.g., "http://api.github.com/repos/myorg/*"
    operations: Set<Operation>,         // e.g., {Read, Write}
    constraints: Constraints,           // max rate, time window, etc.
    delegatable: bool,                  // can this be passed to sub-missions?
}
```

### 3. Mission

A scoped execution context - the "process" in our kernel.

```rust
Mission {
    id: MissionId,
    parent: Option<MissionId>,
    goal: String,                       // natural language description
    capabilities: Set<CapabilityId>,    // what this mission CAN do
    policies: Vec<PolicyId>,            // additional contextual rules
    status: MissionStatus,              // Active, Suspended, Completed, Revoked, Failed
    created_at: Timestamp,
}
```

### 4. Operation Request

Every intercepted action becomes a normalized operation request - the "syscall."

```rust
OperationRequest {
    id: RequestId,
    mission_id: MissionId,
    resource: ResourceUri,
    operation: Operation,               // Read, Write, Execute, Delete, Connect, Delegate
    context: OperationContext,           // protocol-specific metadata
    justification: String,              // agent's stated reason
    chain: Vec<RequestId>,              // parent operations that led to this
}
```

### 5. Policy

A rule that evaluates an operation request in context.

```rust
Policy {
    id: PolicyId,
    name: String,
    scope: PolicyScope,                 // Global, Resource-specific, Mission-specific
    evaluator: PolicyEvaluator,         // Deterministic, LLM, Human
    priority: u32,                      // order in pipeline
    rule: PolicyRule,                   // the actual logic
}
```

### 6. Vault Entry

A secret or credential managed by the built-in encrypted store.

```rust
VaultEntry {
    id: VaultEntryId,
    name: String,
    secret_type: SecretType,            // ApiKey, Token, Certificate, ConnectionString, ...
    encrypted_value: Vec<u8>,
    bound_to: Set<ResourcePattern>,     // which resources this credential unlocks
    rotation_policy: Option<RotationPolicy>,
}
```

### 7. Trace Event

An immutable record of something that happened.

```rust
TraceEvent {
    id: EventId,
    timestamp: Timestamp,
    mission_id: MissionId,
    event_type: TraceEventType,
    parent_event: Option<EventId>,      // causal parent
    payload: serde_json::Value,         // type-specific data
}
```

## Two-Dimensional Permission Model

### Dimension 1: Capabilities (structural)

"Does this mission have access to this resource?" - fast, binary, O(1) lookup.

### Dimension 2: Operation Policies (behavioral)

"Is this operation safe/appropriate given its semantics, context, and the mission's intent?" - contextual, graduated.

Operation policies are independent of resource capabilities. Even if you hold `shell://localhost/*` with `Execute`, an operation policy can still block `rm -rf /`.

### Operation Classification

Every OperationRequest is classified along multiple axes:

```rust
OperationClassification {
    // Structural
    destructiveness: Destructiveness,  // None, Low, Medium, High, Catastrophic
    reversibility: Reversibility,      // Reversible, PartiallyReversible, Irreversible
    scope: BlastRadius,               // Single, Local, Service, Global

    // Behavioral
    data_flow: DataFlowDirection,     // Inbound, Outbound, Internal, Exfiltration(suspected)
    target_trust: TrustLevel,         // Known, Unknown, Untrusted
    pattern: OperationPattern,        // Normal, Unusual, Suspicious, KnownMalicious

    // Mission alignment
    goal_relevance: GoalRelevance,    // DirectlyRelevant, TangentiallyRelevant, Unrelated, Contradictory
}
```

**Deterministic classifiers** (fast, always run):
- Command pattern matching: `rm -rf`, `DROP TABLE`, `chmod 777`, `curl | bash` -> high destructiveness
- Network destination analysis: outbound to unknown domains -> suspected exfiltration
- Known-dangerous pattern database: fork bombs, reverse shells, privilege escalation
- Data flow tracking: vault-sourced values appearing in outbound requests -> exfiltration

**LLM classifier** (runs when deterministic signals are ambiguous):
- Mission goal alignment checking
- Prompt injection detection
- Behavioral anomaly detection

### Taint Analysis (Exfiltration Prevention)

- Values read from the vault are tainted
- Taint propagates through operations (derived values inherit taint)
- If a tainted value appears in an outbound request to an untrusted destination -> classified as exfiltration
- Lightweight tracking at the proxy level (request/response boundary, not full program analysis)

## Policy Pipeline

```
OperationRequest
       |
       v
+---------------------+
| 1. Capability Check  |---- No capability? ---- DENY
|    (resource scope)  |
+----------+----------+
           | has capability
           v
+---------------------+
| 2. Operation         |---- Classifies the operation
|    Classifier        |     along all axes
+----------+----------+
           | classification
           v
+---------------------+
| 3. Deterministic     |---- Hard rules:
|    Policies          |     - Deny catastrophic+irreversible
|                      |     - Deny known exfiltration patterns
|                      |     - Deny known malicious patterns
|                      |     - Rate limits, time windows
+----------+----------+
           | not denied
           v
+---------------------+
| 4. LLM Judge         |---- Contextual evaluation:
|    (with full trace) |     - Mission goal alignment
|                      |     - Prompt injection detection
|                      |     - Justification coherence
|                      |---- Can: ALLOW, DENY, ESCALATE
+----------+----------+
           | escalated or high-risk
           v
+---------------------+
| 5. Human-in-the-Loop|---- Full context:
|                      |     - Mission goal & history
|                      |     - Request & justification
|                      |     - Classification & risk
|                      |     - LLM judge's reasoning
+----------+----------+
           |
           v
       DECISION
```

### Built-in Operation Policy Templates

```toml
[policy.no-catastrophic-destruction]
deny_when = "destructiveness == Catastrophic AND reversibility == Irreversible"

[policy.no-exfiltration]
deny_when = "data_flow == Exfiltration"

[policy.no-self-modification]
deny_when = "target contains 'mission-clearance' OR target contains 'system-prompt'"

[policy.no-privilege-escalation]
deny_when = "pattern == PrivilegeEscalation"

[policy.unknown-destination-review]
escalate_when = "data_flow == Outbound AND target_trust == Unknown"

[policy.goal-drift-detection]
escalate_when = "goal_relevance == Unrelated OR goal_relevance == Contradictory"
```

## Mission Lifecycle & Delegation

### Mission States

```
Created -> Active -> Completed / Failed
Active -> Suspended -> Active (resume)
Any state -> Revoked (cascades to all children)
```

### Delegation ("fork" semantics)

When an agent delegates to a sub-agent:

1. **Subset only**: Child capabilities must be a subset of parent capabilities
2. **Narrowing only**: Resource patterns can only get more specific, never broader
3. **Delegatable flag**: Only capabilities marked `delegatable: true` can be passed down
4. **Additive policies**: Children inherit all parent policies AND can have additional restrictions
5. **Revocation cascades**: Revoking a parent immediately revokes all descendants
6. **Depth limits**: Configurable maximum delegation depth

### Mission-to-Agent Mapping

Missions are identified via opaque tokens injected into the agent's environment:
- HTTP: `X-Mission-Token` header
- DB: connection tag / `application_name`
- Shell: `MISSION_TOKEN` environment variable
- Tool calls: wrapper injects into tool call metadata

## Vault & Credential Management

### Storage

- **Encryption**: AES-256-GCM, master key derived via Argon2id
- **Format**: Individually encrypted entries in SQLite
- **Persistence**: `~/.mission-clearance/vault.db`

### Credential Binding

Every vault entry is bound to resource patterns. When the proxy allows an operation, it looks up bound credentials and injects them transparently. Agents never see raw secrets.

### Operations

```
vault add <name> --type api-key --resource "http://api.github.com/*" --value <secret>
vault list
vault rotate <name>
vault revoke <name>
vault export --encrypted --to <path>
vault import --from <path>
```

## Protocol Adapters

### Adapter Trait

```rust
trait ProtocolAdapter {
    fn identify_mission(&self, raw: &RawRequest) -> Result<MissionToken>;
    fn normalize(&self, raw: &RawRequest) -> Result<OperationRequest>;
    fn inject_credentials(&self, raw: &mut RawRequest, creds: &[Credential]) -> Result<()>;
    fn forward(&self, raw: RawRequest) -> Result<RawResponse>;
    fn deny(&self, reason: &PolicyDecision) -> RawResponse;
}
```

### HTTP Proxy Adapter
- HTTP/HTTPS proxy with MITM (generated CA cert for TLS inspection)
- Agent's `HTTP_PROXY`/`HTTPS_PROXY` env vars point to it
- URL -> resource URI, method -> operation, `Authorization` header injection

### DB Proxy Adapter
- Wire-protocol proxy for Postgres/MySQL
- SQL AST parsing for operation classification (`DROP TABLE` -> Catastrophic)
- Transparent credential rewriting

### Shell Adapter
- Sandboxed shell wrapper (bubblewrap/firejail optional)
- Command interception before execution
- Pattern database for dangerous commands
- Environment variable injection for credentials

### Tool Call Adapter
- Wraps LLM tool executor
- Tool name + args -> resource URI + operation
- Natural justification available from LLM reasoning
- Credential parameter injection

## Trace Graph & Event Log

### Dual Storage

**Event Log** (source of truth):
- Append-only, immutable, SQLite-based
- Cryptographic chaining (each event hashes the previous, tamper-evident)

**Mission Graph** (materialized view):
- Adjacency list in SQLite (nodes + edges)
- Real-time updates from event stream

### Event Types

```rust
enum TraceEventType {
    // Mission lifecycle
    MissionCreated, MissionDelegated, MissionCompleted, MissionRevoked,
    // Operation flow
    OperationRequested, OperationClassified, CapabilityChecked,
    PolicyEvaluated, OperationAllowed, OperationDenied, OperationEscalated,
    // Human interaction
    HumanPrompted, HumanResponded,
    // Vault
    CredentialAccessed, CredentialRotated, CredentialRevoked,
    // Anomaly
    TaintDetected, GoalDriftDetected, PromptInjectionSuspected,
}
```

### Graph Structure

- **Nodes**: Mission, Operation, Decision, HumanInteraction
- **Edges**: spawned (delegation), performed, caused (causal chain), evaluated_by, escalated_to, accessed (vault)

### Query Interface

```rust
trait TraceQuery {
    fn causal_chain(&self, event_id: EventId) -> Vec<TraceEvent>;
    fn mission_tree(&self, mission_id: MissionId) -> MissionTree;
    fn denials(&self, filter: DenialFilter) -> Vec<TraceEvent>;
    fn anomalies(&self, mission_id: Option<MissionId>) -> Vec<TraceEvent>;
    fn export_graph(&self, format: GraphFormat) -> Vec<u8>;
}
```

### LLM Context Summarization

When the LLM judge evaluates a request, it receives a focused summary (not the full log):
- Mission goal and parent chain
- Last N operations in this mission
- Causal chain leading to this request
- Any anomaly events in the mission's history

## API & SDK

### HTTP API

```
POST   /api/v1/missions                  # Create root mission
POST   /api/v1/missions/:id/delegate     # Delegate sub-mission
GET    /api/v1/missions/:id              # Inspect mission
GET    /api/v1/missions/:id/tree         # Full subtree
DELETE /api/v1/missions/:id              # Revoke (cascading)

POST   /api/v1/operations/request        # Submit operation for evaluation
GET    /api/v1/operations/:id/status     # Check decision

POST   /api/v1/vault/entries             # Add entry
GET    /api/v1/vault/entries             # List (metadata only)
POST   /api/v1/vault/entries/:id/rotate  # Rotate

GET    /api/v1/trace/events?mission=:id  # Query events
GET    /api/v1/trace/graph?mission=:id   # Export graph
GET    /api/v1/trace/anomalies           # Recent anomalies
WS     /api/v1/trace/stream              # Real-time event stream

GET    /api/v1/policies                  # List active policies
POST   /api/v1/policies/test             # Dry-run evaluation
```

Protected by API key or mTLS.

### Rust SDK (`mc-sdk`)

Two modes:
- **Client mode**: Connects to a running `mission-clearance` daemon over HTTP
- **Embedded mode**: Kernel runs in-process (for testing or single-agent setups)

## Configuration

```toml
[kernel]
max_delegation_depth = 10
default_mission_timeout = "2h"
fail_closed = true

[vault]
path = "~/.mission-clearance/vault.db"
master_key_source = "passphrase"    # or "env:MC_MASTER_KEY" or "keychain"

[adapters.http]
listen = "127.0.0.1:8080"
tls_inspection = true
ca_cert_path = "~/.mission-clearance/ca.pem"

[adapters.db]
listen = "127.0.0.1:5433"
upstream_protocol = "postgres"

[adapters.shell]
sandbox = "bubblewrap"

[adapters.tool_call]
mode = "wrapper"

[policy_pipeline]
layers = ["deterministic", "llm", "human"]

[policy_pipeline.llm]
provider = "anthropic"
model = "claude-sonnet-4-6"
max_context_events = 50

[policy_pipeline.human]
interface = "terminal"
timeout = "5m"

[trace]
path = "~/.mission-clearance/trace.db"
chain_integrity = true

[operation_policies]
include = ["defaults", "custom-policies.toml"]
```

## Crate Structure

```
mission-clearance/
├── Cargo.toml                    # workspace root
├── crates/
│   ├── mc-core/                  # Domain types, traits (no IO)
│   │   └── src/
│   │       ├── mission.rs
│   │       ├── capability.rs
│   │       ├── policy.rs
│   │       ├── operation.rs
│   │       ├── trace.rs
│   │       └── vault.rs
│   ├── mc-vault/                 # Encrypted credential store
│   │   └── src/
│   │       ├── store.rs          # SQLite + AES-256-GCM
│   │       ├── crypto.rs         # Encryption, key derivation
│   │       └── rotation.rs
│   ├── mc-kernel/                # Mission manager, capability checker
│   │   └── src/
│   │       ├── manager.rs        # Mission lifecycle, delegation
│   │       ├── checker.rs        # Capability validation
│   │       └── classifier.rs     # Operation classification
│   ├── mc-policy/                # Policy pipeline
│   │   └── src/
│   │       ├── pipeline.rs
│   │       ├── deterministic.rs
│   │       ├── llm_judge.rs
│   │       ├── human.rs
│   │       └── taint.rs
│   ├── mc-trace/                 # Event log + graph
│   │   └── src/
│   │       ├── event_log.rs
│   │       ├── graph.rs
│   │       └── query.rs
│   ├── mc-adapters/              # Protocol adapters
│   │   └── src/
│   │       ├── http.rs
│   │       ├── db.rs
│   │       ├── shell.rs
│   │       └── tool_call.rs
│   ├── mc-api/                   # HTTP API server (axum)
│   │   └── src/
│   │       └── lib.rs
│   ├── mc-sdk/                   # Rust SDK (client + embedded)
│   │   └── src/
│   │       ├── client.rs
│   │       └── embedded.rs
│   └── mc-cli/                   # CLI binary
│       └── src/
│           └── main.rs
└── docs/
    └── plans/
```

## Key Design Principles

1. **Fail closed**: No capability = denied. No policy match = escalate (not allow).
2. **Credential injection**: Agents never see raw secrets. Proxy injects after approval.
3. **Mission isolation**: Sub-missions cannot access parent capabilities unless explicitly delegated.
4. **Immutable trace**: Every decision is recorded. Event log is append-only with cryptographic chaining.
5. **Two-dimensional security**: Capabilities gate resource access; operation policies gate behavioral safety.
6. **Monotonic narrowing**: Delegation can only restrict, never expand permissions.
