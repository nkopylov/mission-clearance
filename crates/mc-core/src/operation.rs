use serde::{Deserialize, Serialize};

/// The type of operation being performed on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operation {
    Read,
    Write,
    Execute,
    Delete,
    Connect,
    Delegate,
}

/// Classification of an operation's risk profile along multiple axes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationClassification {
    pub destructiveness: Destructiveness,
    pub reversibility: Reversibility,
    pub blast_radius: BlastRadius,
    pub data_flow: DataFlowDirection,
    pub target_trust: TrustLevel,
    pub pattern: OperationPattern,
    pub goal_relevance: GoalRelevance,
    #[serde(default)]
    pub signals: OperationSignals,
}

/// Boolean signal flags extracted from an operation request.
///
/// Signals represent semantic facts about what a command does (reads sensitive data,
/// sends to network, etc.) rather than matching specific syntax patterns.
/// Policy rules compose these signals to make decisions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationSignals {
    pub reads_sensitive_source: bool,
    pub has_network_sink: bool,
    pub executes_dynamic_code: bool,
    pub writes_persistence_point: bool,
    pub modifies_security_controls: bool,
    pub uses_obfuscation: bool,
    pub has_pipe_chain: bool,
    #[serde(default)]
    pub pipe_chain_taint: Option<PipeChainTaint>,
    /// None = not enriched, Some(true) = safe, Some(false) = dangerous
    #[serde(default)]
    pub dynamic_code_is_benign: Option<bool>,
}

/// Taint analysis result for a pipe chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeChainTaint {
    pub segments: Vec<PipeSegment>,
    pub source_to_sink_flow: bool,
}

/// A single segment of a pipe chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeSegment {
    pub raw: String,
    pub role: PipeSegmentRole,
}

/// Classification of a pipe segment's role in a data flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipeSegmentRole {
    SensitiveSource,
    Transform,
    NetworkSink,
    Neutral,
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

/// How relevant an operation is to the current mission goal.
///
/// The `Unknown` variant is the default assigned by the deterministic
/// classifier when no LLM evaluation is available.  When the LLM judge is
/// implemented, it will populate this field with one of the other variants
/// based on semantic analysis of the operation relative to the mission goal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GoalRelevance {
    DirectlyRelevant,
    TangentiallyRelevant,
    Unrelated,
    Contradictory,
    /// Goal relevance has not been evaluated (e.g. the LLM judge is unavailable).
    Unknown,
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
    FileWrite {
        path: String,
        content_preview: String,
    },
}

/// A normalized operation request -- the "syscall" of the permission system.
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
