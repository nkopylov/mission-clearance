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
