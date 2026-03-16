use crate::id::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An immutable record of something that happened in the system.
///
/// Events form a cryptographically chained log (each event hashes the previous)
/// and a causal graph via parent_event references.
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

/// The type of trace event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    // Permission graph
    PrincipalCreated,
    PrincipalSuspended,
    PrincipalRevoked,
    RoleAssigned,
    RoleRevoked,
    DelegationCreated,
    DelegationRevoked,
    ChainVerified,
    ChainDenied,
    ChainLlmEvaluated,
    CascadeRevocationStarted,
    CascadeRevocationCompleted,
    OneTimePermissionConsumed,
    BoundedAuthorizationCreated,
}

/// Format for graph export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// The type of relationship between graph nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeType {
    Spawned,
    Performed,
    Caused,
    EvaluatedBy,
    EscalatedTo,
    Accessed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_event_type_variants() {
        // Verify all variants exist and can be serialized
        let types = vec![
            TraceEventType::MissionCreated,
            TraceEventType::MissionDelegated,
            TraceEventType::MissionCompleted,
            TraceEventType::MissionRevoked,
            TraceEventType::MissionSuspended,
            TraceEventType::MissionResumed,
            TraceEventType::OperationRequested,
            TraceEventType::OperationClassified,
            TraceEventType::CapabilityChecked,
            TraceEventType::PolicyEvaluated,
            TraceEventType::OperationAllowed,
            TraceEventType::OperationDenied,
            TraceEventType::OperationEscalated,
            TraceEventType::HumanPrompted,
            TraceEventType::HumanResponded,
            TraceEventType::CredentialAccessed,
            TraceEventType::CredentialRotated,
            TraceEventType::CredentialRevoked,
            TraceEventType::TaintDetected,
            TraceEventType::GoalDriftDetected,
            TraceEventType::PromptInjectionSuspected,
            // Permission graph
            TraceEventType::PrincipalCreated,
            TraceEventType::PrincipalSuspended,
            TraceEventType::PrincipalRevoked,
            TraceEventType::RoleAssigned,
            TraceEventType::RoleRevoked,
            TraceEventType::DelegationCreated,
            TraceEventType::DelegationRevoked,
            TraceEventType::ChainVerified,
            TraceEventType::ChainDenied,
            TraceEventType::ChainLlmEvaluated,
            TraceEventType::CascadeRevocationStarted,
            TraceEventType::CascadeRevocationCompleted,
            TraceEventType::OneTimePermissionConsumed,
            TraceEventType::BoundedAuthorizationCreated,
        ];
        assert_eq!(types.len(), 35);
        for t in &types {
            let json = serde_json::to_string(t).unwrap();
            let deser: TraceEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, t);
        }
    }

    #[test]
    fn test_trace_event_serialize() {
        let event = TraceEvent {
            id: EventId::new(),
            sequence: 0,
            timestamp: Utc::now(),
            mission_id: MissionId::new(),
            event_type: TraceEventType::MissionCreated,
            parent_event: None,
            payload: serde_json::json!({"goal": "deploy service"}),
            prev_hash: "genesis".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deser: TraceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.sequence, 0);
        assert_eq!(deser.prev_hash, "genesis");
    }

    #[test]
    fn test_graph_edge_serialize() {
        let edge = GraphEdge {
            from: EventId::new(),
            to: EventId::new(),
            edge_type: EdgeType::Spawned,
        };
        let json = serde_json::to_string(&edge).unwrap();
        let deser: GraphEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.edge_type, EdgeType::Spawned);
    }

    #[test]
    fn test_graph_node_variants() {
        let mission_node = GraphNode::Mission {
            id: MissionId::new(),
            goal: "test".to_string(),
        };
        let op_node = GraphNode::Operation {
            id: RequestId::new(),
            resource: "http://example.com".to_string(),
        };
        let decision_node = GraphNode::Decision {
            id: EventId::new(),
            kind: "Allow".to_string(),
        };

        for node in [mission_node, op_node, decision_node] {
            let json = serde_json::to_string(&node).unwrap();
            let _: GraphNode = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_edge_type_variants() {
        let types = vec![
            EdgeType::Spawned,
            EdgeType::Performed,
            EdgeType::Caused,
            EdgeType::EvaluatedBy,
            EdgeType::EscalatedTo,
            EdgeType::Accessed,
        ];
        assert_eq!(types.len(), 6);
        for t in &types {
            let json = serde_json::to_string(t).unwrap();
            let deser: EdgeType = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, t);
        }
    }
}
