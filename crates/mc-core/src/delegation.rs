use crate::id::{DelegationEdgeId, GrantId, PrincipalId};
use crate::operation::Operation;
use crate::principal::PrincipalKind;
use crate::resource::ResourcePattern;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::capability::Capability;

/// Constraints on a delegation edge between two principals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationConstraints {
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    /// Maximum number of times the delegated capability can be used.
    pub max_operations: Option<u64>,
    /// Number of operations consumed so far.
    pub operations_used: u64,
    /// Whether the target can re-delegate to others.
    pub sub_delegation_allowed: bool,
    /// Maximum depth from this edge onward.
    pub max_sub_depth: Option<u32>,
    /// Which principal kinds the target can delegate to.
    pub allowed_delegate_kinds: Option<Vec<PrincipalKind>>,
    /// Narrowed resource scope at this edge.
    pub resource_scope: Option<ResourcePattern>,
    /// Narrowed operation scope at this edge.
    pub operation_scope: Option<HashSet<Operation>>,
    /// If true, the delegation is consumed on first use.
    pub one_time: bool,
}

impl DelegationConstraints {
    /// Check if this delegation has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(until) = &self.valid_until {
            Utc::now() > *until
        } else {
            false
        }
    }

    /// Check if the operation limit has been reached.
    pub fn is_exhausted(&self) -> bool {
        if let Some(max) = self.max_operations {
            self.operations_used >= max
        } else {
            false
        }
    }
}

impl Default for DelegationConstraints {
    fn default() -> Self {
        Self {
            valid_from: Utc::now(),
            valid_until: None,
            max_operations: None,
            operations_used: 0,
            sub_delegation_allowed: false,
            max_sub_depth: None,
            allowed_delegate_kinds: None,
            resource_scope: None,
            operation_scope: None,
            one_time: false,
        }
    }
}

/// A directed edge representing explicit delegation from one principal to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationEdge {
    pub id: DelegationEdgeId,
    pub from: PrincipalId,
    pub to: PrincipalId,
    pub constraints: DelegationConstraints,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

/// The type of bound on a one-time or limited-use authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BoundedType {
    /// Single use -- consumed on first use.
    OneTime,
    /// Limited number of uses.
    NTimes { max: u64 },
    /// Time-bounded -- expires at a specific time.
    TimeBounded { expires_at: DateTime<Utc> },
    /// Both count and time bounded.
    BoundedWindow {
        max_uses: u64,
        expires_at: DateTime<Utc>,
    },
}

/// A bounded authorization grant -- one-time or limited-use permission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundedAuthorization {
    pub id: GrantId,
    pub principal: PrincipalId,
    /// Frozen snapshot of the capability at grant time.
    pub capability: Capability,
    pub bound_type: BoundedType,
    pub consumed: bool,
    pub use_count: u64,
    pub created_at: DateTime<Utc>,
}

/// Anomaly flags detected during chain verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChainAnomalyFlag {
    /// Delegation chain depth exceeds 3x the median.
    UnusualDepth { depth: u32, median: u32 },
    /// Multi-level delegation happened very quickly (< 5 seconds for 3+ levels).
    RapidDelegation { levels: u32, seconds: f64 },
    /// Goal coherence score is low across the chain.
    LowGoalCoherence { score: f64 },
    /// Trust level decreased along the chain.
    TrustLevelDrop { from: String, to: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_constraints_default() {
        let c = DelegationConstraints::default();
        assert!(!c.is_expired());
        assert!(!c.is_exhausted());
        assert!(!c.sub_delegation_allowed);
        assert!(!c.one_time);
    }

    #[test]
    fn test_delegation_constraints_expired() {
        let c = DelegationConstraints {
            valid_until: Some(Utc::now() - chrono::Duration::hours(1)),
            ..Default::default()
        };
        assert!(c.is_expired());
    }

    #[test]
    fn test_delegation_constraints_exhausted() {
        let c = DelegationConstraints {
            max_operations: Some(5),
            operations_used: 5,
            ..Default::default()
        };
        assert!(c.is_exhausted());
    }

    #[test]
    fn test_delegation_edge_serialize() {
        let edge = DelegationEdge {
            id: DelegationEdgeId::new(),
            from: PrincipalId::new(),
            to: PrincipalId::new(),
            constraints: DelegationConstraints::default(),
            revoked: false,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&edge).unwrap();
        let deser: DelegationEdge = serde_json::from_str(&json).unwrap();
        assert!(!deser.revoked);
    }

    #[test]
    fn test_bounded_type_variants() {
        let types = vec![
            BoundedType::OneTime,
            BoundedType::NTimes { max: 10 },
            BoundedType::TimeBounded {
                expires_at: Utc::now(),
            },
            BoundedType::BoundedWindow {
                max_uses: 5,
                expires_at: Utc::now(),
            },
        ];
        for bt in &types {
            let json = serde_json::to_string(bt).unwrap();
            let _: BoundedType = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_chain_anomaly_flags() {
        let flags = vec![
            ChainAnomalyFlag::UnusualDepth {
                depth: 10,
                median: 3,
            },
            ChainAnomalyFlag::RapidDelegation {
                levels: 4,
                seconds: 2.0,
            },
            ChainAnomalyFlag::LowGoalCoherence { score: 0.2 },
            ChainAnomalyFlag::TrustLevelDrop {
                from: "Human".to_string(),
                to: "Agent".to_string(),
            },
        ];
        for flag in &flags {
            let json = serde_json::to_string(flag).unwrap();
            let deser: ChainAnomalyFlag = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, flag);
        }
    }
}
