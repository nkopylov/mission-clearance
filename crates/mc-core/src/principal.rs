use crate::id::{MissionId, OrgPositionId, PrincipalId, TeamId};
use serde::{Deserialize, Serialize};

/// The kind of entity a principal represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrincipalKind {
    Human,
    AiAgent,
    ServiceAccount,
    Team,
}

/// The lifecycle status of a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalStatus {
    Active,
    Suspended,
    Revoked,
}

/// Trust level assigned to a principal, used in delegation policy decisions.
///
/// Higher numeric value = more trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PrincipalTrustLevel {
    Agent = 1,
    ServiceAccount = 2,
    Human = 3,
}

/// Type-specific details for a principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrincipalDetails {
    Human {
        email: String,
        external_id: Option<String>,
    },
    AiAgent {
        model: String,
        spawned_by: Option<PrincipalId>,
        spawning_mission: Option<MissionId>,
    },
    ServiceAccount {
        purpose: String,
        owner: PrincipalId,
    },
    Team {
        description: String,
    },
}

/// Any entity that can hold permissions -- humans, AI agents, service accounts, or teams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,
    pub kind: PrincipalKind,
    pub status: PrincipalStatus,
    pub trust_level: PrincipalTrustLevel,
    pub display_name: String,
    pub details: PrincipalDetails,
    pub org_position: Option<OrgPositionId>,
    pub teams: Vec<TeamId>,
}

impl Principal {
    pub fn is_active(&self) -> bool {
        self.status == PrincipalStatus::Active
    }
}

/// Compact summary of a principal, used in chain verification context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalSummary {
    pub id: PrincipalId,
    pub kind: PrincipalKind,
    pub trust_level: PrincipalTrustLevel,
    pub display_name: String,
}

impl From<&Principal> for PrincipalSummary {
    fn from(p: &Principal) -> Self {
        Self {
            id: p.id,
            kind: p.kind,
            trust_level: p.trust_level,
            display_name: p.display_name.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_kind_variants() {
        let kinds = [
            PrincipalKind::Human,
            PrincipalKind::AiAgent,
            PrincipalKind::ServiceAccount,
            PrincipalKind::Team,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let deser: PrincipalKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, kind);
        }
    }

    #[test]
    fn test_trust_level_ordering() {
        assert!(PrincipalTrustLevel::Agent < PrincipalTrustLevel::ServiceAccount);
        assert!(PrincipalTrustLevel::ServiceAccount < PrincipalTrustLevel::Human);
    }

    #[test]
    fn test_principal_serialize() {
        let principal = Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::Human,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::Human,
            display_name: "Alice".to_string(),
            details: PrincipalDetails::Human {
                email: "alice@example.com".to_string(),
                external_id: None,
            },
            org_position: None,
            teams: vec![],
        };
        assert!(principal.is_active());
        let json = serde_json::to_string(&principal).unwrap();
        let deser: Principal = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.display_name, "Alice");
        assert_eq!(deser.kind, PrincipalKind::Human);
    }

    #[test]
    fn test_principal_summary_from() {
        let principal = Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::AiAgent,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::Agent,
            display_name: "Agent-1".to_string(),
            details: PrincipalDetails::AiAgent {
                model: "claude-4".to_string(),
                spawned_by: None,
                spawning_mission: None,
            },
            org_position: None,
            teams: vec![],
        };
        let summary = PrincipalSummary::from(&principal);
        assert_eq!(summary.display_name, "Agent-1");
        assert_eq!(summary.kind, PrincipalKind::AiAgent);
    }
}
