use crate::id::{CapabilityId, MissionId, MissionToken, PolicyId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The lifecycle status of a mission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MissionStatus {
    Created,
    Active,
    Suspended,
    Completed,
    Failed,
    Revoked,
}

/// A scoped execution context -- the "process" in the kernel metaphor.
///
/// Missions form a tree via parent references. Each mission has its own
/// set of capabilities and policies. Delegation creates child missions
/// with narrowed permissions.
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
    /// Returns true if the mission is currently active.
    pub fn is_active(&self) -> bool {
        self.status == MissionStatus::Active
    }

    /// Returns true if the mission is in a terminal state (completed, failed, or revoked).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            MissionStatus::Completed | MissionStatus::Failed | MissionStatus::Revoked
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mission(status: MissionStatus) -> Mission {
        let now = Utc::now();
        Mission {
            id: MissionId::new(),
            parent: None,
            token: MissionToken::new(),
            goal: "test mission".to_string(),
            capabilities: HashSet::new(),
            policies: Vec::new(),
            status,
            depth: 0,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_is_active() {
        assert!(make_mission(MissionStatus::Active).is_active());
        assert!(!make_mission(MissionStatus::Created).is_active());
        assert!(!make_mission(MissionStatus::Suspended).is_active());
        assert!(!make_mission(MissionStatus::Completed).is_active());
    }

    #[test]
    fn test_is_terminal() {
        assert!(make_mission(MissionStatus::Completed).is_terminal());
        assert!(make_mission(MissionStatus::Failed).is_terminal());
        assert!(make_mission(MissionStatus::Revoked).is_terminal());
        assert!(!make_mission(MissionStatus::Active).is_terminal());
        assert!(!make_mission(MissionStatus::Created).is_terminal());
        assert!(!make_mission(MissionStatus::Suspended).is_terminal());
    }
}
