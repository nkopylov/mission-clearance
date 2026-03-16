use crate::id::{OrgPositionId, PrincipalId, TeamId};
use serde::{Deserialize, Serialize};

/// Organizational hierarchy level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OrgLevel {
    Individual,
    Lead,
    Manager,
    Director,
    VP,
    SVP,
    CLevel,
}

/// A slot in the organizational chart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgPosition {
    pub id: OrgPositionId,
    pub title: String,
    pub level: OrgLevel,
    pub reports_to: Option<OrgPositionId>,
    pub team: Option<TeamId>,
    pub holder: Option<PrincipalId>,
}

/// A group of principals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: TeamId,
    pub name: String,
    pub parent: Option<TeamId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_org_level_ordering() {
        assert!(OrgLevel::Individual < OrgLevel::Lead);
        assert!(OrgLevel::Lead < OrgLevel::Manager);
        assert!(OrgLevel::Manager < OrgLevel::Director);
        assert!(OrgLevel::Director < OrgLevel::VP);
        assert!(OrgLevel::VP < OrgLevel::SVP);
        assert!(OrgLevel::SVP < OrgLevel::CLevel);
    }

    #[test]
    fn test_org_position_serialize() {
        let pos = OrgPosition {
            id: OrgPositionId::new(),
            title: "Engineering Manager".to_string(),
            level: OrgLevel::Manager,
            reports_to: None,
            team: None,
            holder: None,
        };
        let json = serde_json::to_string(&pos).unwrap();
        let deser: OrgPosition = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.title, "Engineering Manager");
        assert_eq!(deser.level, OrgLevel::Manager);
    }

    #[test]
    fn test_team_serialize() {
        let team = Team {
            id: TeamId::new(),
            name: "Platform".to_string(),
            parent: None,
        };
        let json = serde_json::to_string(&team).unwrap();
        let deser: Team = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.name, "Platform");
    }
}
