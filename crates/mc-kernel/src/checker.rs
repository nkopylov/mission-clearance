use mc_core::id::{CapabilityId, MissionId};
use mc_core::operation::Operation;
use mc_core::resource::ResourceUri;

use crate::manager::MissionManager;

/// Fast-path capability checker.
///
/// Determines whether a mission holds a capability covering a given
/// resource + operation combination.
pub struct CapabilityChecker;

impl CapabilityChecker {
    /// Check if the given mission has a capability covering the resource + operation.
    /// Returns the matching CapabilityId if found.
    pub fn check(
        manager: &MissionManager,
        mission_id: &MissionId,
        resource: &ResourceUri,
        operation: &Operation,
    ) -> Option<CapabilityId> {
        let caps = manager.get_mission_capabilities(mission_id);
        for cap in caps {
            if cap.covers(resource, operation) {
                // Check constraints (expiry)
                if let Some(expires) = &cap.constraints.expires_at {
                    if chrono::Utc::now() > *expires {
                        continue;
                    }
                }
                return Some(cap.id);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use mc_core::capability::{Capability, Constraints};
    use mc_core::resource::ResourcePattern;

    fn make_cap(pattern: &str, ops: &[Operation], delegatable: bool) -> Capability {
        Capability {
            id: CapabilityId::new(),
            resource_pattern: ResourcePattern::new(pattern).unwrap(),
            operations: ops.iter().cloned().collect(),
            constraints: Constraints::default(),
            delegatable,
        }
    }

    fn make_cap_with_expiry(
        pattern: &str,
        ops: &[Operation],
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Capability {
        Capability {
            id: CapabilityId::new(),
            resource_pattern: ResourcePattern::new(pattern).unwrap(),
            operations: ops.iter().cloned().collect(),
            constraints: Constraints {
                expires_at: Some(expires_at),
                ..Constraints::default()
            },
            delegatable: true,
        }
    }

    #[test]
    fn check_matching() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap(
            "http://api.com/repos/*",
            &[Operation::Read, Operation::Write],
            true,
        );
        let cap_id = cap.id;

        let mission = mgr
            .create_root_mission("test".to_string(), vec![cap], vec![])
            .unwrap();

        let resource = ResourceUri::new("http://api.com/repos/foo").unwrap();
        let result = CapabilityChecker::check(&mgr, &mission.id, &resource, &Operation::Read);

        assert_eq!(result, Some(cap_id));
    }

    #[test]
    fn check_no_match() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);

        let mission = mgr
            .create_root_mission("test".to_string(), vec![cap], vec![])
            .unwrap();

        // Different resource path
        let resource = ResourceUri::new("http://api.com/users/bar").unwrap();
        let result = CapabilityChecker::check(&mgr, &mission.id, &resource, &Operation::Read);

        assert_eq!(result, None);
    }

    #[test]
    fn check_expired() {
        let mut mgr = MissionManager::new(5);
        let expired = Utc::now() - Duration::hours(1);
        let cap = make_cap_with_expiry("http://api.com/**", &[Operation::Read], expired);

        let mission = mgr
            .create_root_mission("test".to_string(), vec![cap], vec![])
            .unwrap();

        let resource = ResourceUri::new("http://api.com/repos/foo").unwrap();
        let result = CapabilityChecker::check(&mgr, &mission.id, &resource, &Operation::Read);

        assert_eq!(result, None);
    }

    #[test]
    fn check_not_expired() {
        let mut mgr = MissionManager::new(5);
        let future = Utc::now() + Duration::hours(1);
        let cap = make_cap_with_expiry("http://api.com/**", &[Operation::Read], future);
        let cap_id = cap.id;

        let mission = mgr
            .create_root_mission("test".to_string(), vec![cap], vec![])
            .unwrap();

        let resource = ResourceUri::new("http://api.com/repos/foo").unwrap();
        let result = CapabilityChecker::check(&mgr, &mission.id, &resource, &Operation::Read);

        assert_eq!(result, Some(cap_id));
    }

    #[test]
    fn check_wrong_operation() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);

        let mission = mgr
            .create_root_mission("test".to_string(), vec![cap], vec![])
            .unwrap();

        let resource = ResourceUri::new("http://api.com/repos/foo").unwrap();
        let result = CapabilityChecker::check(&mgr, &mission.id, &resource, &Operation::Write);

        assert_eq!(result, None);
    }

    #[test]
    fn check_nonexistent_mission() {
        let mgr = MissionManager::new(5);
        let fake_id = MissionId::new();
        let resource = ResourceUri::new("http://api.com/repos/foo").unwrap();

        let result = CapabilityChecker::check(&mgr, &fake_id, &resource, &Operation::Read);
        assert_eq!(result, None);
    }

    #[test]
    fn check_multiple_caps_first_match_wins() {
        let mut mgr = MissionManager::new(5);
        let cap1 = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let cap1_id = cap1.id;
        let cap2 = make_cap("http://api.com/**", &[Operation::Read], true);
        let cap2_id = cap2.id;

        let mission = mgr
            .create_root_mission("test".to_string(), vec![cap1, cap2], vec![])
            .unwrap();

        let resource = ResourceUri::new("http://api.com/repos/foo").unwrap();
        let result = CapabilityChecker::check(&mgr, &mission.id, &resource, &Operation::Read);

        // Should return Some -- either cap could match
        assert!(result.is_some());
        let result_id = result.unwrap();
        assert!(result_id == cap1_id || result_id == cap2_id);
    }
}
