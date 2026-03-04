use std::collections::HashMap;

use chrono::Utc;
use mc_core::capability::Capability;
use mc_core::id::{CapabilityId, MissionId, MissionToken, PolicyId};
use mc_core::mission::{Mission, MissionStatus};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MissionError {
    #[error("mission not found: {0}")]
    NotFound(MissionId),
    #[error("mission is not active: {0}")]
    NotActive(MissionId),
    #[error("mission is not suspended: {0}")]
    NotSuspended(MissionId),
    #[error("delegation depth limit exceeded: {depth} > {max}")]
    DepthLimitExceeded { depth: u32, max: u32 },
    #[error("capability cannot be delegated: {0}")]
    InvalidDelegation(String),
}

/// Manages the mission tree in memory.
///
/// Maintains missions, capabilities, token-to-mission index, and parent-children
/// relationships. Enforces delegation depth limits and capability narrowing.
pub struct MissionManager {
    missions: HashMap<MissionId, Mission>,
    capabilities: HashMap<CapabilityId, Capability>,
    token_index: HashMap<MissionToken, MissionId>,
    children_index: HashMap<MissionId, Vec<MissionId>>,
    max_delegation_depth: u32,
}

impl MissionManager {
    pub fn new(max_delegation_depth: u32) -> Self {
        Self {
            missions: HashMap::new(),
            capabilities: HashMap::new(),
            token_index: HashMap::new(),
            children_index: HashMap::new(),
            max_delegation_depth,
        }
    }

    /// Create a root mission (no parent) with the given goal, capabilities, and policies.
    pub fn create_root_mission(
        &mut self,
        goal: String,
        capabilities: Vec<Capability>,
        policies: Vec<PolicyId>,
    ) -> Result<Mission, MissionError> {
        let id = MissionId::new();
        let token = MissionToken::new();
        let now = Utc::now();

        let cap_ids = capabilities
            .iter()
            .map(|c| c.id)
            .collect();

        // Store capabilities
        for cap in capabilities {
            self.capabilities.insert(cap.id, cap);
        }

        let mission = Mission {
            id,
            parent: None,
            token,
            goal,
            capabilities: cap_ids,
            policies,
            status: MissionStatus::Active,
            depth: 0,
            created_at: now,
            updated_at: now,
        };

        self.token_index.insert(token, id);
        self.children_index.insert(id, Vec::new());
        self.missions.insert(id, mission.clone());

        Ok(mission)
    }

    /// Delegate a child mission from a parent.
    ///
    /// Validates:
    /// 1. Parent exists and is active
    /// 2. Depth limit not exceeded
    /// 3. Each child capability passes `parent_cap.can_delegate_to(&child_cap)`
    /// 4. Creates child with parent's policies + additional_policies
    pub fn delegate(
        &mut self,
        parent_id: MissionId,
        goal: String,
        capabilities: Vec<Capability>,
        additional_policies: Vec<PolicyId>,
    ) -> Result<Mission, MissionError> {
        // Validate parent exists and is active
        let parent = self
            .missions
            .get(&parent_id)
            .ok_or(MissionError::NotFound(parent_id))?;

        if !parent.is_active() {
            return Err(MissionError::NotActive(parent_id));
        }

        let child_depth = parent.depth + 1;
        if child_depth > self.max_delegation_depth {
            return Err(MissionError::DepthLimitExceeded {
                depth: child_depth,
                max: self.max_delegation_depth,
            });
        }

        // Collect parent capabilities for validation
        let parent_caps: Vec<&Capability> = parent
            .capabilities
            .iter()
            .filter_map(|id| self.capabilities.get(id))
            .collect();

        // Validate each child capability against parent capabilities
        for child_cap in &capabilities {
            let has_valid_parent = parent_caps
                .iter()
                .any(|parent_cap| parent_cap.can_delegate_to(child_cap));
            if !has_valid_parent {
                return Err(MissionError::InvalidDelegation(format!(
                    "no parent capability can delegate to child capability {}",
                    child_cap.id
                )));
            }
        }

        // Merge parent policies + additional
        let mut policies = parent.policies.clone();
        policies.extend(additional_policies);

        let id = MissionId::new();
        let token = MissionToken::new();
        let now = Utc::now();

        let cap_ids = capabilities.iter().map(|c| c.id).collect();

        // Store capabilities
        for cap in capabilities {
            self.capabilities.insert(cap.id, cap);
        }

        let mission = Mission {
            id,
            parent: Some(parent_id),
            token,
            goal,
            capabilities: cap_ids,
            policies,
            status: MissionStatus::Active,
            depth: child_depth,
            created_at: now,
            updated_at: now,
        };

        self.token_index.insert(token, id);
        self.children_index.insert(id, Vec::new());
        self.children_index
            .entry(parent_id)
            .or_default()
            .push(id);
        self.missions.insert(id, mission.clone());

        Ok(mission)
    }

    /// Complete a mission (must be Active).
    pub fn complete(&mut self, id: MissionId) -> Result<(), MissionError> {
        let mission = self
            .missions
            .get_mut(&id)
            .ok_or(MissionError::NotFound(id))?;
        if !mission.is_active() {
            return Err(MissionError::NotActive(id));
        }
        mission.status = MissionStatus::Completed;
        mission.updated_at = Utc::now();
        Ok(())
    }

    /// Fail a mission (must be Active).
    pub fn fail(&mut self, id: MissionId) -> Result<(), MissionError> {
        let mission = self
            .missions
            .get_mut(&id)
            .ok_or(MissionError::NotFound(id))?;
        if !mission.is_active() {
            return Err(MissionError::NotActive(id));
        }
        mission.status = MissionStatus::Failed;
        mission.updated_at = Utc::now();
        Ok(())
    }

    /// Suspend a mission (must be Active).
    pub fn suspend(&mut self, id: MissionId) -> Result<(), MissionError> {
        let mission = self
            .missions
            .get_mut(&id)
            .ok_or(MissionError::NotFound(id))?;
        if !mission.is_active() {
            return Err(MissionError::NotActive(id));
        }
        mission.status = MissionStatus::Suspended;
        mission.updated_at = Utc::now();
        Ok(())
    }

    /// Resume a suspended mission (must be Suspended).
    pub fn resume(&mut self, id: MissionId) -> Result<(), MissionError> {
        let mission = self
            .missions
            .get_mut(&id)
            .ok_or(MissionError::NotFound(id))?;
        if mission.status != MissionStatus::Suspended {
            return Err(MissionError::NotSuspended(id));
        }
        mission.status = MissionStatus::Active;
        mission.updated_at = Utc::now();
        Ok(())
    }

    /// Revoke a mission and recursively revoke all descendants.
    /// Returns all revoked mission IDs.
    pub fn revoke(&mut self, id: MissionId) -> Result<Vec<MissionId>, MissionError> {
        if !self.missions.contains_key(&id) {
            return Err(MissionError::NotFound(id));
        }

        let mut revoked = Vec::new();
        self.revoke_recursive(id, &mut revoked);
        Ok(revoked)
    }

    fn revoke_recursive(&mut self, id: MissionId, revoked: &mut Vec<MissionId>) {
        if let Some(mission) = self.missions.get_mut(&id) {
            if mission.is_terminal() {
                return;
            }
            mission.status = MissionStatus::Revoked;
            mission.updated_at = Utc::now();
            revoked.push(id);
        }

        // Collect children IDs first to avoid borrow issues
        let children: Vec<MissionId> = self
            .children_index
            .get(&id)
            .cloned()
            .unwrap_or_default();

        for child_id in children {
            self.revoke_recursive(child_id, revoked);
        }
    }

    /// Get a mission by ID.
    pub fn get(&self, id: &MissionId) -> Option<&Mission> {
        self.missions.get(id)
    }

    /// Get all direct children of a mission.
    pub fn get_children(&self, id: &MissionId) -> Vec<&Mission> {
        self.children_index
            .get(id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|child_id| self.missions.get(child_id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Resolve a mission token to its mission ID.
    pub fn resolve_token(&self, token: &MissionToken) -> Option<MissionId> {
        self.token_index.get(token).copied()
    }

    /// Get a capability by ID.
    pub fn get_capability(&self, id: &CapabilityId) -> Option<&Capability> {
        self.capabilities.get(id)
    }

    /// Get all capabilities for a mission.
    pub fn get_mission_capabilities(&self, mission_id: &MissionId) -> Vec<&Capability> {
        self.missions
            .get(mission_id)
            .map(|m| {
                m.capabilities
                    .iter()
                    .filter_map(|cap_id| self.capabilities.get(cap_id))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_core::capability::Constraints;
    use mc_core::operation::Operation;
    use mc_core::resource::ResourcePattern;
    use std::collections::HashSet;

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
    fn create_root_mission() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/**", &[Operation::Read, Operation::Write], true);
        let cap_id = cap.id;

        let mission = mgr
            .create_root_mission(
                "deploy service".to_string(),
                vec![cap],
                vec![PolicyId::new()],
            )
            .unwrap();

        assert_eq!(mission.status, MissionStatus::Active);
        assert_eq!(mission.depth, 0);
        assert!(mission.parent.is_none());
        assert_eq!(mission.goal, "deploy service");
        assert!(mission.capabilities.contains(&cap_id));
    }

    #[test]
    fn delegate_valid() {
        let mut mgr = MissionManager::new(5);
        let parent_cap = make_cap(
            "http://api.com/repos/*",
            &[Operation::Read, Operation::Write],
            true,
        );

        let root = mgr
            .create_root_mission("root".to_string(), vec![parent_cap], vec![])
            .unwrap();

        let child_cap = make_cap("http://api.com/repos/foo", &[Operation::Read], true);
        let child = mgr
            .delegate(root.id, "child task".to_string(), vec![child_cap], vec![])
            .unwrap();

        assert_eq!(child.parent, Some(root.id));
        assert_eq!(child.depth, 1);
        assert_eq!(child.status, MissionStatus::Active);
        assert_eq!(child.goal, "child task");
    }

    #[test]
    fn delegate_rejects_broadening() {
        let mut mgr = MissionManager::new(5);
        let parent_cap = make_cap("http://api.com/repos/foo", &[Operation::Read], true);

        let root = mgr
            .create_root_mission("root".to_string(), vec![parent_cap], vec![])
            .unwrap();

        // Child tries to broaden resource scope
        let child_cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let result = mgr.delegate(root.id, "child".to_string(), vec![child_cap], vec![]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MissionError::InvalidDelegation(_)));
    }

    #[test]
    fn delegate_rejects_non_delegatable() {
        let mut mgr = MissionManager::new(5);
        let parent_cap = make_cap(
            "http://api.com/**",
            &[Operation::Read, Operation::Write],
            false, // not delegatable
        );

        let root = mgr
            .create_root_mission("root".to_string(), vec![parent_cap], vec![])
            .unwrap();

        let child_cap = make_cap("http://api.com/repos/foo", &[Operation::Read], true);
        let result = mgr.delegate(root.id, "child".to_string(), vec![child_cap], vec![]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MissionError::InvalidDelegation(_)));
    }

    #[test]
    fn delegate_rejects_depth_limit() {
        let mut mgr = MissionManager::new(1); // max depth = 1
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);

        let root = mgr
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();

        // First delegation (depth=1) should succeed
        let child_cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let child = mgr
            .delegate(root.id, "child".to_string(), vec![child_cap], vec![])
            .unwrap();

        // Second delegation (depth=2) should fail since max is 1
        let grandchild_cap = make_cap("http://api.com/repos/foo", &[Operation::Read], true);
        let result = mgr.delegate(child.id, "grandchild".to_string(), vec![grandchild_cap], vec![]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MissionError::DepthLimitExceeded { depth: 2, max: 1 }
        ));
    }

    #[test]
    fn delegate_inactive_parent() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);

        let root = mgr
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();

        mgr.complete(root.id).unwrap();

        let child_cap = make_cap("http://api.com/repos/foo", &[Operation::Read], true);
        let result = mgr.delegate(root.id, "child".to_string(), vec![child_cap], vec![]);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MissionError::NotActive(_)));
    }

    #[test]
    fn revoke_cascades() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);

        let root = mgr
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();

        let child_cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let child = mgr
            .delegate(root.id, "child".to_string(), vec![child_cap], vec![])
            .unwrap();

        let grandchild_cap = make_cap("http://api.com/repos/foo", &[Operation::Read], true);
        let grandchild = mgr
            .delegate(child.id, "grandchild".to_string(), vec![grandchild_cap], vec![])
            .unwrap();

        let revoked = mgr.revoke(root.id).unwrap();

        assert_eq!(revoked.len(), 3);
        assert!(revoked.contains(&root.id));
        assert!(revoked.contains(&child.id));
        assert!(revoked.contains(&grandchild.id));

        assert_eq!(mgr.get(&root.id).unwrap().status, MissionStatus::Revoked);
        assert_eq!(mgr.get(&child.id).unwrap().status, MissionStatus::Revoked);
        assert_eq!(
            mgr.get(&grandchild.id).unwrap().status,
            MissionStatus::Revoked
        );
    }

    #[test]
    fn complete_mission() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);

        let root = mgr
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();

        assert_eq!(mgr.get(&root.id).unwrap().status, MissionStatus::Active);
        mgr.complete(root.id).unwrap();
        assert_eq!(mgr.get(&root.id).unwrap().status, MissionStatus::Completed);
    }

    #[test]
    fn fail_mission() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);

        let root = mgr
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();

        mgr.fail(root.id).unwrap();
        assert_eq!(mgr.get(&root.id).unwrap().status, MissionStatus::Failed);
    }

    #[test]
    fn suspend_resume() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);

        let root = mgr
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();

        mgr.suspend(root.id).unwrap();
        assert_eq!(mgr.get(&root.id).unwrap().status, MissionStatus::Suspended);

        mgr.resume(root.id).unwrap();
        assert_eq!(mgr.get(&root.id).unwrap().status, MissionStatus::Active);
    }

    #[test]
    fn resume_non_suspended_fails() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);

        let root = mgr
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();

        let result = mgr.resume(root.id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MissionError::NotSuspended(_)));
    }

    #[test]
    fn resolve_token() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);

        let root = mgr
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();

        let resolved = mgr.resolve_token(&root.token);
        assert_eq!(resolved, Some(root.id));
    }

    #[test]
    fn resolve_unknown_token() {
        let mgr = MissionManager::new(5);
        let unknown_token = MissionToken::new();
        assert_eq!(mgr.resolve_token(&unknown_token), None);
    }

    #[test]
    fn get_mission_capabilities() {
        let mut mgr = MissionManager::new(5);
        let cap1 = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let cap2 = make_cap("http://api.com/users/*", &[Operation::Write], true);
        let cap1_id = cap1.id;
        let cap2_id = cap2.id;

        let root = mgr
            .create_root_mission("root".to_string(), vec![cap1, cap2], vec![])
            .unwrap();

        let caps = mgr.get_mission_capabilities(&root.id);
        assert_eq!(caps.len(), 2);

        let cap_ids: HashSet<CapabilityId> = caps.iter().map(|c| c.id).collect();
        assert!(cap_ids.contains(&cap1_id));
        assert!(cap_ids.contains(&cap2_id));
    }

    #[test]
    fn get_children() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap(
            "http://api.com/**",
            &[Operation::Read, Operation::Write],
            true,
        );

        let root = mgr
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();

        let child_cap1 = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let child1 = mgr
            .delegate(root.id, "child1".to_string(), vec![child_cap1], vec![])
            .unwrap();

        let child_cap2 = make_cap("http://api.com/users/*", &[Operation::Read], true);
        let child2 = mgr
            .delegate(root.id, "child2".to_string(), vec![child_cap2], vec![])
            .unwrap();

        let children = mgr.get_children(&root.id);
        assert_eq!(children.len(), 2);

        let child_ids: HashSet<MissionId> = children.iter().map(|m| m.id).collect();
        assert!(child_ids.contains(&child1.id));
        assert!(child_ids.contains(&child2.id));
    }

    #[test]
    fn delegate_inherits_parent_policies() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let parent_policy = PolicyId::new();
        let extra_policy = PolicyId::new();

        let root = mgr
            .create_root_mission("root".to_string(), vec![cap], vec![parent_policy])
            .unwrap();

        let child_cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let child = mgr
            .delegate(
                root.id,
                "child".to_string(),
                vec![child_cap],
                vec![extra_policy],
            )
            .unwrap();

        assert!(child.policies.contains(&parent_policy));
        assert!(child.policies.contains(&extra_policy));
        assert_eq!(child.policies.len(), 2);
    }

    #[test]
    fn get_nonexistent_mission() {
        let mgr = MissionManager::new(5);
        let fake_id = MissionId::new();
        assert!(mgr.get(&fake_id).is_none());
    }

    #[test]
    fn complete_already_completed_fails() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);

        let root = mgr
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();

        mgr.complete(root.id).unwrap();
        let result = mgr.complete(root.id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MissionError::NotActive(_)));
    }
}
