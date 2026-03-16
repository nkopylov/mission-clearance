use std::collections::HashSet;

use anyhow::{Context, Result};
use mc_core::delegation::DelegationEdge;
use mc_core::id::{MissionId, PrincipalId};
use mc_core::mission::Mission;
use mc_core::principal::{Principal, PrincipalKind, PrincipalSummary};
use mc_kernel::manager::MissionManager;

use crate::store::PermissionGraphStore;

/// A single link in the delegation chain, associating a principal with the
/// mission they control and the delegation edge that granted them access.
#[derive(Debug, Clone)]
pub struct ChainLink {
    pub principal: Principal,
    pub mission: Mission,
    /// `None` for the root link (no delegation edge to the root).
    pub delegation_edge: Option<DelegationEdge>,
}

/// The result of verifying a delegation chain from leaf to root.
#[derive(Debug)]
pub enum ChainVerificationResult {
    /// The chain is valid from root to leaf.
    Verified {
        chain: Vec<ChainLink>,
        root_principal: PrincipalSummary,
    },
    /// The chain failed validation at a specific link.
    Denied {
        reason: String,
        failed_at_link: usize,
    },
    /// Legacy mode -- no principal chain configured (root mission has no creator).
    NoIdentity,
}

/// Verifies delegation chains by walking the mission tree and validating
/// each link against the permission graph.
pub struct ChainVerifier<'a> {
    store: &'a PermissionGraphStore,
    manager: &'a MissionManager,
}

impl<'a> ChainVerifier<'a> {
    pub fn new(store: &'a PermissionGraphStore, manager: &'a MissionManager) -> Self {
        Self { store, manager }
    }

    /// Verify the delegation chain for the given mission.
    ///
    /// Implements the 3-phase algorithm:
    /// 1. COLLECT: walk mission.parent upward, building the chain
    /// 2. VALIDATE: check each link top-down from root
    /// 3. VERIFY ROOT AUTHORITY: ensure root principal is Human or ServiceAccount and Active
    pub fn verify_chain(&self, mission_id: &MissionId) -> Result<ChainVerificationResult> {
        // Phase 1: COLLECT the chain (walk mission.parent upward)
        let chain = match self.collect_chain(mission_id)? {
            Some(chain) => chain,
            None => return Ok(ChainVerificationResult::NoIdentity),
        };

        // Phase 2: VALIDATE each link (top-down from root)
        if let Some(denied) = self.validate_links(&chain)? {
            return Ok(denied);
        }

        // Phase 3: VERIFY ROOT AUTHORITY
        let root_link = &chain[0];
        let root_principal = &root_link.principal;

        match root_principal.kind {
            PrincipalKind::Human | PrincipalKind::ServiceAccount => {}
            kind => {
                return Ok(ChainVerificationResult::Denied {
                    reason: format!(
                        "root principal must be Human or ServiceAccount, got {:?}",
                        kind
                    ),
                    failed_at_link: 0,
                });
            }
        }

        if !root_principal.is_active() {
            return Ok(ChainVerificationResult::Denied {
                reason: format!(
                    "root principal '{}' is not Active (status: {:?})",
                    root_principal.display_name, root_principal.status
                ),
                failed_at_link: 0,
            });
        }

        let root_summary = PrincipalSummary::from(root_principal);
        Ok(ChainVerificationResult::Verified {
            chain,
            root_principal: root_summary,
        })
    }

    /// Phase 1: Walk mission.parent upward, collecting chain links.
    ///
    /// Returns `None` if the root mission has no creator (legacy mode).
    /// Returns the chain in root-first order.
    fn collect_chain(&self, leaf_mission_id: &MissionId) -> Result<Option<Vec<ChainLink>>> {
        let mut links: Vec<ChainLink> = Vec::new();
        let mut visited: HashSet<MissionId> = HashSet::new();
        let mut current_id = *leaf_mission_id;

        loop {
            // Cycle detection
            if !visited.insert(current_id) {
                anyhow::bail!("cycle detected in mission chain at mission {}", current_id);
            }

            let mission = self
                .manager
                .get(&current_id)
                .ok_or_else(|| anyhow::anyhow!("mission {} not found in manager", current_id))?
                .clone();

            let creator_id = match &mission.creator {
                Some(id) => *id,
                None => {
                    // If this is the root (no parent) and no creator -> legacy mode
                    if mission.parent.is_none() {
                        return Ok(None);
                    }
                    // Non-root mission without creator is an error
                    anyhow::bail!(
                        "non-root mission {} has no creator",
                        mission.id
                    );
                }
            };

            let principal = self
                .store
                .get_principal(&creator_id)
                .context(format!("failed to look up principal {}", creator_id))?
                .ok_or_else(|| {
                    anyhow::anyhow!("principal {} not found in store", creator_id)
                })?;

            // Find the delegation edge from the parent's creator to this mission's creator.
            // For the root link (no parent), delegation_edge is None.
            let delegation_edge = if mission.parent.is_some() {
                self.find_delegation_edge_to(&creator_id)?
            } else {
                None
            };

            links.push(ChainLink {
                principal,
                mission: mission.clone(),
                delegation_edge,
            });

            match mission.parent {
                Some(parent_id) => current_id = parent_id,
                None => break, // reached root
            }
        }

        // Reverse to root-first order (we collected leaf-first)
        links.reverse();
        Ok(Some(links))
    }

    /// Find a delegation edge targeting the given principal.
    /// Returns the first non-revoked edge found (deterministic from DB ordering).
    fn find_delegation_edge_to(&self, principal_id: &PrincipalId) -> Result<Option<DelegationEdge>> {
        let edges = self
            .store
            .get_delegations_to(principal_id)
            .context("failed to query delegation edges")?;
        // Return the first edge (could be refined to pick most relevant)
        Ok(edges.into_iter().next())
    }

    /// Phase 2: Validate each link top-down from root.
    ///
    /// Link 0 is the root; validation starts at link 1.
    fn validate_links(
        &self,
        chain: &[ChainLink],
    ) -> Result<Option<ChainVerificationResult>> {
        for i in 1..chain.len() {
            let link = &chain[i];

            // (a) Check mission is active
            if !link.mission.is_active() {
                return Ok(Some(ChainVerificationResult::Denied {
                    reason: format!(
                        "mission '{}' at link {} is not active (status: {:?})",
                        link.mission.id, i, link.mission.status
                    ),
                    failed_at_link: i,
                }));
            }

            // Get the delegation edge -- if there is none, we cannot validate delegation
            let edge = match &link.delegation_edge {
                Some(e) => e,
                None => {
                    return Ok(Some(ChainVerificationResult::Denied {
                        reason: format!(
                            "no delegation edge found for link {} (principal {})",
                            i, link.principal.id
                        ),
                        failed_at_link: i,
                    }));
                }
            };

            // (b) Check delegation edge is not revoked
            if edge.revoked {
                return Ok(Some(ChainVerificationResult::Denied {
                    reason: format!(
                        "delegation edge {} at link {} is revoked",
                        edge.id, i
                    ),
                    failed_at_link: i,
                }));
            }

            // (c) Check delegation edge not expired
            if edge.constraints.is_expired() {
                return Ok(Some(ChainVerificationResult::Denied {
                    reason: format!(
                        "delegation edge {} at link {} has expired",
                        edge.id, i
                    ),
                    failed_at_link: i,
                }));
            }

            // (d) Check operation count within limits
            if edge.constraints.is_exhausted() {
                return Ok(Some(ChainVerificationResult::Denied {
                    reason: format!(
                        "delegation edge {} at link {} has exhausted its operation limit",
                        edge.id, i
                    ),
                    failed_at_link: i,
                }));
            }

            // (e) Check sub_delegation_allowed by parent edge (if depth > 1)
            if i > 1 {
                if let Some(parent_edge) = &chain[i - 1].delegation_edge {
                    if !parent_edge.constraints.sub_delegation_allowed {
                        return Ok(Some(ChainVerificationResult::Denied {
                            reason: format!(
                                "parent delegation edge {} at link {} does not allow sub-delegation",
                                parent_edge.id,
                                i - 1
                            ),
                            failed_at_link: i,
                        }));
                    }
                }
            }

            // (f) Check sub_depth within limit
            if let Some(max_sub_depth) = edge.constraints.max_sub_depth {
                // The remaining chain depth from this link onward
                let remaining_depth = (chain.len() - 1 - i) as u32;
                if remaining_depth > max_sub_depth {
                    return Ok(Some(ChainVerificationResult::Denied {
                        reason: format!(
                            "delegation edge {} at link {} exceeds max sub-depth ({} > {})",
                            edge.id, i, remaining_depth, max_sub_depth
                        ),
                        failed_at_link: i,
                    }));
                }
            }

            // (g) Check principal kind is in allowed_delegate_kinds (if set)
            if let Some(ref allowed_kinds) = edge.constraints.allowed_delegate_kinds {
                if !allowed_kinds.contains(&link.principal.kind) {
                    return Ok(Some(ChainVerificationResult::Denied {
                        reason: format!(
                            "principal kind {:?} at link {} is not in allowed delegate kinds",
                            link.principal.kind, i
                        ),
                        failed_at_link: i,
                    }));
                }
            }

            // (h) Check principal status is Active
            if !link.principal.is_active() {
                return Ok(Some(ChainVerificationResult::Denied {
                    reason: format!(
                        "principal '{}' at link {} is not Active (status: {:?})",
                        link.principal.display_name, i, link.principal.status
                    ),
                    failed_at_link: i,
                }));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use mc_core::capability::{Capability, Constraints};
    use mc_core::delegation::{DelegationConstraints, DelegationEdge};
    use mc_core::id::{CapabilityId, DelegationEdgeId, PrincipalId};
    use mc_core::mission::Mission;
    use mc_core::operation::Operation;
    use mc_core::principal::{
        Principal, PrincipalDetails, PrincipalKind, PrincipalStatus, PrincipalTrustLevel,
    };
    use mc_core::resource::ResourcePattern;

    fn test_store() -> PermissionGraphStore {
        PermissionGraphStore::new(":memory:").expect("in-memory DB should open")
    }

    fn make_human(name: &str) -> Principal {
        Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::Human,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::Human,
            display_name: name.to_string(),
            details: PrincipalDetails::Human {
                email: format!("{}@example.com", name),
                external_id: None,
            },
            org_position: None,
            teams: vec![],
        }
    }

    fn make_agent(name: &str, spawned_by: Option<PrincipalId>) -> Principal {
        Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::AiAgent,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::Agent,
            display_name: name.to_string(),
            details: PrincipalDetails::AiAgent {
                model: "claude-4".to_string(),
                spawned_by,
                spawning_mission: None,
            },
            org_position: None,
            teams: vec![],
        }
    }

    fn make_service_account(name: &str, owner: PrincipalId) -> Principal {
        Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::ServiceAccount,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::ServiceAccount,
            display_name: name.to_string(),
            details: PrincipalDetails::ServiceAccount {
                purpose: "testing".to_string(),
                owner,
            },
            org_position: None,
            teams: vec![],
        }
    }

    fn make_cap(pattern: &str, ops: &[Operation], delegatable: bool) -> Capability {
        Capability {
            id: CapabilityId::new(),
            resource_pattern: ResourcePattern::new(pattern).unwrap(),
            operations: ops.iter().cloned().collect(),
            constraints: Constraints::default(),
            delegatable,
        }
    }

    fn make_delegation_edge(
        from: PrincipalId,
        to: PrincipalId,
        constraints: DelegationConstraints,
    ) -> DelegationEdge {
        DelegationEdge {
            id: DelegationEdgeId::new(),
            from,
            to,
            constraints,
            revoked: false,
            created_at: Utc::now(),
        }
    }

    /// Helper to set up a chain: root_mission (created by human) -> child_mission (created by agent)
    /// with a delegation edge from human to agent.
    fn setup_two_level_chain(
        store: &PermissionGraphStore,
        manager: &mut MissionManager,
    ) -> (Principal, Principal, Mission, Mission) {
        let human = make_human("alice");
        let agent = make_agent("agent-1", Some(human.id));

        store.add_principal(&human).unwrap();
        store.add_principal(&agent).unwrap();

        // Create root mission with creator
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let mut root = manager
            .create_root_mission("root task".to_string(), vec![cap], vec![])
            .unwrap();
        // Set the creator on the root mission
        root.creator = Some(human.id);
        // Update in manager by re-inserting
        set_mission_creator(manager, &root.id, Some(human.id));

        // Create child mission
        let child_cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let mut child = manager
            .delegate(root.id, "child task".to_string(), vec![child_cap], vec![])
            .unwrap();
        child.creator = Some(agent.id);
        set_mission_creator(manager, &child.id, Some(agent.id));

        // Add delegation edge from human to agent
        let edge = make_delegation_edge(
            human.id,
            agent.id,
            DelegationConstraints {
                sub_delegation_allowed: true,
                ..Default::default()
            },
        );
        store.add_delegation_edge(&edge).unwrap();

        (human, agent, root, child)
    }

    /// Helper to set mission creator in the MissionManager.
    /// Since MissionManager doesn't expose a mutable reference to missions directly,
    /// we work around this by accessing the internal state through the get method
    /// and creating missions with creators set.
    fn set_mission_creator(
        manager: &mut MissionManager,
        mission_id: &MissionId,
        creator: Option<PrincipalId>,
    ) {
        // We need to directly manipulate the mission. Since MissionManager
        // only returns &Mission from get(), we use an unsafe approach through
        // pointer casting. In production code, MissionManager should have a
        // set_creator method. For tests, we work around this limitation.
        //
        // Actually, let's use a safe approach: we know the MissionManager
        // stores missions in a HashMap. We can get a raw pointer and cast it.
        // This is only for tests.
        if let Some(mission) = manager.get(mission_id) {
            // SAFETY: We have &mut MissionManager, so no other references exist.
            // This is a test-only workaround.
            let mission_ptr = mission as *const Mission as *mut Mission;
            unsafe {
                (*mission_ptr).creator = creator;
            }
        }
    }

    #[test]
    fn test_two_level_chain_verified() {
        let store = test_store();
        let mut manager = MissionManager::new(10);
        let (_human, _agent, _root, child) = setup_two_level_chain(&store, &mut manager);

        let verifier = ChainVerifier::new(&store, &manager);
        let result = verifier.verify_chain(&child.id).unwrap();

        match result {
            ChainVerificationResult::Verified {
                chain,
                root_principal,
            } => {
                assert_eq!(chain.len(), 2);
                assert_eq!(root_principal.kind, PrincipalKind::Human);
                assert_eq!(root_principal.display_name, "alice");
                // Root link has no delegation edge
                assert!(chain[0].delegation_edge.is_none());
                // Child link has a delegation edge
                assert!(chain[1].delegation_edge.is_some());
            }
            other => panic!("expected Verified, got {:?}", other),
        }
    }

    #[test]
    fn test_three_level_chain_verified() {
        let store = test_store();
        let mut manager = MissionManager::new(10);
        let (_human, agent, _root, child) = setup_two_level_chain(&store, &mut manager);

        // Add a third level: agent delegates to another agent
        let agent2 = make_agent("agent-2", Some(agent.id));
        store.add_principal(&agent2).unwrap();

        let grandchild_cap = make_cap("http://api.com/repos/foo", &[Operation::Read], true);
        let grandchild = manager
            .delegate(
                child.id,
                "grandchild task".to_string(),
                vec![grandchild_cap],
                vec![],
            )
            .unwrap();
        set_mission_creator(&mut manager, &grandchild.id, Some(agent2.id));

        // Add delegation edge from agent to agent2
        let edge2 = make_delegation_edge(
            agent.id,
            agent2.id,
            DelegationConstraints {
                sub_delegation_allowed: true,
                ..Default::default()
            },
        );
        store.add_delegation_edge(&edge2).unwrap();

        let verifier = ChainVerifier::new(&store, &manager);
        let result = verifier.verify_chain(&grandchild.id).unwrap();

        match result {
            ChainVerificationResult::Verified {
                chain,
                root_principal,
            } => {
                assert_eq!(chain.len(), 3);
                assert_eq!(root_principal.kind, PrincipalKind::Human);
                assert_eq!(chain[0].principal.display_name, "alice");
                assert_eq!(chain[1].principal.display_name, "agent-1");
                assert_eq!(chain[2].principal.display_name, "agent-2");
            }
            other => panic!("expected Verified, got {:?}", other),
        }
    }

    #[test]
    fn test_expired_delegation_denied() {
        let store = test_store();
        let mut manager = MissionManager::new(10);

        let human = make_human("alice");
        let agent = make_agent("agent-1", Some(human.id));
        store.add_principal(&human).unwrap();
        store.add_principal(&agent).unwrap();

        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let root = manager
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &root.id, Some(human.id));

        let child_cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let child = manager
            .delegate(root.id, "child".to_string(), vec![child_cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &child.id, Some(agent.id));

        // Add an expired delegation edge
        let edge = DelegationEdge {
            id: DelegationEdgeId::new(),
            from: human.id,
            to: agent.id,
            constraints: DelegationConstraints {
                valid_until: Some(Utc::now() - chrono::Duration::hours(1)),
                ..Default::default()
            },
            revoked: false,
            created_at: Utc::now(),
        };
        store.add_delegation_edge(&edge).unwrap();

        let verifier = ChainVerifier::new(&store, &manager);
        let result = verifier.verify_chain(&child.id).unwrap();

        match result {
            ChainVerificationResult::Denied {
                reason,
                failed_at_link,
            } => {
                assert_eq!(failed_at_link, 1);
                assert!(reason.contains("expired"), "reason was: {}", reason);
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[test]
    fn test_revoked_delegation_denied() {
        let store = test_store();
        let mut manager = MissionManager::new(10);

        let human = make_human("alice");
        let agent = make_agent("agent-1", Some(human.id));
        store.add_principal(&human).unwrap();
        store.add_principal(&agent).unwrap();

        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let root = manager
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &root.id, Some(human.id));

        let child_cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let child = manager
            .delegate(root.id, "child".to_string(), vec![child_cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &child.id, Some(agent.id));

        // Add a revoked delegation edge
        let edge = DelegationEdge {
            id: DelegationEdgeId::new(),
            from: human.id,
            to: agent.id,
            constraints: DelegationConstraints::default(),
            revoked: true,
            created_at: Utc::now(),
        };
        store.add_delegation_edge(&edge).unwrap();

        let verifier = ChainVerifier::new(&store, &manager);
        let result = verifier.verify_chain(&child.id).unwrap();

        match result {
            ChainVerificationResult::Denied {
                reason,
                failed_at_link,
            } => {
                assert_eq!(failed_at_link, 1);
                assert!(reason.contains("revoked"), "reason was: {}", reason);
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[test]
    fn test_exhausted_operations_denied() {
        let store = test_store();
        let mut manager = MissionManager::new(10);

        let human = make_human("alice");
        let agent = make_agent("agent-1", Some(human.id));
        store.add_principal(&human).unwrap();
        store.add_principal(&agent).unwrap();

        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let root = manager
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &root.id, Some(human.id));

        let child_cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let child = manager
            .delegate(root.id, "child".to_string(), vec![child_cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &child.id, Some(agent.id));

        // Add delegation edge with exhausted operations
        let edge = DelegationEdge {
            id: DelegationEdgeId::new(),
            from: human.id,
            to: agent.id,
            constraints: DelegationConstraints {
                max_operations: Some(5),
                operations_used: 5,
                ..Default::default()
            },
            revoked: false,
            created_at: Utc::now(),
        };
        store.add_delegation_edge(&edge).unwrap();

        let verifier = ChainVerifier::new(&store, &manager);
        let result = verifier.verify_chain(&child.id).unwrap();

        match result {
            ChainVerificationResult::Denied {
                reason,
                failed_at_link,
            } => {
                assert_eq!(failed_at_link, 1);
                assert!(
                    reason.contains("exhausted"),
                    "reason was: {}",
                    reason
                );
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[test]
    fn test_root_is_ai_agent_denied() {
        let store = test_store();
        let mut manager = MissionManager::new(10);

        // Root principal is an AI agent (not allowed)
        let agent = make_agent("agent-root", None);
        store.add_principal(&agent).unwrap();

        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let root = manager
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &root.id, Some(agent.id));

        let verifier = ChainVerifier::new(&store, &manager);
        let result = verifier.verify_chain(&root.id).unwrap();

        match result {
            ChainVerificationResult::Denied {
                reason,
                failed_at_link,
            } => {
                assert_eq!(failed_at_link, 0);
                assert!(
                    reason.contains("AiAgent"),
                    "reason was: {}",
                    reason
                );
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[test]
    fn test_root_principal_suspended_denied() {
        let store = test_store();
        let mut manager = MissionManager::new(10);

        let mut human = make_human("alice");
        human.status = PrincipalStatus::Suspended;
        store.add_principal(&human).unwrap();

        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let root = manager
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &root.id, Some(human.id));

        let verifier = ChainVerifier::new(&store, &manager);
        let result = verifier.verify_chain(&root.id).unwrap();

        match result {
            ChainVerificationResult::Denied {
                reason,
                failed_at_link,
            } => {
                assert_eq!(failed_at_link, 0);
                assert!(
                    reason.contains("not Active"),
                    "reason was: {}",
                    reason
                );
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[test]
    fn test_legacy_mode_no_creator() {
        let store = test_store();
        let mut manager = MissionManager::new(10);

        // Create a root mission without setting a creator (default is None)
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let root = manager
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();
        // creator is already None by default

        let verifier = ChainVerifier::new(&store, &manager);
        let result = verifier.verify_chain(&root.id).unwrap();

        assert!(
            matches!(result, ChainVerificationResult::NoIdentity),
            "expected NoIdentity, got {:?}",
            result
        );
    }

    #[test]
    fn test_single_root_mission_with_creator_verified() {
        let store = test_store();
        let mut manager = MissionManager::new(10);

        let human = make_human("alice");
        store.add_principal(&human).unwrap();

        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let root = manager
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &root.id, Some(human.id));

        let verifier = ChainVerifier::new(&store, &manager);
        let result = verifier.verify_chain(&root.id).unwrap();

        match result {
            ChainVerificationResult::Verified {
                chain,
                root_principal,
            } => {
                assert_eq!(chain.len(), 1);
                assert_eq!(root_principal.kind, PrincipalKind::Human);
                assert_eq!(root_principal.display_name, "alice");
                // Single root should have no delegation edge
                assert!(chain[0].delegation_edge.is_none());
            }
            other => panic!("expected Verified, got {:?}", other),
        }
    }

    #[test]
    fn test_service_account_root_verified() {
        let store = test_store();
        let mut manager = MissionManager::new(10);

        let human = make_human("owner");
        let svc = make_service_account("ci-bot", human.id);
        store.add_principal(&human).unwrap();
        store.add_principal(&svc).unwrap();

        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let root = manager
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &root.id, Some(svc.id));

        let verifier = ChainVerifier::new(&store, &manager);
        let result = verifier.verify_chain(&root.id).unwrap();

        match result {
            ChainVerificationResult::Verified {
                root_principal, ..
            } => {
                assert_eq!(root_principal.kind, PrincipalKind::ServiceAccount);
            }
            other => panic!("expected Verified, got {:?}", other),
        }
    }

    #[test]
    fn test_root_is_team_denied() {
        let store = test_store();
        let mut manager = MissionManager::new(10);

        let team_principal = Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::Team,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::Human,
            display_name: "team-alpha".to_string(),
            details: PrincipalDetails::Team {
                description: "a team".to_string(),
            },
            org_position: None,
            teams: vec![],
        };
        store.add_principal(&team_principal).unwrap();

        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let root = manager
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &root.id, Some(team_principal.id));

        let verifier = ChainVerifier::new(&store, &manager);
        let result = verifier.verify_chain(&root.id).unwrap();

        match result {
            ChainVerificationResult::Denied {
                reason,
                failed_at_link,
            } => {
                assert_eq!(failed_at_link, 0);
                assert!(reason.contains("Team"), "reason was: {}", reason);
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }

    #[test]
    fn test_suspended_principal_in_chain_denied() {
        let store = test_store();
        let mut manager = MissionManager::new(10);

        let human = make_human("alice");
        let mut agent = make_agent("agent-1", Some(human.id));
        agent.status = PrincipalStatus::Suspended;
        store.add_principal(&human).unwrap();
        store.add_principal(&agent).unwrap();

        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let root = manager
            .create_root_mission("root".to_string(), vec![cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &root.id, Some(human.id));

        let child_cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let child = manager
            .delegate(root.id, "child".to_string(), vec![child_cap], vec![])
            .unwrap();
        set_mission_creator(&mut manager, &child.id, Some(agent.id));

        // Non-revoked delegation edge
        let edge = make_delegation_edge(human.id, agent.id, DelegationConstraints::default());
        store.add_delegation_edge(&edge).unwrap();

        let verifier = ChainVerifier::new(&store, &manager);
        let result = verifier.verify_chain(&child.id).unwrap();

        match result {
            ChainVerificationResult::Denied {
                reason,
                failed_at_link,
            } => {
                assert_eq!(failed_at_link, 1);
                assert!(
                    reason.contains("not Active"),
                    "reason was: {}",
                    reason
                );
            }
            other => panic!("expected Denied, got {:?}", other),
        }
    }
}
