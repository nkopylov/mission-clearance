//! Cascading revocation through the permission graph.
//!
//! When a principal or delegation edge is revoked, all downstream
//! principals and their missions are recursively revoked.

use crate::store::PermissionGraphStore;
use mc_core::id::PrincipalId;
use mc_core::principal::PrincipalStatus;

/// Result of a cascading revocation operation.
#[derive(Debug, Clone)]
pub struct RevocationResult {
    /// Principals that were revoked as part of the cascade.
    pub revoked_principals: Vec<PrincipalId>,
    /// Delegation edges that were revoked as part of the cascade.
    pub revoked_edges: Vec<mc_core::id::DelegationEdgeId>,
    /// Total number of affected entities.
    pub total_affected: usize,
}

/// Performs cascading revocation through the permission graph.
pub struct CascadingRevoker<'a> {
    store: &'a PermissionGraphStore,
}

impl<'a> CascadingRevoker<'a> {
    pub fn new(store: &'a PermissionGraphStore) -> Self {
        Self { store }
    }

    /// Revoke a principal and cascade to all downstream entities.
    ///
    /// 1. Mark principal as Revoked
    /// 2. Find all `DelegatedTo` edges from this principal
    /// 3. Recursively revoke all downstream principals
    /// 4. Revoke all delegation edges from/to this principal
    pub fn revoke_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> anyhow::Result<RevocationResult> {
        let mut result = RevocationResult {
            revoked_principals: Vec::new(),
            revoked_edges: Vec::new(),
            total_affected: 0,
        };

        let mut visited = std::collections::HashSet::new();
        self.revoke_recursive(principal_id, &mut visited, &mut result)?;

        result.total_affected = result.revoked_principals.len() + result.revoked_edges.len();
        Ok(result)
    }

    fn revoke_recursive(
        &self,
        principal_id: &PrincipalId,
        visited: &mut std::collections::HashSet<PrincipalId>,
        result: &mut RevocationResult,
    ) -> anyhow::Result<()> {
        if !visited.insert(*principal_id) {
            return Ok(()); // Already visited (cycle protection)
        }

        // Revoke the principal
        if let Err(e) = self
            .store
            .update_principal_status(principal_id, PrincipalStatus::Revoked)
        {
            tracing::warn!("Failed to revoke principal {principal_id}: {e}");
        } else {
            result.revoked_principals.push(*principal_id);
        }

        // Find all outgoing delegation edges and cascade
        let outgoing = self.store.get_delegations_from(principal_id)?;
        for edge in outgoing {
            if !edge.revoked {
                if let Err(e) = self.store.revoke_delegation_edge(&edge.id) {
                    tracing::warn!("Failed to revoke delegation edge {}: {e}", edge.id);
                } else {
                    result.revoked_edges.push(edge.id);
                }
                // Cascade to the target principal
                self.revoke_recursive(&edge.to, visited, result)?;
            }
        }

        // Also revoke incoming delegation edges to this principal
        let incoming = self.store.get_delegations_to(principal_id)?;
        for edge in incoming {
            if !edge.revoked {
                if let Err(e) = self.store.revoke_delegation_edge(&edge.id) {
                    tracing::warn!("Failed to revoke delegation edge {}: {e}", edge.id);
                } else {
                    result.revoked_edges.push(edge.id);
                }
            }
        }

        Ok(())
    }

    /// Revoke a specific delegation edge and cascade to the target principal
    /// and all downstream entities.
    pub fn revoke_delegation(
        &self,
        edge_id: &mc_core::id::DelegationEdgeId,
    ) -> anyhow::Result<RevocationResult> {
        let mut result = RevocationResult {
            revoked_principals: Vec::new(),
            revoked_edges: Vec::new(),
            total_affected: 0,
        };

        let edge = self
            .store
            .get_delegation_edge(edge_id)?
            .ok_or_else(|| anyhow::anyhow!("delegation edge not found: {edge_id}"))?;

        // Revoke the edge itself
        self.store.revoke_delegation_edge(edge_id)?;
        result.revoked_edges.push(*edge_id);

        // Cascade to the target
        let mut visited = std::collections::HashSet::new();
        self.revoke_recursive(&edge.to, &mut visited, &mut result)?;

        result.total_affected = result.revoked_principals.len() + result.revoked_edges.len();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use mc_core::delegation::{DelegationConstraints, DelegationEdge};
    use mc_core::id::{DelegationEdgeId, PrincipalId};
    use mc_core::principal::{
        Principal, PrincipalDetails, PrincipalKind, PrincipalStatus, PrincipalTrustLevel,
    };

    fn make_store() -> PermissionGraphStore {
        PermissionGraphStore::new(":memory:").unwrap()
    }

    fn make_human(name: &str) -> Principal {
        Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::Human,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::Human,
            display_name: name.to_string(),
            details: PrincipalDetails::Human {
                email: format!("{name}@example.com"),
                external_id: None,
            },
            org_position: None,
            teams: vec![],
        }
    }

    fn make_agent(name: &str) -> Principal {
        Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::AiAgent,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::Agent,
            display_name: name.to_string(),
            details: PrincipalDetails::AiAgent {
                model: "claude-4".to_string(),
                spawned_by: None,
                spawning_mission: None,
            },
            org_position: None,
            teams: vec![],
        }
    }

    fn make_edge(from: PrincipalId, to: PrincipalId) -> DelegationEdge {
        DelegationEdge {
            id: DelegationEdgeId::new(),
            from,
            to,
            constraints: DelegationConstraints::default(),
            revoked: false,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn revoke_single_principal() {
        let store = make_store();
        let alice = make_human("Alice");
        store.add_principal(&alice).unwrap();

        let revoker = CascadingRevoker::new(&store);
        let result = revoker.revoke_principal(&alice.id).unwrap();

        assert_eq!(result.revoked_principals.len(), 1);
        assert!(result.revoked_principals.contains(&alice.id));

        let revoked = store.get_principal(&alice.id).unwrap().unwrap();
        assert_eq!(revoked.status, PrincipalStatus::Revoked);
    }

    #[test]
    fn revoke_cascades_through_delegation() {
        let store = make_store();
        let alice = make_human("Alice");
        let bot_a = make_agent("Bot-A");
        let bot_b = make_agent("Bot-B");

        store.add_principal(&alice).unwrap();
        store.add_principal(&bot_a).unwrap();
        store.add_principal(&bot_b).unwrap();

        let edge1 = make_edge(alice.id, bot_a.id);
        let edge2 = make_edge(bot_a.id, bot_b.id);
        store.add_delegation_edge(&edge1).unwrap();
        store.add_delegation_edge(&edge2).unwrap();

        // Revoke Alice → should cascade to Bot-A → Bot-B
        let revoker = CascadingRevoker::new(&store);
        let result = revoker.revoke_principal(&alice.id).unwrap();

        assert_eq!(result.revoked_principals.len(), 3);
        assert!(result.revoked_principals.contains(&alice.id));
        assert!(result.revoked_principals.contains(&bot_a.id));
        assert!(result.revoked_principals.contains(&bot_b.id));

        // All principals should be Revoked
        for id in [&alice.id, &bot_a.id, &bot_b.id] {
            let p = store.get_principal(id).unwrap().unwrap();
            assert_eq!(p.status, PrincipalStatus::Revoked);
        }
    }

    #[test]
    fn revoke_delegation_edge_cascades() {
        let store = make_store();
        let alice = make_human("Alice");
        let bot_a = make_agent("Bot-A");
        let bot_b = make_agent("Bot-B");

        store.add_principal(&alice).unwrap();
        store.add_principal(&bot_a).unwrap();
        store.add_principal(&bot_b).unwrap();

        let edge1 = make_edge(alice.id, bot_a.id);
        let edge2 = make_edge(bot_a.id, bot_b.id);
        store.add_delegation_edge(&edge1).unwrap();
        store.add_delegation_edge(&edge2).unwrap();

        // Revoke edge1 → should cascade to Bot-A, Bot-B but NOT Alice
        let revoker = CascadingRevoker::new(&store);
        let result = revoker.revoke_delegation(&edge1.id).unwrap();

        // Bot-A and Bot-B should be revoked
        assert!(result.revoked_principals.contains(&bot_a.id));
        assert!(result.revoked_principals.contains(&bot_b.id));

        // Alice should NOT be revoked
        let alice_p = store.get_principal(&alice.id).unwrap().unwrap();
        assert_eq!(alice_p.status, PrincipalStatus::Active);
    }

    #[test]
    fn revoke_handles_cycles() {
        let store = make_store();
        let bot_a = make_agent("Bot-A");
        let bot_b = make_agent("Bot-B");

        store.add_principal(&bot_a).unwrap();
        store.add_principal(&bot_b).unwrap();

        // Create a cycle: A → B → A
        let edge1 = make_edge(bot_a.id, bot_b.id);
        let edge2 = make_edge(bot_b.id, bot_a.id);
        store.add_delegation_edge(&edge1).unwrap();
        store.add_delegation_edge(&edge2).unwrap();

        // Should not infinite loop
        let revoker = CascadingRevoker::new(&store);
        let result = revoker.revoke_principal(&bot_a.id).unwrap();

        assert_eq!(result.revoked_principals.len(), 2);
    }
}
