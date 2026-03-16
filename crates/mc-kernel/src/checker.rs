use mc_core::delegation::ChainAnomalyFlag;
use mc_core::id::{CapabilityId, MissionId};
use mc_core::operation::Operation;
use mc_core::policy::EvaluationContext;
use mc_core::principal::PrincipalSummary;
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

/// Graph-aware capability checker wrapper.
///
/// Enriches the `EvaluationContext` with principal chain, effective trust level,
/// and chain anomaly flags from the permission graph's chain verification.
///
/// This struct is agnostic to `mc-graph` -- it only uses `mc-core` types.
/// The caller (e.g., API layer that owns both `mc-graph` and `mc-kernel`)
/// performs chain verification via `mc-graph::ChainVerifier` and passes
/// the results here to enrich the context.
pub struct GraphCapabilityChecker;

impl GraphCapabilityChecker {
    /// Check capability (fast-path) and enrich the evaluation context with
    /// graph-derived information.
    ///
    /// Returns `(Option<CapabilityId>, EvaluationContext)` -- the capability match
    /// from the fast path, plus the enriched context for the policy pipeline.
    pub fn check_and_enrich(
        manager: &MissionManager,
        mission_id: &MissionId,
        resource: &ResourceUri,
        operation: &Operation,
        mut context: EvaluationContext,
        principal_chain: Vec<PrincipalSummary>,
        chain_anomaly_flags: Vec<ChainAnomalyFlag>,
    ) -> (Option<CapabilityId>, EvaluationContext) {
        // Fast-path capability check (Layer 1, unchanged)
        let cap_id = CapabilityChecker::check(manager, mission_id, resource, operation);

        // Compute effective trust level = minimum trust in the chain
        let effective_trust = if principal_chain.is_empty() {
            None
        } else {
            principal_chain.iter().map(|p| p.trust_level).min()
        };

        // Enrich context with graph information
        context.principal_chain = principal_chain;
        context.effective_trust_level = effective_trust;
        context.chain_anomaly_flags = chain_anomaly_flags;

        (cap_id, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use mc_core::capability::{Capability, Constraints};
    use mc_core::id::PrincipalId;
    use mc_core::principal::{PrincipalKind, PrincipalTrustLevel};
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

    fn make_context() -> EvaluationContext {
        EvaluationContext {
            mission_goal: "test".to_string(),
            mission_chain: vec![],
            recent_operations: vec![],
            anomaly_history: vec![],
            executes_session_written_file: false,
            principal_chain: vec![],
            effective_trust_level: None,
            chain_anomaly_flags: vec![],
        }
    }

    fn make_principal_summary(kind: PrincipalKind, trust: PrincipalTrustLevel) -> PrincipalSummary {
        PrincipalSummary {
            id: PrincipalId::new(),
            kind,
            trust_level: trust,
            display_name: format!("{kind:?}"),
        }
    }

    #[test]
    fn graph_checker_enriches_context_with_chain() {
        let mut mgr = MissionManager::new(5);
        let cap = make_cap("http://api.com/**", &[Operation::Read], true);
        let cap_id = cap.id;
        let mission = mgr
            .create_root_mission("test".to_string(), vec![cap], vec![])
            .unwrap();

        let chain = vec![
            make_principal_summary(PrincipalKind::Human, PrincipalTrustLevel::Human),
            make_principal_summary(PrincipalKind::AiAgent, PrincipalTrustLevel::Agent),
        ];
        let resource = ResourceUri::new("http://api.com/repos/foo").unwrap();
        let (result, ctx) = GraphCapabilityChecker::check_and_enrich(
            &mgr,
            &mission.id,
            &resource,
            &Operation::Read,
            make_context(),
            chain,
            vec![],
        );

        assert_eq!(result, Some(cap_id));
        assert_eq!(ctx.principal_chain.len(), 2);
        // Effective trust = minimum = Agent
        assert_eq!(
            ctx.effective_trust_level,
            Some(PrincipalTrustLevel::Agent)
        );
    }

    #[test]
    fn graph_checker_empty_chain_no_trust_level() {
        let mgr = MissionManager::new(5);
        let fake_id = MissionId::new();
        let resource = ResourceUri::new("http://api.com/repos/foo").unwrap();

        let (result, ctx) = GraphCapabilityChecker::check_and_enrich(
            &mgr,
            &fake_id,
            &resource,
            &Operation::Read,
            make_context(),
            vec![],
            vec![],
        );

        assert_eq!(result, None);
        assert!(ctx.principal_chain.is_empty());
        assert_eq!(ctx.effective_trust_level, None);
    }

    #[test]
    fn graph_checker_passes_anomaly_flags() {
        let mgr = MissionManager::new(5);
        let fake_id = MissionId::new();
        let resource = ResourceUri::new("http://api.com/repos/foo").unwrap();

        let flags = vec![ChainAnomalyFlag::UnusualDepth {
            depth: 10,
            median: 3,
        }];
        let (_, ctx) = GraphCapabilityChecker::check_and_enrich(
            &mgr,
            &fake_id,
            &resource,
            &Operation::Read,
            make_context(),
            vec![make_principal_summary(
                PrincipalKind::Human,
                PrincipalTrustLevel::Human,
            )],
            flags,
        );

        assert_eq!(ctx.chain_anomaly_flags.len(), 1);
        assert!(matches!(
            ctx.chain_anomaly_flags[0],
            ChainAnomalyFlag::UnusualDepth { depth: 10, .. }
        ));
    }

    #[test]
    fn graph_checker_effective_trust_is_minimum() {
        let mgr = MissionManager::new(5);
        let fake_id = MissionId::new();
        let resource = ResourceUri::new("http://api.com/repos/foo").unwrap();

        // Chain: Human → ServiceAccount → Agent
        let chain = vec![
            make_principal_summary(PrincipalKind::Human, PrincipalTrustLevel::Human),
            make_principal_summary(
                PrincipalKind::ServiceAccount,
                PrincipalTrustLevel::ServiceAccount,
            ),
            make_principal_summary(PrincipalKind::AiAgent, PrincipalTrustLevel::Agent),
        ];
        let (_, ctx) = GraphCapabilityChecker::check_and_enrich(
            &mgr,
            &fake_id,
            &resource,
            &Operation::Read,
            make_context(),
            chain,
            vec![],
        );

        // Minimum trust in chain is Agent
        assert_eq!(
            ctx.effective_trust_level,
            Some(PrincipalTrustLevel::Agent)
        );
    }
}
