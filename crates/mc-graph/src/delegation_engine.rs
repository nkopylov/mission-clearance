//! Delegation policy engine -- configurable rules that determine who can
//! delegate what to whom.
//!
//! Rules are evaluated top-down by priority (highest first). First match wins.
//! No match = Deny (fail-closed).

use mc_core::operation::Operation;
use mc_core::org::OrgLevel;
use mc_core::principal::{Principal, PrincipalKind};
use mc_core::resource::ResourcePattern;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The effect of a delegation policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegationEffect {
    Allow,
    Deny,
    RequireApproval,
}

/// A single delegation policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRule {
    pub name: String,
    pub priority: u32,
    pub effect: DelegationEffect,
    pub condition: DelegationCondition,
}

/// Conditions that must all be met for a rule to match.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DelegationCondition {
    /// Minimum org level of the delegator.
    pub delegator_min_level: Option<OrgLevel>,
    /// Required type of the delegator.
    pub delegator_type: Option<PrincipalKind>,
    /// Required type of the target.
    pub target_type: Option<PrincipalKind>,
    /// Operations the rule applies to (if empty, matches all).
    #[serde(default)]
    pub operations: HashSet<Operation>,
    /// Resource pattern the rule applies to (if None, matches all).
    pub resource: Option<ResourcePattern>,
    /// Maximum chain depth for this rule.
    pub max_chain_depth: Option<u32>,
}

/// Context for evaluating a delegation request.
pub struct DelegationRequest<'a> {
    pub delegator: &'a Principal,
    pub delegator_org_level: Option<OrgLevel>,
    pub target: &'a Principal,
    pub operations: &'a HashSet<Operation>,
    pub resource: Option<&'a ResourcePattern>,
    pub current_chain_depth: u32,
}

/// Result of delegation policy evaluation.
#[derive(Debug, Clone)]
pub struct DelegationDecision {
    pub effect: DelegationEffect,
    pub matched_rule: Option<String>,
    pub reasoning: String,
}

/// Evaluates delegation requests against a set of configurable rules.
pub struct DelegationChecker {
    rules: Vec<DelegationRule>,
}

impl DelegationChecker {
    /// Create a new checker with the given rules.
    /// Rules will be sorted by priority (highest first).
    pub fn new(mut rules: Vec<DelegationRule>) -> Self {
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        Self { rules }
    }

    /// Create a checker with no rules (everything denied by default).
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Create a checker with permissive defaults (allow all).
    pub fn permissive() -> Self {
        Self::new(vec![DelegationRule {
            name: "allow-all".to_string(),
            priority: 0,
            effect: DelegationEffect::Allow,
            condition: DelegationCondition::default(),
        }])
    }

    /// Evaluate a delegation request against the rules.
    pub fn check(&self, request: &DelegationRequest) -> DelegationDecision {
        for rule in &self.rules {
            if self.matches_condition(&rule.condition, request) {
                return DelegationDecision {
                    effect: rule.effect,
                    matched_rule: Some(rule.name.clone()),
                    reasoning: format!("Delegation rule '{}' matched", rule.name),
                };
            }
        }

        // No match = Deny (fail-closed)
        DelegationDecision {
            effect: DelegationEffect::Deny,
            matched_rule: None,
            reasoning: "No delegation policy matched (fail-closed)".to_string(),
        }
    }

    fn matches_condition(
        &self,
        condition: &DelegationCondition,
        request: &DelegationRequest,
    ) -> bool {
        // Check delegator org level
        if let Some(min_level) = &condition.delegator_min_level {
            match request.delegator_org_level {
                Some(level) if level >= *min_level => {}
                _ => return false,
            }
        }

        // Check delegator type
        if let Some(dtype) = &condition.delegator_type {
            if request.delegator.kind != *dtype {
                return false;
            }
        }

        // Check target type
        if let Some(ttype) = &condition.target_type {
            if request.target.kind != *ttype {
                return false;
            }
        }

        // Check operations (if specified, at least one must be in the request)
        if !condition.operations.is_empty()
            && condition.operations.is_disjoint(request.operations)
        {
            return false;
        }

        // Check resource pattern
        if let (Some(rule_resource), Some(req_resource)) = (&condition.resource, request.resource) {
            // Rule resource must be a superset of (or equal to) the request resource
            if !req_resource.is_subset_of(rule_resource) {
                return false;
            }
        }

        // Check chain depth
        if let Some(max_depth) = condition.max_chain_depth {
            if request.current_chain_depth > max_depth {
                return false;
            }
        }

        true
    }

    /// Get the number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_core::id::{OrgPositionId, PrincipalId, TeamId};
    use mc_core::principal::{PrincipalDetails, PrincipalStatus, PrincipalTrustLevel};

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

    #[test]
    fn empty_checker_denies_all() {
        let checker = DelegationChecker::empty();
        let delegator = make_human("Alice");
        let target = make_agent("Bot");
        let ops: HashSet<Operation> = [Operation::Read].into_iter().collect();
        let req = DelegationRequest {
            delegator: &delegator,
            delegator_org_level: Some(OrgLevel::Individual),
            target: &target,
            operations: &ops,
            resource: None,
            current_chain_depth: 0,
        };
        let decision = checker.check(&req);
        assert_eq!(decision.effect, DelegationEffect::Deny);
        assert!(decision.matched_rule.is_none());
    }

    #[test]
    fn permissive_checker_allows_all() {
        let checker = DelegationChecker::permissive();
        let delegator = make_human("Alice");
        let target = make_agent("Bot");
        let ops: HashSet<Operation> = [Operation::Read].into_iter().collect();
        let req = DelegationRequest {
            delegator: &delegator,
            delegator_org_level: Some(OrgLevel::Individual),
            target: &target,
            operations: &ops,
            resource: None,
            current_chain_depth: 0,
        };
        let decision = checker.check(&req);
        assert_eq!(decision.effect, DelegationEffect::Allow);
    }

    #[test]
    fn vp_can_delegate_to_ai() {
        let rules = vec![DelegationRule {
            name: "vp-to-ai".to_string(),
            priority: 100,
            effect: DelegationEffect::Allow,
            condition: DelegationCondition {
                delegator_min_level: Some(OrgLevel::VP),
                target_type: Some(PrincipalKind::AiAgent),
                ..Default::default()
            },
        }];
        let checker = DelegationChecker::new(rules);
        let delegator = make_human("VP Alice");
        let target = make_agent("Bot");
        let ops: HashSet<Operation> = [Operation::Write].into_iter().collect();
        let req = DelegationRequest {
            delegator: &delegator,
            delegator_org_level: Some(OrgLevel::VP),
            target: &target,
            operations: &ops,
            resource: None,
            current_chain_depth: 0,
        };
        let decision = checker.check(&req);
        assert_eq!(decision.effect, DelegationEffect::Allow);
    }

    #[test]
    fn engineer_cannot_use_vp_rule() {
        let rules = vec![DelegationRule {
            name: "vp-to-ai".to_string(),
            priority: 100,
            effect: DelegationEffect::Allow,
            condition: DelegationCondition {
                delegator_min_level: Some(OrgLevel::VP),
                target_type: Some(PrincipalKind::AiAgent),
                ..Default::default()
            },
        }];
        let checker = DelegationChecker::new(rules);
        let delegator = make_human("Engineer Bob");
        let target = make_agent("Bot");
        let ops: HashSet<Operation> = [Operation::Write].into_iter().collect();
        let req = DelegationRequest {
            delegator: &delegator,
            delegator_org_level: Some(OrgLevel::Individual),
            target: &target,
            operations: &ops,
            resource: None,
            current_chain_depth: 0,
        };
        let decision = checker.check(&req);
        assert_eq!(decision.effect, DelegationEffect::Deny);
    }

    #[test]
    fn operation_filter_matches() {
        let rules = vec![DelegationRule {
            name: "read-only".to_string(),
            priority: 100,
            effect: DelegationEffect::Allow,
            condition: DelegationCondition {
                operations: [Operation::Read].into_iter().collect(),
                ..Default::default()
            },
        }];
        let checker = DelegationChecker::new(rules);
        let delegator = make_human("Alice");
        let target = make_agent("Bot");

        // Read matches
        let read_ops: HashSet<Operation> = [Operation::Read].into_iter().collect();
        let req = DelegationRequest {
            delegator: &delegator,
            delegator_org_level: None,
            target: &target,
            operations: &read_ops,
            resource: None,
            current_chain_depth: 0,
        };
        assert_eq!(checker.check(&req).effect, DelegationEffect::Allow);

        // Write doesn't match
        let write_ops: HashSet<Operation> = [Operation::Write].into_iter().collect();
        let req = DelegationRequest {
            delegator: &delegator,
            delegator_org_level: None,
            target: &target,
            operations: &write_ops,
            resource: None,
            current_chain_depth: 0,
        };
        assert_eq!(checker.check(&req).effect, DelegationEffect::Deny);
    }

    #[test]
    fn higher_priority_wins() {
        let rules = vec![
            DelegationRule {
                name: "deny-all".to_string(),
                priority: 200,
                effect: DelegationEffect::Deny,
                condition: DelegationCondition::default(),
            },
            DelegationRule {
                name: "allow-all".to_string(),
                priority: 100,
                effect: DelegationEffect::Allow,
                condition: DelegationCondition::default(),
            },
        ];
        let checker = DelegationChecker::new(rules);
        let delegator = make_human("Alice");
        let target = make_agent("Bot");
        let ops: HashSet<Operation> = [Operation::Read].into_iter().collect();
        let req = DelegationRequest {
            delegator: &delegator,
            delegator_org_level: None,
            target: &target,
            operations: &ops,
            resource: None,
            current_chain_depth: 0,
        };
        let decision = checker.check(&req);
        assert_eq!(decision.effect, DelegationEffect::Deny);
        assert_eq!(decision.matched_rule.as_deref(), Some("deny-all"));
    }

    #[test]
    fn chain_depth_limit() {
        let rules = vec![DelegationRule {
            name: "depth-limit".to_string(),
            priority: 100,
            effect: DelegationEffect::Deny,
            condition: DelegationCondition {
                delegator_type: Some(PrincipalKind::AiAgent),
                target_type: Some(PrincipalKind::AiAgent),
                max_chain_depth: Some(3),
                ..Default::default()
            },
        }];
        let checker = DelegationChecker::new(rules);
        let delegator = make_agent("Agent-A");
        let target = make_agent("Agent-B");
        let ops: HashSet<Operation> = [Operation::Read].into_iter().collect();

        // Within limit (depth 2) → rule doesn't match → falls through to deny
        let req = DelegationRequest {
            delegator: &delegator,
            delegator_org_level: None,
            target: &target,
            operations: &ops,
            resource: None,
            current_chain_depth: 2,
        };
        // The rule requires depth > 3 to NOT match, but max_chain_depth = 3
        // means depth <= 3 matches the rule. So depth 2 matches → Deny
        let decision = checker.check(&req);
        assert_eq!(decision.effect, DelegationEffect::Deny);

        // Above limit (depth 4) → condition doesn't match → falls through
        let req = DelegationRequest {
            delegator: &delegator,
            delegator_org_level: None,
            target: &target,
            operations: &ops,
            resource: None,
            current_chain_depth: 4,
        };
        let decision = checker.check(&req);
        // max_chain_depth = 3, current = 4, so 4 > 3 → condition doesn't match → fall through → deny
        assert_eq!(decision.effect, DelegationEffect::Deny);
    }

    #[test]
    fn require_approval_effect() {
        let rules = vec![DelegationRule {
            name: "write-needs-approval".to_string(),
            priority: 100,
            effect: DelegationEffect::RequireApproval,
            condition: DelegationCondition {
                operations: [Operation::Write].into_iter().collect(),
                target_type: Some(PrincipalKind::AiAgent),
                ..Default::default()
            },
        }];
        let checker = DelegationChecker::new(rules);
        let delegator = make_human("Alice");
        let target = make_agent("Bot");
        let ops: HashSet<Operation> = [Operation::Write].into_iter().collect();
        let req = DelegationRequest {
            delegator: &delegator,
            delegator_org_level: Some(OrgLevel::Individual),
            target: &target,
            operations: &ops,
            resource: None,
            current_chain_depth: 0,
        };
        let decision = checker.check(&req);
        assert_eq!(decision.effect, DelegationEffect::RequireApproval);
    }

    #[test]
    fn resource_pattern_matching() {
        let rules = vec![DelegationRule {
            name: "prod-db-approval".to_string(),
            priority: 200,
            effect: DelegationEffect::RequireApproval,
            condition: DelegationCondition {
                target_type: Some(PrincipalKind::AiAgent),
                operations: [Operation::Write, Operation::Delete].into_iter().collect(),
                resource: Some(ResourcePattern::new("db://production/**").unwrap()),
                ..Default::default()
            },
        }];
        let checker = DelegationChecker::new(rules);
        let delegator = make_human("Alice");
        let target = make_agent("Bot");
        let ops: HashSet<Operation> = [Operation::Write].into_iter().collect();

        // Production DB → requires approval
        let prod_res = ResourcePattern::new("db://production/users").unwrap();
        let req = DelegationRequest {
            delegator: &delegator,
            delegator_org_level: Some(OrgLevel::Individual),
            target: &target,
            operations: &ops,
            resource: Some(&prod_res),
            current_chain_depth: 0,
        };
        let decision = checker.check(&req);
        assert_eq!(decision.effect, DelegationEffect::RequireApproval);

        // Staging DB → no match → deny (fail-closed, no other rules)
        let staging_res = ResourcePattern::new("db://staging/users").unwrap();
        let req = DelegationRequest {
            delegator: &delegator,
            delegator_org_level: Some(OrgLevel::Individual),
            target: &target,
            operations: &ops,
            resource: Some(&staging_res),
            current_chain_depth: 0,
        };
        let decision = checker.check(&req);
        assert_eq!(decision.effect, DelegationEffect::Deny);
    }

    #[test]
    fn rule_count() {
        let checker = DelegationChecker::empty();
        assert_eq!(checker.rule_count(), 0);

        let checker = DelegationChecker::permissive();
        assert_eq!(checker.rule_count(), 1);
    }
}
