use mc_core::id::PolicyId;
use mc_core::operation::{
    DataFlowDirection, Destructiveness, GoalRelevance, OperationClassification, OperationPattern,
    OperationRequest, Reversibility, TrustLevel,
};
use mc_core::policy::{
    EvaluationContext, PolicyDecision, PolicyDecisionKind, PolicyEvaluator, PolicyEvaluatorType,
};

/// A single deterministic rule that evaluates an operation request
/// and its classification, returning an optional policy decision.
struct DeterministicRule {
    name: String,
    evaluate:
        Box<dyn Fn(&OperationRequest, &OperationClassification) -> Option<PolicyDecisionKind> + Send + Sync>,
}

/// Deterministic (rule-based) policy evaluator.
///
/// Evaluates hard rules against the operation classification axes.
/// Returns the first matching rule's decision, or `Allow` if no rule matches.
pub struct DeterministicEvaluator {
    rules: Vec<DeterministicRule>,
}

impl DeterministicEvaluator {
    /// Create a new evaluator with all built-in rules from the Mission Clearance design.
    ///
    /// Built-in rules:
    /// 1. `no-catastrophic-destruction` -- DENY when destructiveness == Catastrophic AND reversibility == Irreversible
    /// 2. `no-exfiltration` -- DENY when data_flow == ExfiltrationSuspected
    /// 3. `no-self-modification` -- DENY when resource URI contains "mission-clearance" or "system-prompt"
    /// 4. `no-privilege-escalation` -- DENY when pattern == KnownMalicious
    /// 5. `unknown-destination-review` -- ESCALATE when data_flow == Outbound AND target_trust == Unknown
    /// 6. `goal-drift-detection` -- ESCALATE when goal_relevance == Unrelated OR Contradictory
    pub fn with_defaults() -> Self {
        let rules = vec![
            DeterministicRule {
                name: "no-catastrophic-destruction".to_string(),
                evaluate: Box::new(|_req, cls| {
                    if cls.destructiveness == Destructiveness::Catastrophic
                        && cls.reversibility == Reversibility::Irreversible
                    {
                        Some(PolicyDecisionKind::Deny)
                    } else {
                        None
                    }
                }),
            },
            DeterministicRule {
                name: "no-exfiltration".to_string(),
                evaluate: Box::new(|_req, cls| {
                    if cls.data_flow == DataFlowDirection::ExfiltrationSuspected {
                        Some(PolicyDecisionKind::Deny)
                    } else {
                        None
                    }
                }),
            },
            DeterministicRule {
                name: "no-self-modification".to_string(),
                evaluate: Box::new(|req, _cls| {
                    let uri = req.resource.as_str().to_lowercase();
                    if uri.contains("mission-clearance") || uri.contains("system-prompt") {
                        Some(PolicyDecisionKind::Deny)
                    } else {
                        None
                    }
                }),
            },
            DeterministicRule {
                name: "no-privilege-escalation".to_string(),
                evaluate: Box::new(|_req, cls| {
                    if cls.pattern == OperationPattern::KnownMalicious {
                        Some(PolicyDecisionKind::Deny)
                    } else {
                        None
                    }
                }),
            },
            DeterministicRule {
                name: "unknown-destination-review".to_string(),
                evaluate: Box::new(|_req, cls| {
                    if cls.data_flow == DataFlowDirection::Outbound
                        && cls.target_trust == TrustLevel::Unknown
                    {
                        Some(PolicyDecisionKind::Escalate)
                    } else {
                        None
                    }
                }),
            },
            DeterministicRule {
                name: "goal-drift-detection".to_string(),
                evaluate: Box::new(|_req, cls| {
                    if cls.goal_relevance == GoalRelevance::Unrelated
                        || cls.goal_relevance == GoalRelevance::Contradictory
                    {
                        Some(PolicyDecisionKind::Escalate)
                    } else {
                        None
                    }
                }),
            },
        ];

        Self { rules }
    }

    /// Create a new evaluator with no rules (empty).
    pub fn new_empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a custom rule to the evaluator.
    pub fn add_rule(
        &mut self,
        name: impl Into<String>,
        evaluate: impl Fn(&OperationRequest, &OperationClassification) -> Option<PolicyDecisionKind>
            + Send
            + Sync
            + 'static,
    ) {
        self.rules.push(DeterministicRule {
            name: name.into(),
            evaluate: Box::new(evaluate),
        });
    }
}

impl PolicyEvaluator for DeterministicEvaluator {
    fn evaluate(
        &self,
        request: &OperationRequest,
        classification: &OperationClassification,
        _context: &EvaluationContext,
    ) -> PolicyDecision {
        for rule in &self.rules {
            if let Some(kind) = (rule.evaluate)(request, classification) {
                return PolicyDecision {
                    policy_id: PolicyId::new(),
                    kind,
                    reasoning: format!("Rule '{}' triggered", rule.name),
                    evaluator: PolicyEvaluatorType::Deterministic,
                };
            }
        }

        // No rule matched: allow
        PolicyDecision {
            policy_id: PolicyId::new(),
            kind: PolicyDecisionKind::Allow,
            reasoning: "No deterministic rule triggered".to_string(),
            evaluator: PolicyEvaluatorType::Deterministic,
        }
    }

    fn evaluator_type(&self) -> PolicyEvaluatorType {
        PolicyEvaluatorType::Deterministic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use mc_core::id::{MissionId, RequestId};
    use mc_core::operation::{
        BlastRadius, DataFlowDirection, Destructiveness, GoalRelevance, Operation,
        OperationClassification, OperationContext, OperationPattern, Reversibility, TrustLevel,
    };
    use mc_core::resource::ResourceUri;

    fn default_context() -> EvaluationContext {
        EvaluationContext {
            mission_goal: "test mission".to_string(),
            mission_chain: vec![],
            recent_operations: vec![],
            anomaly_history: vec![],
        }
    }

    fn make_request(resource_uri: &str) -> OperationRequest {
        OperationRequest {
            id: RequestId::new(),
            mission_id: MissionId::new(),
            resource: ResourceUri::new(resource_uri).unwrap(),
            operation: Operation::Execute,
            context: OperationContext::Shell {
                command: "test".to_string(),
                args: vec![],
                working_dir: None,
            },
            justification: "test".to_string(),
            chain: vec![],
            timestamp: Utc::now(),
        }
    }

    fn make_classification(
        destructiveness: Destructiveness,
        reversibility: Reversibility,
        data_flow: DataFlowDirection,
        target_trust: TrustLevel,
        pattern: OperationPattern,
        goal_relevance: GoalRelevance,
    ) -> OperationClassification {
        OperationClassification {
            destructiveness,
            reversibility,
            blast_radius: BlastRadius::Single,
            data_flow,
            target_trust,
            pattern,
            goal_relevance,
        }
    }

    fn normal_classification() -> OperationClassification {
        make_classification(
            Destructiveness::None,
            Reversibility::Reversible,
            DataFlowDirection::Internal,
            TrustLevel::Known,
            OperationPattern::Normal,
            GoalRelevance::DirectlyRelevant,
        )
    }

    #[test]
    fn deny_catastrophic_irreversible() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification(
            Destructiveness::Catastrophic,
            Reversibility::Irreversible,
            DataFlowDirection::Internal,
            TrustLevel::Known,
            OperationPattern::Normal,
            GoalRelevance::DirectlyRelevant,
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("no-catastrophic-destruction"));
    }

    #[test]
    fn allow_catastrophic_reversible() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification(
            Destructiveness::Catastrophic,
            Reversibility::Reversible,
            DataFlowDirection::Internal,
            TrustLevel::Known,
            OperationPattern::Normal,
            GoalRelevance::DirectlyRelevant,
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
    }

    #[test]
    fn deny_exfiltration() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification(
            Destructiveness::None,
            Reversibility::Reversible,
            DataFlowDirection::ExfiltrationSuspected,
            TrustLevel::Known,
            OperationPattern::Normal,
            GoalRelevance::DirectlyRelevant,
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("no-exfiltration"));
    }

    #[test]
    fn deny_self_modification_mission_clearance() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("file://localhost/home/user/mission-clearance/config.yaml");
        let cls = normal_classification();
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("no-self-modification"));
    }

    #[test]
    fn deny_self_modification_system_prompt() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("file://localhost/etc/system-prompt.txt");
        let cls = normal_classification();
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("no-self-modification"));
    }

    #[test]
    fn deny_known_malicious() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification(
            Destructiveness::None,
            Reversibility::Reversible,
            DataFlowDirection::Internal,
            TrustLevel::Known,
            OperationPattern::KnownMalicious,
            GoalRelevance::DirectlyRelevant,
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("no-privilege-escalation"));
    }

    #[test]
    fn escalate_unknown_destination() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("http://suspicious-site.xyz/data");
        let cls = make_classification(
            Destructiveness::None,
            Reversibility::Reversible,
            DataFlowDirection::Outbound,
            TrustLevel::Unknown,
            OperationPattern::Normal,
            GoalRelevance::DirectlyRelevant,
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
        assert!(decision.reasoning.contains("unknown-destination-review"));
    }

    #[test]
    fn escalate_goal_drift_unrelated() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification(
            Destructiveness::None,
            Reversibility::Reversible,
            DataFlowDirection::Internal,
            TrustLevel::Known,
            OperationPattern::Normal,
            GoalRelevance::Unrelated,
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
        assert!(decision.reasoning.contains("goal-drift-detection"));
    }

    #[test]
    fn escalate_goal_drift_contradictory() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification(
            Destructiveness::None,
            Reversibility::Reversible,
            DataFlowDirection::Internal,
            TrustLevel::Known,
            OperationPattern::Normal,
            GoalRelevance::Contradictory,
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
        assert!(decision.reasoning.contains("goal-drift-detection"));
    }

    #[test]
    fn allow_normal_operation() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
        assert!(decision.reasoning.contains("No deterministic rule triggered"));
    }

    #[test]
    fn custom_rule_fires() {
        let mut eval = DeterministicEvaluator::new_empty();
        eval.add_rule("custom-deny-all", |_req, _cls| {
            Some(PolicyDecisionKind::Deny)
        });
        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("custom-deny-all"));
    }

    #[test]
    fn empty_evaluator_allows() {
        let eval = DeterministicEvaluator::new_empty();
        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
    }

    #[test]
    fn first_matching_rule_wins() {
        // Both exfiltration and known-malicious could match,
        // but exfiltration comes first in the default ordering.
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification(
            Destructiveness::None,
            Reversibility::Reversible,
            DataFlowDirection::ExfiltrationSuspected,
            TrustLevel::Known,
            OperationPattern::KnownMalicious,
            GoalRelevance::DirectlyRelevant,
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        // exfiltration rule fires first
        assert!(decision.reasoning.contains("no-exfiltration"));
    }

    #[test]
    fn evaluator_type_is_deterministic() {
        let eval = DeterministicEvaluator::with_defaults();
        assert_eq!(eval.evaluator_type(), PolicyEvaluatorType::Deterministic);
    }
}
