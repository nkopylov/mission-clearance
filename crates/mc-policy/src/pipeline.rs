use mc_core::id::PolicyId;
use mc_core::operation::{OperationClassification, OperationRequest};
use mc_core::policy::{
    EvaluationContext, PolicyDecision, PolicyDecisionKind, PolicyEvaluator, PolicyEvaluatorType,
};

/// Policy pipeline orchestrator.
///
/// Chains multiple policy evaluators in order. The pipeline processes
/// each evaluator sequentially with the following logic:
///
/// - If any evaluator returns **Deny**, the pipeline short-circuits and returns Deny.
/// - If an evaluator returns **Escalate**, the pipeline passes to the next evaluator.
/// - If an evaluator returns **Allow**, the pipeline continues to the next evaluator
///   (or returns Allow if this is the last evaluator).
/// - If the pipeline exhausts all evaluators with no definitive decision
///   (all escalated), it **fails closed** and returns Deny.
/// - An empty pipeline returns Deny (fail closed).
pub struct PolicyPipeline {
    evaluators: Vec<Box<dyn PolicyEvaluator>>,
}

impl PolicyPipeline {
    /// Create a new empty pipeline.
    pub fn new() -> Self {
        Self {
            evaluators: Vec::new(),
        }
    }

    /// Add an evaluator to the end of the pipeline.
    pub fn add_evaluator(&mut self, evaluator: Box<dyn PolicyEvaluator>) {
        self.evaluators.push(evaluator);
    }

    /// Return the number of evaluators in the pipeline.
    pub fn evaluator_count(&self) -> usize {
        self.evaluators.len()
    }

    /// Evaluate a request through the pipeline.
    pub fn evaluate(
        &self,
        request: &OperationRequest,
        classification: &OperationClassification,
        context: &EvaluationContext,
    ) -> PolicyDecision {
        if self.evaluators.is_empty() {
            return PolicyDecision {
                policy_id: PolicyId::new(),
                kind: PolicyDecisionKind::Deny,
                reasoning: "Empty pipeline: fail closed".to_string(),
                evaluator: PolicyEvaluatorType::Deterministic,
            };
        }

        let mut last_decision: Option<PolicyDecision> = None;

        for evaluator in &self.evaluators {
            let decision = evaluator.evaluate(request, classification, context);

            match decision.kind {
                PolicyDecisionKind::Deny => {
                    // Short-circuit: deny immediately
                    return decision;
                }
                PolicyDecisionKind::Allow => {
                    // Continue to next evaluator, but remember this as a potential final answer
                    last_decision = Some(decision);
                }
                PolicyDecisionKind::Escalate => {
                    // Pass to next evaluator
                    last_decision = Some(decision);
                    continue;
                }
            }
        }

        // If we get here, check the last decision
        match &last_decision {
            Some(d) if d.kind == PolicyDecisionKind::Allow => last_decision.unwrap(),
            _ => {
                // All escalated or no evaluators returned Allow: fail closed
                PolicyDecision {
                    policy_id: PolicyId::new(),
                    kind: PolicyDecisionKind::Deny,
                    reasoning: "Pipeline exhausted with no Allow decision: fail closed".to_string(),
                    evaluator: PolicyEvaluatorType::Deterministic,
                }
            }
        }
    }
}

impl Default for PolicyPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deterministic::DeterministicEvaluator;
    use crate::human::MockHuman;
    use crate::llm_judge::MockLlmJudge;
    use chrono::Utc;
    use mc_core::id::{MissionId, RequestId};
    use mc_core::operation::{
        BlastRadius, DataFlowDirection, Destructiveness, GoalRelevance, Operation,
        OperationClassification, OperationContext, OperationPattern, Reversibility, TrustLevel,
    };
    use mc_core::resource::ResourceUri;

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

    fn normal_classification() -> OperationClassification {
        OperationClassification {
            destructiveness: Destructiveness::None,
            reversibility: Reversibility::Reversible,
            blast_radius: BlastRadius::Single,
            data_flow: DataFlowDirection::Internal,
            target_trust: TrustLevel::Known,
            pattern: OperationPattern::Normal,
            goal_relevance: GoalRelevance::DirectlyRelevant,
        }
    }

    fn catastrophic_classification() -> OperationClassification {
        OperationClassification {
            destructiveness: Destructiveness::Catastrophic,
            reversibility: Reversibility::Irreversible,
            blast_radius: BlastRadius::Global,
            data_flow: DataFlowDirection::Internal,
            target_trust: TrustLevel::Known,
            pattern: OperationPattern::Normal,
            goal_relevance: GoalRelevance::DirectlyRelevant,
        }
    }

    fn default_context() -> EvaluationContext {
        EvaluationContext {
            mission_goal: "test mission".to_string(),
            mission_chain: vec![],
            recent_operations: vec![],
            anomaly_history: vec![],
        }
    }

    #[test]
    fn deny_short_circuits() {
        // Deterministic denies -> LLM and human never called
        let mut pipeline = PolicyPipeline::new();
        pipeline.add_evaluator(Box::new(DeterministicEvaluator::with_defaults()));
        pipeline.add_evaluator(Box::new(MockLlmJudge::always_allow()));
        pipeline.add_evaluator(Box::new(MockHuman::always_allow()));

        let req = make_request("shell://localhost/bin");
        let cls = catastrophic_classification();
        let decision = pipeline.evaluate(&req, &cls, &default_context());

        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert_eq!(decision.evaluator, PolicyEvaluatorType::Deterministic);
    }

    #[test]
    fn allow_passthrough() {
        // All evaluators allow -> final Allow
        let mut pipeline = PolicyPipeline::new();
        pipeline.add_evaluator(Box::new(DeterministicEvaluator::with_defaults()));
        pipeline.add_evaluator(Box::new(MockLlmJudge::always_allow()));
        pipeline.add_evaluator(Box::new(MockHuman::always_allow()));

        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let decision = pipeline.evaluate(&req, &cls, &default_context());

        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
    }

    #[test]
    fn escalate_to_next() {
        // First escalates, second allows -> Allow
        let mut pipeline = PolicyPipeline::new();
        pipeline.add_evaluator(Box::new(MockLlmJudge::always_escalate()));
        pipeline.add_evaluator(Box::new(MockHuman::always_allow()));

        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let decision = pipeline.evaluate(&req, &cls, &default_context());

        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
        assert_eq!(decision.evaluator, PolicyEvaluatorType::Human);
    }

    #[test]
    fn all_escalate_then_deny() {
        // All escalate -> fail closed (Deny)
        let mut pipeline = PolicyPipeline::new();
        pipeline.add_evaluator(Box::new(MockLlmJudge::always_escalate()));
        pipeline.add_evaluator(Box::new(MockHuman::always_escalate()));

        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let decision = pipeline.evaluate(&req, &cls, &default_context());

        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("fail closed"));
    }

    #[test]
    fn empty_pipeline_denies() {
        // No evaluators -> Deny (fail closed)
        let pipeline = PolicyPipeline::new();

        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let decision = pipeline.evaluate(&req, &cls, &default_context());

        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("Empty pipeline"));
    }

    #[test]
    fn deterministic_allow_llm_deny() {
        // Deterministic allows, LLM denies -> Deny
        let mut pipeline = PolicyPipeline::new();
        pipeline.add_evaluator(Box::new(DeterministicEvaluator::with_defaults()));
        pipeline.add_evaluator(Box::new(MockLlmJudge::always_deny("risky operation")));

        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let decision = pipeline.evaluate(&req, &cls, &default_context());

        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert_eq!(decision.evaluator, PolicyEvaluatorType::Llm);
    }

    #[test]
    fn full_pipeline_integration_allow() {
        // Full pipeline: deterministic + LLM + human, all allow
        let mut pipeline = PolicyPipeline::new();
        pipeline.add_evaluator(Box::new(DeterministicEvaluator::with_defaults()));
        pipeline.add_evaluator(Box::new(MockLlmJudge::always_allow()));
        pipeline.add_evaluator(Box::new(MockHuman::always_allow()));

        let req = make_request("http://api.github.com/repos/org/repo");
        let cls = normal_classification();
        let ctx = EvaluationContext {
            mission_goal: "Deploy feature".to_string(),
            mission_chain: vec!["Release v2".to_string()],
            recent_operations: vec![],
            anomaly_history: vec![],
        };
        let decision = pipeline.evaluate(&req, &cls, &ctx);

        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
    }

    #[test]
    fn full_pipeline_integration_deny_catastrophic() {
        // Full pipeline: catastrophic operation denied by deterministic
        let mut pipeline = PolicyPipeline::new();
        pipeline.add_evaluator(Box::new(DeterministicEvaluator::with_defaults()));
        pipeline.add_evaluator(Box::new(MockLlmJudge::always_allow()));
        pipeline.add_evaluator(Box::new(MockHuman::always_allow()));

        let req = make_request("shell://localhost/bin");
        let cls = catastrophic_classification();
        let decision = pipeline.evaluate(&req, &cls, &default_context());

        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert_eq!(decision.evaluator, PolicyEvaluatorType::Deterministic);
        assert!(decision
            .reasoning
            .contains("no-catastrophic-destruction"));
    }

    #[test]
    fn full_pipeline_escalate_then_human_allows() {
        // Deterministic allows, LLM escalates, human allows
        let mut pipeline = PolicyPipeline::new();
        pipeline.add_evaluator(Box::new(DeterministicEvaluator::with_defaults()));
        pipeline.add_evaluator(Box::new(MockLlmJudge::always_escalate()));
        pipeline.add_evaluator(Box::new(MockHuman::always_allow()));

        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let decision = pipeline.evaluate(&req, &cls, &default_context());

        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
        assert_eq!(decision.evaluator, PolicyEvaluatorType::Human);
    }

    #[test]
    fn full_pipeline_escalate_then_human_denies() {
        // Deterministic allows, LLM escalates, human denies
        let mut pipeline = PolicyPipeline::new();
        pipeline.add_evaluator(Box::new(DeterministicEvaluator::with_defaults()));
        pipeline.add_evaluator(Box::new(MockLlmJudge::always_escalate()));
        pipeline.add_evaluator(Box::new(MockHuman::always_deny("not approved")));

        let req = make_request("shell://localhost/bin");
        let cls = normal_classification();
        let decision = pipeline.evaluate(&req, &cls, &default_context());

        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert_eq!(decision.evaluator, PolicyEvaluatorType::Human);
    }

    #[test]
    fn evaluator_count() {
        let mut pipeline = PolicyPipeline::new();
        assert_eq!(pipeline.evaluator_count(), 0);

        pipeline.add_evaluator(Box::new(MockLlmJudge::always_allow()));
        assert_eq!(pipeline.evaluator_count(), 1);

        pipeline.add_evaluator(Box::new(MockHuman::always_allow()));
        assert_eq!(pipeline.evaluator_count(), 2);
    }

    #[test]
    fn default_pipeline_is_empty() {
        let pipeline = PolicyPipeline::default();
        assert_eq!(pipeline.evaluator_count(), 0);
    }
}
