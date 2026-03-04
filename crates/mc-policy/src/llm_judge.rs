use mc_core::id::PolicyId;
use mc_core::operation::{OperationClassification, OperationRequest};
use mc_core::policy::{
    EvaluationContext, PolicyDecision, PolicyDecisionKind, PolicyEvaluator, PolicyEvaluatorType,
};

/// LLM-based policy evaluator.
///
/// Constructs a prompt with mission context, recent operations, and the
/// current operation request/classification, then queries an LLM for a
/// policy decision.
pub struct LlmJudge {
    api_key: String,
    model: String,
    api_url: String,
}

impl LlmJudge {
    /// Create a new LLM judge with the given API key and model.
    /// Uses the OpenAI-compatible API endpoint by default.
    pub fn new(api_key: String, model: String) -> Self {
        Self {
            api_key,
            model,
            api_url: "https://api.openai.com/v1/chat/completions".to_string(),
        }
    }

    /// Create a new LLM judge with a custom API URL.
    pub fn with_api_url(api_key: String, model: String, api_url: String) -> Self {
        Self {
            api_key,
            model,
            api_url,
        }
    }

    /// Build the prompt for the LLM.
    ///
    /// This is public for testing purposes so we can verify prompt construction
    /// without calling the LLM.
    pub fn build_prompt(
        request: &OperationRequest,
        classification: &OperationClassification,
        context: &EvaluationContext,
    ) -> String {
        let mut prompt = String::new();

        prompt.push_str("You are a security policy evaluator for an AI agent system.\n\n");

        // Mission context
        prompt.push_str(&format!("## Mission Goal\n{}\n\n", context.mission_goal));

        if !context.mission_chain.is_empty() {
            prompt.push_str("## Mission Chain (parent goals)\n");
            for (i, goal) in context.mission_chain.iter().enumerate() {
                prompt.push_str(&format!("{}. {}\n", i + 1, goal));
            }
            prompt.push('\n');
        }

        // Recent operations
        if !context.recent_operations.is_empty() {
            prompt.push_str("## Recent Operations\n");
            for op in &context.recent_operations {
                prompt.push_str(&format!(
                    "- {} on {} -> {:?} at {}\n",
                    op.operation, op.resource, op.decision, op.timestamp
                ));
            }
            prompt.push('\n');
        }

        // Anomaly history
        if !context.anomaly_history.is_empty() {
            prompt.push_str("## Anomaly History\n");
            for anomaly in &context.anomaly_history {
                prompt.push_str(&format!("- {}\n", anomaly));
            }
            prompt.push('\n');
        }

        // Current operation
        prompt.push_str("## Current Operation Request\n");
        prompt.push_str(&format!("- Resource: {}\n", request.resource));
        prompt.push_str(&format!("- Operation: {:?}\n", request.operation));
        prompt.push_str(&format!("- Justification: {}\n", request.justification));
        prompt.push('\n');

        // Classification
        prompt.push_str("## Operation Classification\n");
        prompt.push_str(&format!(
            "- Destructiveness: {:?}\n",
            classification.destructiveness
        ));
        prompt.push_str(&format!(
            "- Reversibility: {:?}\n",
            classification.reversibility
        ));
        prompt.push_str(&format!(
            "- Blast Radius: {:?}\n",
            classification.blast_radius
        ));
        prompt.push_str(&format!("- Data Flow: {:?}\n", classification.data_flow));
        prompt.push_str(&format!(
            "- Target Trust: {:?}\n",
            classification.target_trust
        ));
        prompt.push_str(&format!("- Pattern: {:?}\n", classification.pattern));
        prompt.push_str(&format!(
            "- Goal Relevance: {:?}\n",
            classification.goal_relevance
        ));
        prompt.push('\n');

        prompt.push_str(
            "## Decision Required\n\
             Should this operation be ALLOWED, DENIED, or ESCALATED to a human reviewer?\n\
             Respond with JSON: {\"decision\": \"Allow\"|\"Deny\"|\"Escalate\", \"reasoning\": \"...\"}\n",
        );

        prompt
    }
}

impl PolicyEvaluator for LlmJudge {
    fn evaluate(
        &self,
        request: &OperationRequest,
        classification: &OperationClassification,
        context: &EvaluationContext,
    ) -> PolicyDecision {
        let _prompt = Self::build_prompt(request, classification, context);

        // In a real implementation, we would send the prompt to the LLM API
        // using self.api_key, self.model, and self.api_url.
        // For now, we fail closed: if the LLM cannot be reached, deny.
        tracing::warn!(
            model = %self.model,
            api_url = %self.api_url,
            has_api_key = !self.api_key.is_empty(),
            "LLM judge called but synchronous HTTP not implemented; failing closed"
        );

        PolicyDecision {
            policy_id: PolicyId::new(),
            kind: PolicyDecisionKind::Deny,
            reasoning: "LLM judge unavailable (sync implementation); failing closed".to_string(),
            evaluator: PolicyEvaluatorType::Llm,
        }
    }

    fn evaluator_type(&self) -> PolicyEvaluatorType {
        PolicyEvaluatorType::Llm
    }
}

/// Mock LLM judge for testing.
///
/// Always returns a preconfigured decision without calling any external API.
pub struct MockLlmJudge {
    decision: PolicyDecisionKind,
    reasoning: String,
}

impl MockLlmJudge {
    /// Create a mock that always allows.
    pub fn always_allow() -> Self {
        Self {
            decision: PolicyDecisionKind::Allow,
            reasoning: "Mock LLM: allowed".to_string(),
        }
    }

    /// Create a mock that always denies with the given reason.
    pub fn always_deny(reason: &str) -> Self {
        Self {
            decision: PolicyDecisionKind::Deny,
            reasoning: format!("Mock LLM: denied - {}", reason),
        }
    }

    /// Create a mock that always escalates.
    pub fn always_escalate() -> Self {
        Self {
            decision: PolicyDecisionKind::Escalate,
            reasoning: "Mock LLM: escalated".to_string(),
        }
    }
}

impl PolicyEvaluator for MockLlmJudge {
    fn evaluate(
        &self,
        _request: &OperationRequest,
        _classification: &OperationClassification,
        _context: &EvaluationContext,
    ) -> PolicyDecision {
        PolicyDecision {
            policy_id: PolicyId::new(),
            kind: self.decision,
            reasoning: self.reasoning.clone(),
            evaluator: PolicyEvaluatorType::Llm,
        }
    }

    fn evaluator_type(&self) -> PolicyEvaluatorType {
        PolicyEvaluatorType::Llm
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
    use mc_core::policy::OperationSummary;
    use mc_core::resource::ResourceUri;

    fn make_request() -> OperationRequest {
        OperationRequest {
            id: RequestId::new(),
            mission_id: MissionId::new(),
            resource: ResourceUri::new("http://api.github.com/repos/org/repo").unwrap(),
            operation: Operation::Write,
            context: OperationContext::Http {
                method: "POST".to_string(),
                headers: vec![],
                body_preview: Some("test body".to_string()),
            },
            justification: "Creating a new repository".to_string(),
            chain: vec![],
            timestamp: Utc::now(),
        }
    }

    fn make_classification() -> OperationClassification {
        OperationClassification {
            destructiveness: Destructiveness::Low,
            reversibility: Reversibility::Reversible,
            blast_radius: BlastRadius::Single,
            data_flow: DataFlowDirection::Outbound,
            target_trust: TrustLevel::Known,
            pattern: OperationPattern::Normal,
            goal_relevance: GoalRelevance::DirectlyRelevant,
        }
    }

    fn make_context() -> EvaluationContext {
        EvaluationContext {
            mission_goal: "Deploy the new feature to production".to_string(),
            mission_chain: vec!["Release version 2.0".to_string()],
            recent_operations: vec![OperationSummary {
                resource: "http://api.github.com/repos/org/repo".to_string(),
                operation: "Read".to_string(),
                decision: PolicyDecisionKind::Allow,
                timestamp: Utc::now(),
            }],
            anomaly_history: vec![],
        }
    }

    #[test]
    fn mock_allow() {
        let judge = MockLlmJudge::always_allow();
        let decision = judge.evaluate(&make_request(), &make_classification(), &make_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
        assert_eq!(decision.evaluator, PolicyEvaluatorType::Llm);
    }

    #[test]
    fn mock_deny() {
        let judge = MockLlmJudge::always_deny("test denial reason");
        let decision = judge.evaluate(&make_request(), &make_classification(), &make_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("test denial reason"));
    }

    #[test]
    fn mock_escalate() {
        let judge = MockLlmJudge::always_escalate();
        let decision = judge.evaluate(&make_request(), &make_classification(), &make_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
    }

    #[test]
    fn prompt_construction_contains_mission_goal() {
        let req = make_request();
        let cls = make_classification();
        let ctx = make_context();
        let prompt = LlmJudge::build_prompt(&req, &cls, &ctx);

        assert!(prompt.contains("Deploy the new feature to production"));
    }

    #[test]
    fn prompt_construction_contains_mission_chain() {
        let req = make_request();
        let cls = make_classification();
        let ctx = make_context();
        let prompt = LlmJudge::build_prompt(&req, &cls, &ctx);

        assert!(prompt.contains("Release version 2.0"));
    }

    #[test]
    fn prompt_construction_contains_operation_details() {
        let req = make_request();
        let cls = make_classification();
        let ctx = make_context();
        let prompt = LlmJudge::build_prompt(&req, &cls, &ctx);

        assert!(prompt.contains("Creating a new repository"));
        assert!(prompt.contains("api.github.com"));
        assert!(prompt.contains("Destructiveness"));
        assert!(prompt.contains("Reversibility"));
    }

    #[test]
    fn prompt_construction_contains_recent_operations() {
        let req = make_request();
        let cls = make_classification();
        let ctx = make_context();
        let prompt = LlmJudge::build_prompt(&req, &cls, &ctx);

        assert!(prompt.contains("Recent Operations"));
        assert!(prompt.contains("Read"));
    }

    #[test]
    fn prompt_construction_empty_chain() {
        let req = make_request();
        let cls = make_classification();
        let ctx = EvaluationContext {
            mission_goal: "Simple goal".to_string(),
            mission_chain: vec![],
            recent_operations: vec![],
            anomaly_history: vec![],
        };
        let prompt = LlmJudge::build_prompt(&req, &cls, &ctx);

        assert!(prompt.contains("Simple goal"));
        assert!(!prompt.contains("Mission Chain"));
    }

    #[test]
    fn real_llm_judge_fails_closed() {
        let judge = LlmJudge::new("fake-key".to_string(), "gpt-4".to_string());
        let decision = judge.evaluate(&make_request(), &make_classification(), &make_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("failing closed"));
    }

    #[test]
    fn evaluator_type_is_llm() {
        let judge = MockLlmJudge::always_allow();
        assert_eq!(judge.evaluator_type(), PolicyEvaluatorType::Llm);

        let real = LlmJudge::new("key".to_string(), "model".to_string());
        assert_eq!(real.evaluator_type(), PolicyEvaluatorType::Llm);
    }
}
