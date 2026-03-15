use mc_core::id::PolicyId;
use mc_core::operation::{OperationClassification, OperationContext, OperationRequest};
use mc_core::policy::{
    EvaluationContext, PolicyDecision, PolicyDecisionKind, PolicyEvaluator, PolicyEvaluatorType,
};

/// Placeholder URL for the OpenAI-compatible chat completions endpoint.
///
/// This constant exists so the default is visible and easy to override via
/// [`LlmJudge::with_api_url`].  When the LLM judge is actually implemented,
/// this should be read from the application configuration instead of being
/// hardcoded.
const DEFAULT_LLM_API_URL: &str = "https://api.openai.com/v1/chat/completions";

/// LLM-based policy evaluator (**not yet implemented**).
///
/// This evaluator is a planned feature for v0.2+.  The prompt construction
/// logic ([`LlmJudge::build_prompt`]) is fully implemented and tested, but
/// the actual HTTP call to an LLM API is **not wired up**.  As a result,
/// [`PolicyEvaluator::evaluate`] always returns [`PolicyDecisionKind::Deny`]
/// (fail-closed behaviour) so that enabling the judge in a pipeline does not
/// silently skip LLM review.
///
/// Use [`MockLlmJudge`] for testing pipelines that include an LLM evaluator.
pub struct LlmJudge {
    api_key: String,
    model: String,
    api_url: String,
}

impl LlmJudge {
    /// Create a new LLM judge with the given API key and model.
    ///
    /// Uses [`DEFAULT_LLM_API_URL`] as the API endpoint.
    ///
    /// **Note:** The LLM judge is not yet implemented.  `evaluate()` will
    /// always return `Deny` (fail-closed).
    pub fn new(api_key: String, model: String) -> Self {
        tracing::info!(
            model = %model,
            "LLM judge is not yet implemented; evaluate() will fail closed (Deny)"
        );
        Self {
            api_key,
            model,
            api_url: DEFAULT_LLM_API_URL.to_string(),
        }
    }

    /// Create a new LLM judge with a custom API URL.
    ///
    /// **Note:** The LLM judge is not yet implemented.  `evaluate()` will
    /// always return `Deny` (fail-closed).
    pub fn with_api_url(api_key: String, model: String, api_url: String) -> Self {
        tracing::info!(
            model = %model,
            api_url = %api_url,
            "LLM judge is not yet implemented; evaluate() will fail closed (Deny)"
        );
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

        // Include full command content for shell operations
        match &request.context {
            OperationContext::Shell { command, args, .. } => {
                let full_cmd = if args.is_empty() {
                    command.clone()
                } else {
                    format!("{} {}", command, args.join(" "))
                };
                prompt.push_str(&format!("- Full Command: {}\n", full_cmd));
            }
            OperationContext::Database { query, database } => {
                prompt.push_str(&format!("- Database: {}\n", database));
                prompt.push_str(&format!("- Query: {}\n", query));
            }
            OperationContext::Http { method, body_preview, .. } => {
                prompt.push_str(&format!("- HTTP Method: {}\n", method));
                if let Some(body) = body_preview {
                    prompt.push_str(&format!("- Body Preview: {}\n", body));
                }
            }
            OperationContext::ToolCall { tool_name, arguments } => {
                prompt.push_str(&format!("- Tool: {}\n", tool_name));
                prompt.push_str(&format!("- Arguments: {}\n", arguments));
            }
            OperationContext::FileWrite { path, content_preview } => {
                prompt.push_str(&format!("- File Path: {}\n", path));
                let preview = if content_preview.len() > 500 {
                    &content_preview[..500]
                } else {
                    content_preview.as_str()
                };
                prompt.push_str(&format!("- Content Preview:\n```\n{}\n```\n", preview));
            }
        }
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

        // Extracted signals
        let signals = &classification.signals;
        prompt.push_str("## Extracted Signals\n");
        prompt.push_str(&format!("- Reads Sensitive Source: {}\n", signals.reads_sensitive_source));
        prompt.push_str(&format!("- Has Network Sink: {}\n", signals.has_network_sink));
        prompt.push_str(&format!("- Executes Dynamic Code: {}\n", signals.executes_dynamic_code));
        prompt.push_str(&format!("- Writes Persistence Point: {}\n", signals.writes_persistence_point));
        prompt.push_str(&format!("- Modifies Security Controls: {}\n", signals.modifies_security_controls));
        prompt.push_str(&format!("- Uses Obfuscation: {}\n", signals.uses_obfuscation));
        prompt.push_str(&format!("- Has Pipe Chain: {}\n", signals.has_pipe_chain));
        if let Some(ref taint) = signals.pipe_chain_taint {
            prompt.push_str(&format!("- Pipe Chain Source-to-Sink Flow: {}\n", taint.source_to_sink_flow));
            for seg in &taint.segments {
                prompt.push_str(&format!("  - Segment: {:?} -> {:?}\n", seg.raw, seg.role));
            }
        }
        match signals.dynamic_code_is_benign {
            Some(true) => prompt.push_str("- Dynamic Code Assessment: BENIGN\n"),
            Some(false) => prompt.push_str("- Dynamic Code Assessment: DANGEROUS\n"),
            None => {
                if signals.executes_dynamic_code {
                    prompt.push_str("- Dynamic Code Assessment: UNCERTAIN\n");
                }
            }
        }
        prompt.push('\n');

        prompt.push_str(
            "## Decision Required\n\
             Should this operation be ALLOWED, DENIED, or ESCALATED to a human reviewer?\n\
             Respond with JSON: {\"decision\": \"Allow\"|\"Deny\"|\"Escalate\", \"reasoning\": \"...\"}\n\n\
             If you detect a command, tool, path, or code pattern that the deterministic\n\
             signals MISSED, mention it explicitly in your reasoning. For example:\n\
             \"The command 'http' (httpie) is a network tool not in the detector's list.\"\n\
             This helps the feedback loop learn new patterns.\n",
        );

        prompt
    }
}

impl PolicyEvaluator for LlmJudge {
    /// Evaluate a policy decision using the LLM.
    ///
    /// **Not yet implemented.** Always returns [`PolicyDecisionKind::Deny`]
    /// (fail-closed) because the HTTP call to the LLM API has not been wired
    /// up.  The prompt *is* constructed (via [`Self::build_prompt`]) so that
    /// it can be inspected in traces.
    fn evaluate(
        &self,
        request: &OperationRequest,
        classification: &OperationClassification,
        context: &EvaluationContext,
    ) -> PolicyDecision {
        let _prompt = Self::build_prompt(request, classification, context);

        // The LLM HTTP call is not yet implemented.  This is expected
        // behaviour — log at info level, not warn.
        tracing::info!(
            model = %self.model,
            api_url = %self.api_url,
            has_api_key = !self.api_key.is_empty(),
            "LLM judge not yet implemented; failing closed"
        );

        PolicyDecision {
            policy_id: PolicyId::new(),
            kind: PolicyDecisionKind::Deny,
            reasoning: "LLM judge not yet implemented; failing closed".to_string(),
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
        OperationClassification, OperationContext, OperationPattern, OperationSignals,
        Reversibility, TrustLevel,
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
            signals: OperationSignals::default(),
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
            executes_session_written_file: false,
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
            executes_session_written_file: false,
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
