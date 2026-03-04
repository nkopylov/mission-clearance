use mc_core::id::PolicyId;
use mc_core::operation::{OperationClassification, OperationRequest};
use mc_core::policy::{
    EvaluationContext, PolicyDecision, PolicyDecisionKind, PolicyEvaluator, PolicyEvaluatorType,
};

/// Mock human-in-the-loop evaluator for testing.
///
/// Always returns a preconfigured decision. Use this in tests
/// and development when interactive human input is not available.
pub struct MockHuman {
    decision: PolicyDecisionKind,
    reasoning: String,
}

impl MockHuman {
    /// Create a mock human that always allows.
    pub fn always_allow() -> Self {
        Self {
            decision: PolicyDecisionKind::Allow,
            reasoning: "Mock human: approved".to_string(),
        }
    }

    /// Create a mock human that always denies with the given reason.
    pub fn always_deny(reason: &str) -> Self {
        Self {
            decision: PolicyDecisionKind::Deny,
            reasoning: format!("Mock human: denied - {}", reason),
        }
    }

    /// Create a mock human that always escalates.
    pub fn always_escalate() -> Self {
        Self {
            decision: PolicyDecisionKind::Escalate,
            reasoning: "Mock human: escalated (no resolution)".to_string(),
        }
    }
}

impl PolicyEvaluator for MockHuman {
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
            evaluator: PolicyEvaluatorType::Human,
        }
    }

    fn evaluator_type(&self) -> PolicyEvaluatorType {
        PolicyEvaluatorType::Human
    }
}

/// Terminal-based human-in-the-loop evaluator.
///
/// In a real deployment, this would display the operation details
/// to a terminal and prompt the human operator for a decision.
/// Currently provides a minimal implementation that fails closed
/// (denies by default) since interactive I/O is not always available.
pub struct TerminalHuman;

impl TerminalHuman {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TerminalHuman {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEvaluator for TerminalHuman {
    fn evaluate(
        &self,
        request: &OperationRequest,
        classification: &OperationClassification,
        context: &EvaluationContext,
    ) -> PolicyDecision {
        // In a real implementation, we would:
        // 1. Print the operation details to the terminal
        // 2. Wait for the human to input Allow/Deny/Escalate
        // 3. Return the human's decision
        tracing::warn!(
            resource = %request.resource,
            operation = ?request.operation,
            destructiveness = ?classification.destructiveness,
            mission_goal = %context.mission_goal,
            "Terminal human review requested but interactive I/O not implemented; failing closed"
        );

        PolicyDecision {
            policy_id: PolicyId::new(),
            kind: PolicyDecisionKind::Deny,
            reasoning: "Terminal human review unavailable; failing closed".to_string(),
            evaluator: PolicyEvaluatorType::Human,
        }
    }

    fn evaluator_type(&self) -> PolicyEvaluatorType {
        PolicyEvaluatorType::Human
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

    fn make_request() -> OperationRequest {
        OperationRequest {
            id: RequestId::new(),
            mission_id: MissionId::new(),
            resource: ResourceUri::new("shell://localhost/bin").unwrap(),
            operation: Operation::Execute,
            context: OperationContext::Shell {
                command: "rm".to_string(),
                args: vec!["-rf".to_string(), "/tmp/test".to_string()],
                working_dir: None,
            },
            justification: "Cleaning up temp files".to_string(),
            chain: vec![],
            timestamp: Utc::now(),
        }
    }

    fn make_classification() -> OperationClassification {
        OperationClassification {
            destructiveness: Destructiveness::High,
            reversibility: Reversibility::Irreversible,
            blast_radius: BlastRadius::Service,
            data_flow: DataFlowDirection::Internal,
            target_trust: TrustLevel::Known,
            pattern: OperationPattern::Normal,
            goal_relevance: GoalRelevance::DirectlyRelevant,
        }
    }

    fn make_context() -> EvaluationContext {
        EvaluationContext {
            mission_goal: "Clean up test artifacts".to_string(),
            mission_chain: vec![],
            recent_operations: vec![],
            anomaly_history: vec![],
        }
    }

    #[test]
    fn mock_human_allow() {
        let human = MockHuman::always_allow();
        let decision = human.evaluate(&make_request(), &make_classification(), &make_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
        assert_eq!(decision.evaluator, PolicyEvaluatorType::Human);
        assert!(decision.reasoning.contains("approved"));
    }

    #[test]
    fn mock_human_deny() {
        let human = MockHuman::always_deny("too destructive");
        let decision = human.evaluate(&make_request(), &make_classification(), &make_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("too destructive"));
    }

    #[test]
    fn mock_human_escalate() {
        let human = MockHuman::always_escalate();
        let decision = human.evaluate(&make_request(), &make_classification(), &make_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Escalate);
    }

    #[test]
    fn terminal_human_fails_closed() {
        let human = TerminalHuman::new();
        let decision = human.evaluate(&make_request(), &make_classification(), &make_context());
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reasoning.contains("failing closed"));
    }

    #[test]
    fn terminal_human_default() {
        let human = TerminalHuman::default();
        assert_eq!(human.evaluator_type(), PolicyEvaluatorType::Human);
    }

    #[test]
    fn evaluator_type_is_human() {
        let mock = MockHuman::always_allow();
        assert_eq!(mock.evaluator_type(), PolicyEvaluatorType::Human);

        let terminal = TerminalHuman::new();
        assert_eq!(terminal.evaluator_type(), PolicyEvaluatorType::Human);
    }
}
