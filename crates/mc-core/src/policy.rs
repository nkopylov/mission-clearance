use crate::id::PolicyId;
use crate::operation::{OperationClassification, OperationRequest};
use serde::{Deserialize, Serialize};

/// The scope to which a policy applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyScope {
    /// Applies to all operations globally.
    Global,
    /// Applies to operations on a specific resource pattern.
    Resource,
    /// Applies to operations within a specific mission.
    Mission,
}

/// The type of evaluator that produced a policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEvaluatorType {
    Deterministic,
    Llm,
    Human,
}

/// The kind of decision a policy evaluator can make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecisionKind {
    Allow,
    Deny,
    Escalate,
}

/// A decision produced by a policy evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub policy_id: PolicyId,
    pub kind: PolicyDecisionKind,
    pub reasoning: String,
    pub evaluator: PolicyEvaluatorType,
}

/// Trait for policy evaluators in the pipeline.
///
/// Each evaluator receives the operation request, its classification,
/// and contextual information about the mission, then produces a decision.
pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(
        &self,
        request: &OperationRequest,
        classification: &OperationClassification,
        context: &EvaluationContext,
    ) -> PolicyDecision;

    fn evaluator_type(&self) -> PolicyEvaluatorType;
}

/// Context provided to policy evaluators for informed decision-making.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationContext {
    /// The stated goal of the mission requesting the operation.
    pub mission_goal: String,
    /// Goals of ancestor missions in the delegation chain.
    pub mission_chain: Vec<String>,
    /// Recent operations performed by this mission.
    pub recent_operations: Vec<OperationSummary>,
    /// Any anomaly events in the mission's history.
    pub anomaly_history: Vec<String>,
    /// Whether the operation targets a file that was written earlier in the same session.
    /// Used by the execute-after-write-review rule to detect write-then-execute attacks.
    #[serde(default)]
    pub executes_session_written_file: bool,
    /// The delegation chain of principals from leaf to root. Empty in legacy mode.
    #[serde(default)]
    pub principal_chain: Vec<crate::principal::PrincipalSummary>,
    /// The effective trust level of the requesting principal. `None` in legacy mode.
    #[serde(default)]
    pub effective_trust_level: Option<crate::principal::PrincipalTrustLevel>,
    /// Anomaly flags detected during chain verification.
    #[serde(default)]
    pub chain_anomaly_flags: Vec<crate::delegation::ChainAnomalyFlag>,
}

/// A summary of a previously executed operation, used in evaluation context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationSummary {
    pub resource: String,
    pub operation: String,
    pub decision: PolicyDecisionKind,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// A stored policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: PolicyId,
    pub name: String,
    pub scope: PolicyScope,
    pub evaluator: PolicyEvaluatorType,
    pub priority: u32,
    pub rule: PolicyRule,
}

/// The rule body of a policy.
///
/// Deterministic rules are condition expressions; LLM/human rules are prompts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyRule {
    DenyWhen(String),
    EscalateWhen(String),
    AllowWhen(String),
    LlmPrompt(String),
    HumanPrompt(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_scope_variants() {
        let global = PolicyScope::Global;
        let resource = PolicyScope::Resource;
        let mission = PolicyScope::Mission;
        assert_ne!(global, resource);
        assert_ne!(resource, mission);
    }

    #[test]
    fn test_policy_decision_serialize() {
        let decision = PolicyDecision {
            policy_id: PolicyId::new(),
            kind: PolicyDecisionKind::Deny,
            reasoning: "catastrophic operation".to_string(),
            evaluator: PolicyEvaluatorType::Deterministic,
        };
        let json = serde_json::to_string(&decision).unwrap();
        let deser: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.kind, PolicyDecisionKind::Deny);
        assert_eq!(deser.evaluator, PolicyEvaluatorType::Deterministic);
    }

    #[test]
    fn test_policy_rule_variants() {
        let deny = PolicyRule::DenyWhen("destructiveness == Catastrophic".into());
        let escalate = PolicyRule::EscalateWhen("data_flow == Outbound".into());
        let allow = PolicyRule::AllowWhen("pattern == Normal".into());
        let llm = PolicyRule::LlmPrompt("Is this safe?".into());
        let human = PolicyRule::HumanPrompt("Please review".into());

        // Verify they round-trip through serde
        for rule in [deny, escalate, allow, llm, human] {
            let json = serde_json::to_string(&rule).unwrap();
            let _: PolicyRule = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_policy_struct() {
        let policy = Policy {
            id: PolicyId::new(),
            name: "no-catastrophic-destruction".to_string(),
            scope: PolicyScope::Global,
            evaluator: PolicyEvaluatorType::Deterministic,
            priority: 100,
            rule: PolicyRule::DenyWhen(
                "destructiveness == Catastrophic AND reversibility == Irreversible".into(),
            ),
        };
        let json = serde_json::to_string(&policy).unwrap();
        let deser: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.name, "no-catastrophic-destruction");
        assert_eq!(deser.priority, 100);
    }
}
