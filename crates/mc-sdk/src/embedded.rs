use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use mc_api::routes::missions::{CapabilitySpec, MissionResponse};
use mc_api::routes::operations::OperationDecisionResponse;
use mc_api::routes::vault::VaultEntryResponse;
use mc_api::state::AppState;
use mc_core::capability::{Capability, Constraints};
use mc_core::id::{CapabilityId, MissionToken, RequestId};
use mc_kernel::signal_enricher::{HeuristicEnricher, SignalEnricher};
use mc_core::operation::{Operation, OperationContext, OperationRequest};
#[cfg(feature = "feedback-loop")]
use mc_policy::feedback::FeedbackLoop;
use mc_core::policy::{EvaluationContext, PolicyDecisionKind};
use mc_core::resource::{ResourcePattern, ResourceUri};
use mc_core::trace::TraceEventType;
use mc_core::vault::SecretType;
use mc_policy::deterministic::DeterministicEvaluator;

/// In-process kernel for direct access without HTTP.
///
/// Wraps all subsystems in a single struct, providing typed
/// access to missions, vault, operations, and tracing.
pub struct EmbeddedKernel {
    state: Arc<AppState>,
    signal_enricher: Box<dyn SignalEnricher>,
    #[cfg(feature = "feedback-loop")]
    feedback_loop: Option<FeedbackLoop>,
}

impl EmbeddedKernel {
    /// Create a new in-process kernel with all subsystems initialized in memory.
    ///
    /// The `vault_passphrase` is used to encrypt the in-memory vault.
    /// Callers should source this from an environment variable or secure input
    /// rather than hardcoding it.
    pub fn new(max_delegation_depth: u32, vault_passphrase: &str) -> Result<Self> {
        let state = Arc::new(AppState {
            mission_manager: std::sync::Mutex::new(
                mc_kernel::manager::MissionManager::new(max_delegation_depth),
            ),
            vault: std::sync::Mutex::new(
                mc_vault::store::VaultStore::new(":memory:", vault_passphrase)
                    .context("failed to create in-memory vault")?,
            ),
            event_log: std::sync::Mutex::new(
                mc_trace::event_log::EventLog::new(":memory:")
                    .context("failed to create in-memory event log")?,
            ),
            graph: std::sync::Mutex::new(
                mc_trace::graph::MissionGraph::new(":memory:")
                    .context("failed to create in-memory mission graph")?,
            ),
            policy_pipeline: {
                let mut pipeline = mc_policy::pipeline::PolicyPipeline::new();
                pipeline.add_evaluator(Box::new(DeterministicEvaluator::with_defaults()));
                pipeline
            },
            #[cfg(feature = "feedback-loop")]
            feedback_loop: None,
            expected_api_key: None,
            permission_graph: std::sync::Mutex::new(
                mc_graph::store::PermissionGraphStore::new(":memory:")
                    .context("failed to create in-memory permission graph")?,
            ),
            delegation_engine: mc_graph::delegation_engine::DelegationChecker::permissive(),
        });

        Ok(Self {
            state,
            signal_enricher: Box::new(HeuristicEnricher::new()),
            #[cfg(feature = "feedback-loop")]
            feedback_loop: FeedbackLoop::auto_detect(),
        })
    }

    /// Create a new kernel wrapping existing `AppState` (useful for testing).
    pub fn with_state(state: Arc<AppState>) -> Self {
        Self {
            state,
            signal_enricher: Box::new(HeuristicEnricher::new()),
            #[cfg(feature = "feedback-loop")]
            feedback_loop: None,
        }
    }

    /// Enable the feedback loop for automatic pattern learning.
    ///
    /// When enabled, disagreements between deterministic and LLM evaluators
    /// trigger a sub-agent that modifies the source code pattern lists.
    ///
    /// Only available when compiled with the `feedback-loop` feature.
    #[cfg(feature = "feedback-loop")]
    pub fn with_feedback_loop(mut self, project_root: std::path::PathBuf) -> Self {
        self.feedback_loop = Some(FeedbackLoop::new(project_root));
        self
    }

    /// Return a reference to the internal `AppState`.
    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    // ---- Mission operations ----

    /// Create a root mission.
    pub fn create_mission(
        &self,
        goal: &str,
        capabilities: Vec<CapabilitySpec>,
        policies: Vec<String>,
    ) -> Result<MissionResponse> {
        let caps = capabilities
            .iter()
            .map(spec_to_capability)
            .collect::<Result<Vec<_>>>()?;

        let policy_ids = parse_policy_ids(&policies)?;

        let mut mgr = self.state.mission_manager.lock().map_err(|e| anyhow::anyhow!("mission manager lock poisoned: {e}"))?;
        let mission = mgr
            .create_root_mission(goal.to_string(), caps, policy_ids)
            .context("failed to create root mission")?;

        // Log the event.
        if let Ok(log) = self.state.event_log.lock() {
            if let Err(e) = log.append(
                mission.id,
                TraceEventType::MissionCreated,
                None,
                serde_json::json!({"goal": &mission.goal}),
            ) {
                tracing::error!("Failed to append trace event: {e}");
            }
        }

        Ok(mission_to_response(&mission))
    }

    /// Get a mission by ID string.
    pub fn get_mission(&self, id: &str) -> Result<MissionResponse> {
        let mission_id = uuid::Uuid::parse_str(id)
            .map(mc_core::id::MissionId::from_uuid)
            .context("invalid mission ID")?;

        let mgr = self.state.mission_manager.lock().map_err(|e| anyhow::anyhow!("mission manager lock poisoned: {e}"))?;
        let mission = mgr
            .get(&mission_id)
            .context("mission not found")?;

        Ok(mission_to_response(mission))
    }

    /// Delegate a child mission from a parent.
    pub fn delegate_mission(
        &self,
        parent_id: &str,
        goal: &str,
        capabilities: Vec<CapabilitySpec>,
        policies: Vec<String>,
    ) -> Result<MissionResponse> {
        let parent_mission_id = uuid::Uuid::parse_str(parent_id)
            .map(mc_core::id::MissionId::from_uuid)
            .context("invalid parent mission ID")?;

        let caps = capabilities
            .iter()
            .map(spec_to_capability)
            .collect::<Result<Vec<_>>>()?;

        let policy_ids = parse_policy_ids(&policies)?;

        let mut mgr = self.state.mission_manager.lock().map_err(|e| anyhow::anyhow!("mission manager lock poisoned: {e}"))?;
        let child = mgr
            .delegate(parent_mission_id, goal.to_string(), caps, policy_ids)
            .context("failed to delegate mission")?;

        // Log delegation event.
        if let Ok(log) = self.state.event_log.lock() {
            if let Err(e) = log.append(
                child.id,
                TraceEventType::MissionDelegated,
                None,
                serde_json::json!({"parent": parent_id, "goal": &child.goal}),
            ) {
                tracing::error!("Failed to append trace event: {e}");
            }
        }

        Ok(mission_to_response(&child))
    }

    /// Revoke a mission and all descendants. Returns the list of revoked IDs.
    pub fn revoke_mission(&self, id: &str) -> Result<Vec<String>> {
        let mission_id = uuid::Uuid::parse_str(id)
            .map(mc_core::id::MissionId::from_uuid)
            .context("invalid mission ID")?;

        let mut mgr = self.state.mission_manager.lock().map_err(|e| anyhow::anyhow!("mission manager lock poisoned: {e}"))?;
        let revoked = mgr
            .revoke(mission_id)
            .context("failed to revoke mission")?;

        // Log revocation events.
        if let Ok(log) = self.state.event_log.lock() {
            for mid in &revoked {
                if let Err(e) = log.append(
                    *mid,
                    TraceEventType::MissionRevoked,
                    None,
                    serde_json::json!({"revoked_by": id}),
                ) {
                    tracing::error!("Failed to append trace event: {e}");
                }
            }
        }

        Ok(revoked.iter().map(|m| m.to_string()).collect())
    }

    // ---- Vault operations ----

    /// Add a credential to the vault.
    pub fn vault_add(
        &self,
        name: &str,
        secret_type: &str,
        value: &str,
        resource_patterns: Vec<String>,
    ) -> Result<String> {
        let st = parse_secret_type(secret_type)?;

        let bound_to: HashSet<ResourcePattern> = resource_patterns
            .iter()
            .map(|s| ResourcePattern::new(s).context("invalid resource pattern"))
            .collect::<Result<_>>()?;

        let vault = self.state.vault.lock().map_err(|e| anyhow::anyhow!("vault lock poisoned: {e}"))?;
        let id = vault
            .add(name, st, value, bound_to)
            .context("failed to add vault entry")?;

        Ok(id.to_string())
    }

    /// List all vault entries (metadata only).
    pub fn vault_list(&self) -> Result<Vec<VaultEntryResponse>> {
        let vault = self.state.vault.lock().map_err(|e| anyhow::anyhow!("vault lock poisoned: {e}"))?;
        let entries = vault
            .list()
            .context("failed to list vault entries")?;

        let response: Vec<VaultEntryResponse> = entries
            .iter()
            .map(|e| VaultEntryResponse {
                id: e.id.to_string(),
                name: e.name.clone(),
                secret_type: format!("{:?}", e.secret_type),
                revoked: e.revoked,
                created_at: e.created_at.to_rfc3339(),
            })
            .collect();

        Ok(response)
    }

    /// Rotate a vault credential to a new value.
    pub fn vault_rotate(&self, entry_id: &str, new_value: &str) -> Result<()> {
        let uuid = uuid::Uuid::parse_str(entry_id)
            .map(mc_core::id::VaultEntryId::from_uuid)
            .context("invalid vault entry ID")?;

        let vault = self.state.vault.lock().map_err(|e| anyhow::anyhow!("vault lock poisoned: {e}"))?;
        vault
            .rotate(&uuid, new_value)
            .context("failed to rotate vault entry")
    }

    /// Revoke a vault credential.
    pub fn vault_revoke(&self, entry_id: &str) -> Result<()> {
        let uuid = uuid::Uuid::parse_str(entry_id)
            .map(mc_core::id::VaultEntryId::from_uuid)
            .context("invalid vault entry ID")?;

        let vault = self.state.vault.lock().map_err(|e| anyhow::anyhow!("vault lock poisoned: {e}"))?;
        vault
            .revoke(&uuid)
            .context("failed to revoke vault entry")
    }

    // ---- Operations ----

    /// Submit an operation request for evaluation.
    pub fn submit_operation(
        &self,
        mission_token: &str,
        resource: &str,
        operation: &str,
        justification: &str,
    ) -> Result<OperationDecisionResponse> {
        // Parse the mission token.
        let token_uuid = uuid::Uuid::parse_str(mission_token)
            .context("invalid mission token")?;
        let token = MissionToken::from_uuid(token_uuid);

        // Parse operation and resource.
        let op = parse_operation(operation)?;
        let resource_uri = ResourceUri::new(resource)
            .context("invalid resource URI")?;

        // Resolve the token and check the mission.
        let mgr = self.state.mission_manager.lock().map_err(|e| anyhow::anyhow!("mission manager lock poisoned: {e}"))?;
        let mission_id = mgr
            .resolve_token(&token)
            .context("unknown mission token")?;

        let mission = mgr
            .get(&mission_id)
            .context("mission not found")?;

        if !mission.is_active() {
            anyhow::bail!("mission is not active");
        }

        // Check capabilities.
        let has_capability = mc_kernel::checker::CapabilityChecker::check(
            &mgr,
            &mission_id,
            &resource_uri,
            &op,
        );

        let request_id = RequestId::new();

        if has_capability.is_none() {
            // Log denied event.
            if let Ok(log) = self.state.event_log.lock() {
                if let Err(e) = log.append(
                    mission_id,
                    TraceEventType::OperationDenied,
                    None,
                    serde_json::json!({
                        "resource": resource,
                        "operation": operation,
                        "reason": "no matching capability"
                    }),
                ) {
                    tracing::error!("Failed to append trace event: {e}");
                }
            }

            return Ok(OperationDecisionResponse {
                decision: "denied".to_string(),
                reasoning: "No matching capability for this resource and operation".to_string(),
                request_id: request_id.to_string(),
            });
        }

        // Build the OperationRequest for policy evaluation.
        let op_request = OperationRequest {
            id: request_id,
            mission_id,
            resource: resource_uri,
            operation: op,
            context: OperationContext::ToolCall {
                tool_name: "sdk-request".to_string(),
                arguments: serde_json::json!({}),
            },
            justification: justification.to_string(),
            chain: vec![],
            timestamp: chrono::Utc::now(),
        };

        // Classify the operation.
        let mut classification = mc_kernel::classifier::OperationClassifier::classify(&op_request);

        // Enrich signals (e.g. analyze inline code for benign/dangerous patterns).
        self.signal_enricher.enrich(&op_request, &mut classification);

        // Build evaluation context.
        let eval_context = EvaluationContext {
            mission_goal: mission.goal.clone(),
            mission_chain: vec![],
            recent_operations: vec![],
            anomaly_history: vec![],
            executes_session_written_file: false,
            principal_chain: vec![],
            effective_trust_level: None,
            chain_anomaly_flags: vec![],
        };

        // Drop the manager lock before policy evaluation.
        drop(mgr);

        // Run through the policy pipeline with trace for feedback loop.
        let pipeline_result = self
            .state
            .policy_pipeline
            .evaluate_with_trace(&op_request, &classification, &eval_context);

        // Trigger feedback loop if there's a disagreement.
        #[cfg(feature = "feedback-loop")]
        if let Some(ref feedback) = self.feedback_loop {
            feedback.check_and_learn(&pipeline_result.trace, &op_request, &classification);
        }

        let decision = pipeline_result.decision;

        // Log the result.
        let event_type = match decision.kind {
            PolicyDecisionKind::Allow => TraceEventType::OperationAllowed,
            PolicyDecisionKind::Deny => TraceEventType::OperationDenied,
            PolicyDecisionKind::Escalate => TraceEventType::OperationEscalated,
        };

        if let Ok(log) = self.state.event_log.lock() {
            if let Err(e) = log.append(
                mission_id,
                event_type,
                None,
                serde_json::json!({
                    "resource": op_request.resource.as_str(),
                    "operation": format!("{:?}", op_request.operation),
                    "decision": format!("{:?}", decision.kind),
                    "reasoning": &decision.reasoning,
                }),
            ) {
                tracing::error!("Failed to append trace event: {e}");
            }
        }

        let decision_str = match decision.kind {
            PolicyDecisionKind::Allow => "allowed",
            PolicyDecisionKind::Deny => "denied",
            PolicyDecisionKind::Escalate => "escalated",
        };

        Ok(OperationDecisionResponse {
            decision: decision_str.to_string(),
            reasoning: decision.reasoning,
            request_id: request_id.to_string(),
        })
    }

    /// Submit an operation request with an explicit `OperationContext`.
    ///
    /// This variant allows callers to specify Shell, Http, or Database context
    /// so the classifier can produce appropriate risk classifications.
    pub fn submit_operation_with_context(
        &self,
        mission_token: &str,
        resource: &str,
        operation: &str,
        justification: &str,
        context: OperationContext,
    ) -> Result<OperationDecisionResponse> {
        let token_uuid = uuid::Uuid::parse_str(mission_token)
            .context("invalid mission token")?;
        let token = MissionToken::from_uuid(token_uuid);

        let op = parse_operation(operation)?;
        let resource_uri = ResourceUri::new(resource)
            .context("invalid resource URI")?;

        let mgr = self.state.mission_manager.lock().map_err(|e| anyhow::anyhow!("mission manager lock poisoned: {e}"))?;
        let mission_id = mgr
            .resolve_token(&token)
            .context("unknown mission token")?;

        let mission = mgr
            .get(&mission_id)
            .context("mission not found")?;

        if !mission.is_active() {
            anyhow::bail!("mission is not active");
        }

        let has_capability = mc_kernel::checker::CapabilityChecker::check(
            &mgr,
            &mission_id,
            &resource_uri,
            &op,
        );

        let request_id = RequestId::new();

        if has_capability.is_none() {
            return Ok(OperationDecisionResponse {
                decision: "denied".to_string(),
                reasoning: "No matching capability for this resource and operation".to_string(),
                request_id: request_id.to_string(),
            });
        }

        let op_request = OperationRequest {
            id: request_id,
            mission_id,
            resource: resource_uri,
            operation: op,
            context,
            justification: justification.to_string(),
            chain: vec![],
            timestamp: chrono::Utc::now(),
        };

        let mut classification = mc_kernel::classifier::OperationClassifier::classify(&op_request);
        self.signal_enricher.enrich(&op_request, &mut classification);

        let eval_context = EvaluationContext {
            mission_goal: mission.goal.clone(),
            mission_chain: vec![],
            recent_operations: vec![],
            anomaly_history: vec![],
            executes_session_written_file: false,
            principal_chain: vec![],
            effective_trust_level: None,
            chain_anomaly_flags: vec![],
        };

        drop(mgr);

        let pipeline_result = self
            .state
            .policy_pipeline
            .evaluate_with_trace(&op_request, &classification, &eval_context);

        // Trigger feedback loop if there's a disagreement.
        #[cfg(feature = "feedback-loop")]
        if let Some(ref feedback) = self.feedback_loop {
            feedback.check_and_learn(&pipeline_result.trace, &op_request, &classification);
        }

        let decision = pipeline_result.decision;

        let decision_str = match decision.kind {
            PolicyDecisionKind::Allow => "allowed",
            PolicyDecisionKind::Deny => "denied",
            PolicyDecisionKind::Escalate => "escalated",
        };

        Ok(OperationDecisionResponse {
            decision: decision_str.to_string(),
            reasoning: decision.reasoning,
            request_id: request_id.to_string(),
        })
    }
}

// ---- Helpers ----

fn parse_operation(s: &str) -> Result<Operation> {
    match s {
        "Read" => Ok(Operation::Read),
        "Write" => Ok(Operation::Write),
        "Execute" => Ok(Operation::Execute),
        "Delete" => Ok(Operation::Delete),
        "Connect" => Ok(Operation::Connect),
        "Delegate" => Ok(Operation::Delegate),
        other => anyhow::bail!("unknown operation: {other}"),
    }
}

fn parse_secret_type(s: &str) -> Result<SecretType> {
    match s {
        "ApiKey" => Ok(SecretType::ApiKey),
        "BearerToken" => Ok(SecretType::BearerToken),
        "Certificate" => Ok(SecretType::Certificate),
        "ConnectionString" => Ok(SecretType::ConnectionString),
        "Password" => Ok(SecretType::Password),
        "SshKey" => Ok(SecretType::SshKey),
        "Custom" => Ok(SecretType::Custom),
        other => anyhow::bail!("unknown secret type: {other}"),
    }
}

fn spec_to_capability(spec: &CapabilitySpec) -> Result<Capability> {
    let resource_pattern = ResourcePattern::new(&spec.resource_pattern)
        .context("invalid resource pattern")?;

    let operations = spec
        .operations
        .iter()
        .map(|s| parse_operation(s))
        .collect::<Result<_>>()?;

    Ok(Capability {
        id: CapabilityId::new(),
        resource_pattern,
        operations,
        constraints: Constraints::default(),
        delegatable: spec.delegatable,
    })
}

fn parse_policy_ids(policies: &[String]) -> Result<Vec<mc_core::id::PolicyId>> {
    policies
        .iter()
        .map(|s| {
            uuid::Uuid::parse_str(s)
                .map(mc_core::id::PolicyId::from_uuid)
                .context("invalid policy ID")
        })
        .collect()
}

fn mission_to_response(m: &mc_core::mission::Mission) -> MissionResponse {
    MissionResponse {
        id: m.id.to_string(),
        token: m.token.to_string(),
        goal: m.goal.clone(),
        status: format!("{:?}", m.status),
        parent: m.parent.map(|p| p.to_string()),
        depth: m.depth,
        created_at: m.created_at.to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel() -> EmbeddedKernel {
        EmbeddedKernel::new(10, "test-passphrase").expect("failed to create embedded kernel")
    }

    #[test]
    fn test_embedded_create_mission() {
        let k = kernel();
        let resp = k
            .create_mission("deploy service", vec![], vec![])
            .unwrap();

        assert_eq!(resp.goal, "deploy service");
        assert_eq!(resp.depth, 0);
        assert!(resp.parent.is_none());
        assert_eq!(resp.status, "Active");
        assert!(!resp.id.is_empty());
        assert!(!resp.token.is_empty());
    }

    #[test]
    fn test_embedded_get_mission() {
        let k = kernel();
        let created = k
            .create_mission("test-get", vec![], vec![])
            .unwrap();

        let fetched = k.get_mission(&created.id).unwrap();
        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.goal, "test-get");
    }

    #[test]
    fn test_embedded_delegate_mission() {
        let k = kernel();
        let cap = CapabilitySpec {
            resource_pattern: "http://api.com/**".to_string(),
            operations: vec!["Read".to_string(), "Write".to_string()],
            delegatable: true,
        };
        let parent = k
            .create_mission("parent-task", vec![cap], vec![])
            .unwrap();

        let child_cap = CapabilitySpec {
            resource_pattern: "http://api.com/repos/*".to_string(),
            operations: vec!["Read".to_string()],
            delegatable: false,
        };
        let child = k
            .delegate_mission(&parent.id, "child-task", vec![child_cap], vec![])
            .unwrap();

        assert_eq!(child.goal, "child-task");
        assert_eq!(child.parent.as_deref(), Some(parent.id.as_str()));
        assert_eq!(child.depth, 1);
    }

    #[test]
    fn test_embedded_revoke_cascades() {
        let k = kernel();
        let cap = CapabilitySpec {
            resource_pattern: "http://api.com/**".to_string(),
            operations: vec!["Read".to_string()],
            delegatable: true,
        };
        let root = k
            .create_mission("root", vec![cap], vec![])
            .unwrap();

        let child_cap = CapabilitySpec {
            resource_pattern: "http://api.com/repos/*".to_string(),
            operations: vec!["Read".to_string()],
            delegatable: true,
        };
        let child = k
            .delegate_mission(&root.id, "child", vec![child_cap], vec![])
            .unwrap();

        let grandchild_cap = CapabilitySpec {
            resource_pattern: "http://api.com/repos/foo".to_string(),
            operations: vec!["Read".to_string()],
            delegatable: false,
        };
        let _grandchild = k
            .delegate_mission(&child.id, "grandchild", vec![grandchild_cap], vec![])
            .unwrap();

        let revoked = k.revoke_mission(&root.id).unwrap();
        assert_eq!(revoked.len(), 3);
        assert!(revoked.contains(&root.id));
        assert!(revoked.contains(&child.id));
    }

    #[test]
    fn test_embedded_vault_add_and_list() {
        let k = kernel();

        let id = k
            .vault_add(
                "test-secret",
                "ApiKey",
                "sk-test-123",
                vec!["http://api.example.com/**".to_string()],
            )
            .unwrap();

        assert!(!id.is_empty());

        let entries = k.vault_list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "test-secret");
        assert_eq!(entries[0].secret_type, "ApiKey");
        assert!(!entries[0].revoked);
    }

    #[test]
    fn test_embedded_submit_operation_allowed() {
        let k = kernel();
        let cap = CapabilitySpec {
            resource_pattern: "http://api.com/**".to_string(),
            operations: vec!["Read".to_string()],
            delegatable: false,
        };
        let mission = k
            .create_mission("op-test", vec![cap], vec![])
            .unwrap();

        let result = k
            .submit_operation(
                &mission.token,
                "http://api.com/repos/foo",
                "Read",
                "test read operation",
            )
            .unwrap();

        assert_eq!(result.decision, "allowed");
        assert!(!result.request_id.is_empty());
    }

    #[test]
    fn test_embedded_submit_operation_denied() {
        let k = kernel();

        // Mission with no capabilities.
        let mission = k
            .create_mission("no-caps", vec![], vec![])
            .unwrap();

        let result = k
            .submit_operation(
                &mission.token,
                "http://api.com/repos/foo",
                "Read",
                "should be denied",
            )
            .unwrap();

        assert_eq!(result.decision, "denied");
        assert!(result.reasoning.contains("No matching capability"));
    }

    #[test]
    fn test_embedded_full_flow() {
        let k = kernel();

        // Step 1: Create a mission with capabilities.
        let cap = CapabilitySpec {
            resource_pattern: "http://api.com/**".to_string(),
            operations: vec!["Read".to_string(), "Write".to_string()],
            delegatable: true,
        };
        let mission = k
            .create_mission("full-flow", vec![cap], vec![])
            .unwrap();

        // Step 2: Add a vault entry.
        let vault_id = k
            .vault_add(
                "flow-secret",
                "ApiKey",
                "sk-flow-123",
                vec!["http://api.com/**".to_string()],
            )
            .unwrap();
        assert!(!vault_id.is_empty());

        // Step 3: Submit an operation -- should be allowed.
        let result = k
            .submit_operation(
                &mission.token,
                "http://api.com/repos/myrepo",
                "Read",
                "read repo data",
            )
            .unwrap();
        assert_eq!(result.decision, "allowed");

        // Step 4: Verify vault entry is listed.
        let entries = k.vault_list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "flow-secret");
    }

    #[test]
    fn test_embedded_operation_wrong_operation_type() {
        let k = kernel();
        let cap = CapabilitySpec {
            resource_pattern: "http://api.com/**".to_string(),
            operations: vec!["Read".to_string()],
            delegatable: false,
        };
        let mission = k
            .create_mission("read-only", vec![cap], vec![])
            .unwrap();

        // Try to Write -- should be denied (no Write capability).
        let result = k
            .submit_operation(
                &mission.token,
                "http://api.com/repos/foo",
                "Write",
                "attempt to write",
            )
            .unwrap();

        assert_eq!(result.decision, "denied");
    }

    #[test]
    fn test_embedded_operation_wrong_resource() {
        let k = kernel();
        let cap = CapabilitySpec {
            resource_pattern: "http://api.com/repos/*".to_string(),
            operations: vec!["Read".to_string()],
            delegatable: false,
        };
        let mission = k
            .create_mission("scoped", vec![cap], vec![])
            .unwrap();

        // Resource outside the capability scope.
        let result = k
            .submit_operation(
                &mission.token,
                "http://api.com/users/bar",
                "Read",
                "attempt to read users",
            )
            .unwrap();

        assert_eq!(result.decision, "denied");
    }

    #[test]
    fn test_embedded_delegate_depth_limit() {
        let k = EmbeddedKernel::new(1, "test-passphrase").unwrap();
        let cap = CapabilitySpec {
            resource_pattern: "http://api.com/**".to_string(),
            operations: vec!["Read".to_string()],
            delegatable: true,
        };
        let root = k
            .create_mission("root", vec![cap], vec![])
            .unwrap();

        let child_cap = CapabilitySpec {
            resource_pattern: "http://api.com/repos/*".to_string(),
            operations: vec!["Read".to_string()],
            delegatable: true,
        };
        let child = k
            .delegate_mission(&root.id, "child", vec![child_cap], vec![])
            .unwrap();

        // This should fail -- depth 2 exceeds max of 1.
        let grandchild_cap = CapabilitySpec {
            resource_pattern: "http://api.com/repos/foo".to_string(),
            operations: vec!["Read".to_string()],
            delegatable: false,
        };
        let result = k.delegate_mission(&child.id, "grandchild", vec![grandchild_cap], vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_embedded_vault_multiple_entries() {
        let k = kernel();

        k.vault_add(
            "secret-a",
            "ApiKey",
            "val-a",
            vec!["http://api.com/**".to_string()],
        )
        .unwrap();

        k.vault_add(
            "secret-b",
            "BearerToken",
            "val-b",
            vec!["http://github.com/**".to_string()],
        )
        .unwrap();

        let entries = k.vault_list().unwrap();
        assert_eq!(entries.len(), 2);

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"secret-a"));
        assert!(names.contains(&"secret-b"));
    }
}
