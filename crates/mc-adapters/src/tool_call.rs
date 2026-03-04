//! Tool Call adapter -- intercepts structured LLM tool/function calls.
//!
//! Expects JSON requests of the form:
//! ```json
//! {
//!     "mission_token": "uuid-string",
//!     "tool": "tool_name",
//!     "arguments": { ... },
//!     "justification": "why I need to call this tool"
//! }
//! ```

use anyhow::{Context, Result};
use async_trait::async_trait;
use mc_core::id::{MissionToken, RequestId};
use mc_core::operation::{Operation, OperationContext, OperationRequest};
use mc_core::policy::PolicyDecision;
use mc_core::resource::ResourceUri;
use mc_core::vault::Credential;
use uuid::Uuid;

use crate::{ProtocolAdapter, RawRequest, RawResponse};

/// Adapter for structured LLM tool/function calls.
pub struct ToolCallAdapter;

impl ToolCallAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ToolCallAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the raw request data as JSON.
fn parse_request(raw: &RawRequest) -> Result<serde_json::Value> {
    let body: serde_json::Value =
        serde_json::from_slice(&raw.data).context("failed to parse tool call request as JSON")?;
    Ok(body)
}

#[async_trait]
impl ProtocolAdapter for ToolCallAdapter {
    fn name(&self) -> &str {
        "tool_call"
    }

    async fn identify_mission(&self, raw: &RawRequest) -> Result<MissionToken> {
        // Try metadata first, then the body
        let token_string = if let Some(s) = raw.metadata.get("mission_token").and_then(|v| v.as_str()) {
            s.to_string()
        } else {
            let body: serde_json::Value = serde_json::from_slice(&raw.data)
                .context("failed to parse tool call request body")?;
            body.get("mission_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow::anyhow!("missing mission_token in tool call request"))?
        };

        let uuid = Uuid::parse_str(&token_string).context("invalid mission_token UUID")?;
        Ok(MissionToken::from_uuid(uuid))
    }

    async fn normalize(&self, raw: &RawRequest) -> Result<OperationRequest> {
        let body = parse_request(raw)?;

        let tool_name = body
            .get("tool")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'tool' field"))?
            .to_string();

        let arguments = body
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        let justification = body
            .get("justification")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mission_token = self.identify_mission(raw).await?;

        let resource_uri = ResourceUri::new(&format!("tool://{tool_name}"))
            .context("failed to construct resource URI")?;

        Ok(OperationRequest {
            id: RequestId::new(),
            mission_id: mc_core::id::MissionId::from_uuid(*mission_token.as_uuid()),
            resource: resource_uri,
            operation: Operation::Execute,
            context: OperationContext::ToolCall {
                tool_name,
                arguments,
            },
            justification,
            chain: vec![],
            timestamp: chrono::Utc::now(),
        })
    }

    async fn inject_credentials(
        &self,
        raw: &mut RawRequest,
        creds: &[Credential],
    ) -> Result<()> {
        // Parse the body, inject credentials into arguments under parameter names
        let mut body: serde_json::Value = serde_json::from_slice(&raw.data)
            .context("failed to parse tool call request for credential injection")?;

        let arguments = body
            .get_mut("arguments")
            .and_then(|v| v.as_object_mut())
            .ok_or_else(|| anyhow::anyhow!("missing 'arguments' object"))?;

        for cred in creds {
            // Use the credential name based on secret type or a default parameter name
            let param_name = match cred.secret_type {
                mc_core::vault::SecretType::ApiKey => "api_key",
                mc_core::vault::SecretType::BearerToken => "bearer_token",
                mc_core::vault::SecretType::Password => "password",
                mc_core::vault::SecretType::ConnectionString => "connection_string",
                _ => "credential",
            };
            arguments.insert(
                param_name.to_string(),
                serde_json::Value::String(cred.value.clone()),
            );
        }

        raw.data = serde_json::to_vec(&body)?;
        Ok(())
    }

    async fn forward(&self, raw: RawRequest) -> Result<RawResponse> {
        // Tool execution happens outside the adapter -- return the request as-is.
        Ok(RawResponse {
            data: raw.data,
            metadata: raw.metadata,
        })
    }

    fn deny(&self, reason: &PolicyDecision) -> RawResponse {
        let body = serde_json::json!({
            "error": "denied",
            "reason": reason.reasoning,
        });
        RawResponse {
            data: serde_json::to_vec(&body).unwrap_or_default(),
            metadata: serde_json::json!({}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_core::id::{PolicyId, VaultEntryId};
    use mc_core::policy::{PolicyDecisionKind, PolicyEvaluatorType};
    use mc_core::vault::SecretType;

    fn make_tool_call_request(token: &str, tool: &str, args: serde_json::Value) -> RawRequest {
        let body = serde_json::json!({
            "mission_token": token,
            "tool": tool,
            "arguments": args,
            "justification": "need to perform this action"
        });
        RawRequest {
            data: serde_json::to_vec(&body).unwrap(),
            metadata: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn normalize_tool_call() {
        let adapter = ToolCallAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = make_tool_call_request(
            &token,
            "search_files",
            serde_json::json!({"pattern": "*.rs"}),
        );

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "tool://search_files");
        assert_eq!(op.operation, Operation::Execute);
        match &op.context {
            OperationContext::ToolCall {
                tool_name,
                arguments,
            } => {
                assert_eq!(tool_name, "search_files");
                assert_eq!(arguments["pattern"], "*.rs");
            }
            _ => panic!("expected ToolCall context"),
        }
    }

    #[tokio::test]
    async fn identify_mission_token_from_body() {
        let adapter = ToolCallAdapter::new();
        let uuid = Uuid::new_v4();
        let raw = make_tool_call_request(&uuid.to_string(), "some_tool", serde_json::json!({}));

        let token = adapter.identify_mission(&raw).await.unwrap();
        assert_eq!(*token.as_uuid(), uuid);
    }

    #[tokio::test]
    async fn identify_mission_token_from_metadata() {
        let adapter = ToolCallAdapter::new();
        let uuid = Uuid::new_v4();
        let raw = RawRequest {
            data: serde_json::to_vec(&serde_json::json!({
                "tool": "test",
                "arguments": {},
            }))
            .unwrap(),
            metadata: serde_json::json!({
                "mission_token": uuid.to_string(),
            }),
        };

        let token = adapter.identify_mission(&raw).await.unwrap();
        assert_eq!(*token.as_uuid(), uuid);
    }

    #[tokio::test]
    async fn identify_mission_missing_token() {
        let adapter = ToolCallAdapter::new();
        let raw = RawRequest {
            data: serde_json::to_vec(&serde_json::json!({
                "tool": "test",
                "arguments": {},
            }))
            .unwrap(),
            metadata: serde_json::json!({}),
        };

        let result = adapter.identify_mission(&raw).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn inject_credentials_tool_call() {
        let adapter = ToolCallAdapter::new();
        let token = Uuid::new_v4().to_string();
        let mut raw = make_tool_call_request(
            &token,
            "call_api",
            serde_json::json!({"url": "https://example.com"}),
        );

        let cred = Credential {
            entry_id: VaultEntryId::new(),
            secret_type: SecretType::ApiKey,
            value: "sk-secret-123".to_string(),
        };

        adapter
            .inject_credentials(&mut raw, &[cred])
            .await
            .unwrap();

        let body: serde_json::Value = serde_json::from_slice(&raw.data).unwrap();
        assert_eq!(body["arguments"]["api_key"], "sk-secret-123");
        // Original argument preserved
        assert_eq!(body["arguments"]["url"], "https://example.com");
    }

    #[tokio::test]
    async fn inject_multiple_credentials() {
        let adapter = ToolCallAdapter::new();
        let token = Uuid::new_v4().to_string();
        let mut raw = make_tool_call_request(&token, "call_api", serde_json::json!({}));

        let creds = vec![
            Credential {
                entry_id: VaultEntryId::new(),
                secret_type: SecretType::ApiKey,
                value: "key-123".to_string(),
            },
            Credential {
                entry_id: VaultEntryId::new(),
                secret_type: SecretType::Password,
                value: "pass-456".to_string(),
            },
        ];

        adapter
            .inject_credentials(&mut raw, &creds)
            .await
            .unwrap();

        let body: serde_json::Value = serde_json::from_slice(&raw.data).unwrap();
        assert_eq!(body["arguments"]["api_key"], "key-123");
        assert_eq!(body["arguments"]["password"], "pass-456");
    }

    #[tokio::test]
    async fn deny_response() {
        let adapter = ToolCallAdapter::new();
        let decision = PolicyDecision {
            policy_id: PolicyId::new(),
            kind: PolicyDecisionKind::Deny,
            reasoning: "tool not allowed in this mission".to_string(),
            evaluator: PolicyEvaluatorType::Deterministic,
        };

        let resp = adapter.deny(&decision);
        let body: serde_json::Value = serde_json::from_slice(&resp.data).unwrap();
        assert_eq!(body["error"], "denied");
        assert_eq!(body["reason"], "tool not allowed in this mission");
    }

    #[tokio::test]
    async fn forward_returns_request_as_is() {
        let adapter = ToolCallAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = make_tool_call_request(&token, "test_tool", serde_json::json!({"x": 1}));
        let original_data = raw.data.clone();

        let resp = adapter.forward(raw).await.unwrap();
        assert_eq!(resp.data, original_data);
    }

    #[test]
    fn adapter_name() {
        let adapter = ToolCallAdapter::new();
        assert_eq!(adapter.name(), "tool_call");
    }

    #[tokio::test]
    async fn normalize_without_justification() {
        let adapter = ToolCallAdapter::new();
        let token = Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "mission_token": token,
            "tool": "read_file",
            "arguments": {"path": "/etc/hosts"},
        });
        let raw = RawRequest {
            data: serde_json::to_vec(&body).unwrap(),
            metadata: serde_json::json!({}),
        };

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.justification, "");
    }

    #[tokio::test]
    async fn normalize_without_arguments() {
        let adapter = ToolCallAdapter::new();
        let token = Uuid::new_v4().to_string();
        let body = serde_json::json!({
            "mission_token": token,
            "tool": "list_files",
        });
        let raw = RawRequest {
            data: serde_json::to_vec(&body).unwrap(),
            metadata: serde_json::json!({}),
        };

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "tool://list_files");
        match &op.context {
            OperationContext::ToolCall { arguments, .. } => {
                assert!(arguments.is_object());
            }
            _ => panic!("expected ToolCall context"),
        }
    }
}
