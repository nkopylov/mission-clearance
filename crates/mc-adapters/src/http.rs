//! HTTP proxy adapter -- intercepts HTTP/HTTPS requests.
//!
//! Normalizes HTTP methods to operations:
//! - GET, HEAD, OPTIONS -> Read
//! - POST, PUT, PATCH -> Write
//! - DELETE -> Delete

use std::collections::HashSet;

use anyhow::{Context, Result};
use async_trait::async_trait;
use mc_core::id::{MissionId, MissionToken, RequestId};
use mc_core::operation::{Operation, OperationContext, OperationRequest};
use mc_core::policy::PolicyDecision;
use mc_core::resource::ResourceUri;
use mc_core::vault::Credential;
use uuid::Uuid;

use crate::{ProtocolAdapter, RawRequest, RawResponse};

/// Adapter for HTTP/HTTPS requests.
pub struct HttpProxyAdapter {
    #[allow(dead_code)]
    known_domains: HashSet<String>,
}

impl HttpProxyAdapter {
    pub fn new() -> Self {
        Self {
            known_domains: HashSet::new(),
        }
    }

    pub fn with_known_domains(domains: Vec<String>) -> Self {
        Self {
            known_domains: domains.into_iter().collect(),
        }
    }
}

impl Default for HttpProxyAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Map HTTP method to an Operation.
fn method_to_operation(method: &str) -> Operation {
    match method.to_uppercase().as_str() {
        "GET" | "HEAD" | "OPTIONS" => Operation::Read,
        "POST" | "PUT" | "PATCH" => Operation::Write,
        "DELETE" => Operation::Delete,
        _ => Operation::Execute,
    }
}

/// Extract headers from metadata as Vec<(String, String)>.
fn extract_headers(metadata: &serde_json::Value) -> Vec<(String, String)> {
    metadata
        .get("headers")
        .and_then(|h| h.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect()
        })
        .unwrap_or_default()
}

#[async_trait]
impl ProtocolAdapter for HttpProxyAdapter {
    fn name(&self) -> &str {
        "http"
    }

    async fn identify_mission(&self, raw: &RawRequest) -> Result<MissionToken> {
        // Look for X-Mission-Token header in metadata
        let headers = extract_headers(&raw.metadata);
        let token_str = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("X-Mission-Token"))
            .map(|(_, v)| v.as_str())
            .or_else(|| {
                raw.metadata
                    .get("mission_token")
                    .and_then(|v| v.as_str())
            })
            .ok_or_else(|| anyhow::anyhow!("missing X-Mission-Token header"))?;

        let uuid = Uuid::parse_str(token_str).context("invalid X-Mission-Token UUID")?;
        Ok(MissionToken::from_uuid(uuid))
    }

    async fn normalize(&self, raw: &RawRequest) -> Result<OperationRequest> {
        let method = raw
            .metadata
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_string();

        let url = raw
            .metadata
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing 'url' in HTTP request metadata"))?;

        let headers = extract_headers(&raw.metadata);

        let body_preview = if raw.data.is_empty() {
            None
        } else {
            // Take first 256 bytes as preview
            let preview_len = raw.data.len().min(256);
            Some(String::from_utf8_lossy(&raw.data[..preview_len]).to_string())
        };

        let mission_token = self.identify_mission(raw).await?;

        let resource_uri =
            ResourceUri::new(url).context("failed to construct resource URI from URL")?;

        let operation = method_to_operation(&method);

        Ok(OperationRequest {
            id: RequestId::new(),
            mission_id: MissionId::from_uuid(*mission_token.as_uuid()),
            resource: resource_uri,
            operation,
            context: OperationContext::Http {
                method,
                headers,
                body_preview,
            },
            justification: String::new(),
            chain: vec![],
            timestamp: chrono::Utc::now(),
        })
    }

    async fn inject_credentials(
        &self,
        raw: &mut RawRequest,
        creds: &[Credential],
    ) -> Result<()> {
        // Add credentials as headers in the metadata
        let headers = raw
            .metadata
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("metadata is not an object"))?
            .entry("headers")
            .or_insert_with(|| serde_json::json!({}));

        let headers_obj = headers
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("headers is not an object"))?;

        for cred in creds {
            match cred.secret_type {
                mc_core::vault::SecretType::BearerToken => {
                    headers_obj.insert(
                        "Authorization".to_string(),
                        serde_json::Value::String(format!("Bearer {}", cred.value)),
                    );
                }
                mc_core::vault::SecretType::ApiKey => {
                    headers_obj.insert(
                        "X-API-Key".to_string(),
                        serde_json::Value::String(cred.value.clone()),
                    );
                }
                _ => {
                    headers_obj.insert(
                        "Authorization".to_string(),
                        serde_json::Value::String(cred.value.clone()),
                    );
                }
            }
        }

        Ok(())
    }

    async fn forward(&self, raw: RawRequest) -> Result<RawResponse> {
        // Actual HTTP forwarding happens at the server level.
        Ok(RawResponse {
            data: raw.data,
            metadata: raw.metadata,
        })
    }

    fn deny(&self, reason: &PolicyDecision) -> RawResponse {
        let body = serde_json::json!({
            "status": 403,
            "error": "denied",
            "reason": reason.reasoning,
        });
        RawResponse {
            data: serde_json::to_vec(&body).unwrap_or_default(),
            metadata: serde_json::json!({
                "status_code": 403,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_core::id::{PolicyId, VaultEntryId};
    use mc_core::policy::{PolicyDecisionKind, PolicyEvaluatorType};
    use mc_core::vault::SecretType;

    fn make_http_request(method: &str, url: &str, token: &str) -> RawRequest {
        RawRequest {
            data: vec![],
            metadata: serde_json::json!({
                "method": method,
                "url": url,
                "headers": {
                    "X-Mission-Token": token,
                    "Content-Type": "application/json",
                },
            }),
        }
    }

    #[tokio::test]
    async fn normalize_http_get() {
        let adapter = HttpProxyAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = make_http_request("GET", "http://api.github.com/repos/foo", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.operation, Operation::Read);
        assert_eq!(op.resource.as_str(), "http://api.github.com/repos/foo");
        match &op.context {
            OperationContext::Http { method, .. } => assert_eq!(method, "GET"),
            _ => panic!("expected Http context"),
        }
    }

    #[tokio::test]
    async fn normalize_http_post() {
        let adapter = HttpProxyAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = make_http_request("POST", "http://api.github.com/repos", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.operation, Operation::Write);
    }

    #[tokio::test]
    async fn normalize_http_put() {
        let adapter = HttpProxyAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = make_http_request("PUT", "http://api.github.com/repos/foo", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.operation, Operation::Write);
    }

    #[tokio::test]
    async fn normalize_http_patch() {
        let adapter = HttpProxyAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = make_http_request("PATCH", "http://api.github.com/repos/foo", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.operation, Operation::Write);
    }

    #[tokio::test]
    async fn normalize_http_delete() {
        let adapter = HttpProxyAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = make_http_request("DELETE", "http://api.github.com/repos/foo", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.operation, Operation::Delete);
    }

    #[tokio::test]
    async fn normalize_http_head() {
        let adapter = HttpProxyAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = make_http_request("HEAD", "http://api.github.com/repos/foo", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.operation, Operation::Read);
    }

    #[tokio::test]
    async fn normalize_http_options() {
        let adapter = HttpProxyAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = make_http_request("OPTIONS", "http://api.github.com/repos/foo", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.operation, Operation::Read);
    }

    #[tokio::test]
    async fn identify_mission_from_header() {
        let adapter = HttpProxyAdapter::new();
        let uuid = Uuid::new_v4();
        let raw = make_http_request("GET", "http://example.com/api", &uuid.to_string());

        let token = adapter.identify_mission(&raw).await.unwrap();
        assert_eq!(*token.as_uuid(), uuid);
    }

    #[tokio::test]
    async fn identify_mission_from_metadata_fallback() {
        let adapter = HttpProxyAdapter::new();
        let uuid = Uuid::new_v4();
        let raw = RawRequest {
            data: vec![],
            metadata: serde_json::json!({
                "method": "GET",
                "url": "http://example.com",
                "mission_token": uuid.to_string(),
            }),
        };

        let token = adapter.identify_mission(&raw).await.unwrap();
        assert_eq!(*token.as_uuid(), uuid);
    }

    #[tokio::test]
    async fn identify_mission_missing() {
        let adapter = HttpProxyAdapter::new();
        let raw = RawRequest {
            data: vec![],
            metadata: serde_json::json!({
                "method": "GET",
                "url": "http://example.com",
            }),
        };

        let result = adapter.identify_mission(&raw).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn inject_bearer_token() {
        let adapter = HttpProxyAdapter::new();
        let token = Uuid::new_v4().to_string();
        let mut raw = make_http_request("GET", "http://api.github.com/repos", &token);

        let cred = Credential {
            entry_id: VaultEntryId::new(),
            secret_type: SecretType::BearerToken,
            value: "ghp_token123".to_string(),
        };

        adapter
            .inject_credentials(&mut raw, &[cred])
            .await
            .unwrap();

        let auth = raw.metadata["headers"]["Authorization"]
            .as_str()
            .unwrap();
        assert_eq!(auth, "Bearer ghp_token123");
    }

    #[tokio::test]
    async fn inject_api_key_header() {
        let adapter = HttpProxyAdapter::new();
        let token = Uuid::new_v4().to_string();
        let mut raw = make_http_request("GET", "http://api.example.com/data", &token);

        let cred = Credential {
            entry_id: VaultEntryId::new(),
            secret_type: SecretType::ApiKey,
            value: "api-key-abc".to_string(),
        };

        adapter
            .inject_credentials(&mut raw, &[cred])
            .await
            .unwrap();

        let key = raw.metadata["headers"]["X-API-Key"].as_str().unwrap();
        assert_eq!(key, "api-key-abc");
    }

    #[tokio::test]
    async fn deny_response_403() {
        let adapter = HttpProxyAdapter::new();
        let decision = PolicyDecision {
            policy_id: PolicyId::new(),
            kind: PolicyDecisionKind::Deny,
            reasoning: "request to untrusted domain".to_string(),
            evaluator: PolicyEvaluatorType::Deterministic,
        };

        let resp = adapter.deny(&decision);
        let body: serde_json::Value = serde_json::from_slice(&resp.data).unwrap();
        assert_eq!(body["status"], 403);
        assert_eq!(body["error"], "denied");
        assert_eq!(body["reason"], "request to untrusted domain");
        assert_eq!(resp.metadata["status_code"], 403);
    }

    #[tokio::test]
    async fn normalize_with_body_preview() {
        let adapter = HttpProxyAdapter::new();
        let token = Uuid::new_v4().to_string();
        let mut raw = make_http_request("POST", "http://api.example.com/data", &token);
        raw.data = b"{\"key\": \"value\", \"data\": \"some payload\"}".to_vec();

        let op = adapter.normalize(&raw).await.unwrap();
        match &op.context {
            OperationContext::Http { body_preview, .. } => {
                assert!(body_preview.is_some());
                let preview = body_preview.as_ref().unwrap();
                assert!(preview.contains("key"));
            }
            _ => panic!("expected Http context"),
        }
    }

    #[test]
    fn adapter_name() {
        let adapter = HttpProxyAdapter::new();
        assert_eq!(adapter.name(), "http");
    }

    #[test]
    fn with_known_domains() {
        let adapter =
            HttpProxyAdapter::with_known_domains(vec!["github.com".into(), "gitlab.com".into()]);
        assert!(adapter.known_domains.contains("github.com"));
        assert!(adapter.known_domains.contains("gitlab.com"));
        assert!(!adapter.known_domains.contains("evil.com"));
    }

    #[test]
    fn method_to_op_mapping() {
        assert_eq!(method_to_operation("GET"), Operation::Read);
        assert_eq!(method_to_operation("get"), Operation::Read);
        assert_eq!(method_to_operation("POST"), Operation::Write);
        assert_eq!(method_to_operation("PUT"), Operation::Write);
        assert_eq!(method_to_operation("PATCH"), Operation::Write);
        assert_eq!(method_to_operation("DELETE"), Operation::Delete);
        assert_eq!(method_to_operation("HEAD"), Operation::Read);
        assert_eq!(method_to_operation("OPTIONS"), Operation::Read);
        assert_eq!(method_to_operation("CONNECT"), Operation::Execute);
    }
}
