use anyhow::Result;
use async_trait::async_trait;
use mc_core::id::MissionToken;
use mc_core::operation::OperationRequest;
use mc_core::policy::PolicyDecision;
use mc_core::vault::Credential;

pub mod db;
pub mod http;
pub mod shell;
pub mod tool_call;

/// Protocol-specific raw request data.
#[derive(Debug, Clone)]
pub struct RawRequest {
    pub data: Vec<u8>,
    pub metadata: serde_json::Value,
}

/// Protocol-specific raw response data.
#[derive(Debug, Clone)]
pub struct RawResponse {
    pub data: Vec<u8>,
    pub metadata: serde_json::Value,
}

/// Common interface for protocol-specific adapters.
///
/// Each adapter translates protocol-specific interactions into normalized
/// [`OperationRequest`]s that the kernel can evaluate. The adapters do not
/// actually forward requests themselves -- they normalize, classify, inject
/// credentials, and format denial responses. Actual proxy servers (HTTP proxy,
/// DB proxy, shell wrapper) are built separately in mc-api / mc-cli.
#[async_trait]
pub trait ProtocolAdapter: Send + Sync {
    /// Name of this adapter (e.g., "http", "shell", "db", "tool_call").
    fn name(&self) -> &str;

    /// Extract mission token from raw request.
    async fn identify_mission(&self, raw: &RawRequest) -> Result<MissionToken>;

    /// Normalize raw request into a standard OperationRequest.
    async fn normalize(&self, raw: &RawRequest) -> Result<OperationRequest>;

    /// Inject credentials into the raw request (after policy allows).
    async fn inject_credentials(&self, raw: &mut RawRequest, creds: &[Credential]) -> Result<()>;

    /// Forward the (possibly credential-injected) request to the actual destination.
    async fn forward(&self, raw: RawRequest) -> Result<RawResponse>;

    /// Return a denial response to the caller.
    fn deny(&self, reason: &PolicyDecision) -> RawResponse;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_request_clone() {
        let req = RawRequest {
            data: b"hello".to_vec(),
            metadata: serde_json::json!({"key": "value"}),
        };
        let cloned = req.clone();
        assert_eq!(cloned.data, req.data);
        assert_eq!(cloned.metadata, req.metadata);
    }

    #[test]
    fn raw_response_debug() {
        let resp = RawResponse {
            data: b"world".to_vec(),
            metadata: serde_json::json!({}),
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("RawResponse"));
    }
}
