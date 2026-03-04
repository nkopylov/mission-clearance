use anyhow::{Context, Result};
use mc_api::routes::missions::{CapabilitySpec, MissionResponse};
use mc_api::routes::operations::OperationDecisionResponse;
use mc_api::routes::vault::VaultEntryResponse;

/// HTTP client for the Mission Clearance API.
///
/// Connects to a running `mc-api` server and provides a typed interface
/// for all API operations.
pub struct MissionClearanceClient {
    base_url: String,
    api_key: String,
    client: reqwest::Client,
}

impl MissionClearanceClient {
    /// Create a new client targeting the given server.
    pub fn new(base_url: &str, api_key: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Return the configured base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Return the configured API key.
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    // ---- Mission operations ----

    /// Create a root mission with the given goal, capabilities, and policies.
    pub async fn create_mission(
        &self,
        goal: &str,
        capabilities: Vec<CapabilitySpec>,
        policies: Vec<String>,
    ) -> Result<MissionResponse> {
        let body = serde_json::json!({
            "goal": goal,
            "capabilities": capabilities,
            "policies": policies,
        });

        let resp = self
            .client
            .post(format!("{}/api/v1/missions", self.base_url))
            .header("x-api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .context("failed to send create_mission request")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("create_mission failed ({status}): {text}");
        }

        resp.json::<MissionResponse>()
            .await
            .context("failed to parse create_mission response")
    }

    /// Get a mission by ID.
    pub async fn get_mission(&self, id: &str) -> Result<MissionResponse> {
        let resp = self
            .client
            .get(format!("{}/api/v1/missions/{}", self.base_url, id))
            .header("x-api-key", &self.api_key)
            .send()
            .await
            .context("failed to send get_mission request")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("get_mission failed ({status}): {text}");
        }

        resp.json::<MissionResponse>()
            .await
            .context("failed to parse get_mission response")
    }

    /// Delegate a child mission from a parent.
    pub async fn delegate_mission(
        &self,
        parent_id: &str,
        goal: &str,
        capabilities: Vec<CapabilitySpec>,
        policies: Vec<String>,
    ) -> Result<MissionResponse> {
        let body = serde_json::json!({
            "goal": goal,
            "capabilities": capabilities,
            "policies": policies,
        });

        let resp = self
            .client
            .post(format!(
                "{}/api/v1/missions/{}/delegate",
                self.base_url, parent_id
            ))
            .header("x-api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .context("failed to send delegate_mission request")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("delegate_mission failed ({status}): {text}");
        }

        resp.json::<MissionResponse>()
            .await
            .context("failed to parse delegate_mission response")
    }

    /// Revoke a mission (and all descendants). Returns the list of revoked IDs.
    pub async fn revoke_mission(&self, id: &str) -> Result<Vec<String>> {
        let resp = self
            .client
            .delete(format!("{}/api/v1/missions/{}", self.base_url, id))
            .header("x-api-key", &self.api_key)
            .send()
            .await
            .context("failed to send revoke_mission request")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("revoke_mission failed ({status}): {text}");
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse revoke_mission response")?;

        let revoked = body["revoked"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();

        Ok(revoked)
    }

    // ---- Vault operations ----

    /// Add a credential to the vault.
    pub async fn vault_add(
        &self,
        name: &str,
        secret_type: &str,
        value: &str,
        resource_patterns: Vec<String>,
    ) -> Result<String> {
        let body = serde_json::json!({
            "name": name,
            "secret_type": secret_type,
            "value": value,
            "bound_to": resource_patterns,
        });

        let resp = self
            .client
            .post(format!("{}/api/v1/vault/entries", self.base_url))
            .header("x-api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .context("failed to send vault_add request")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("vault_add failed ({status}): {text}");
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse vault_add response")?;

        body["id"]
            .as_str()
            .map(String::from)
            .context("vault_add response missing 'id'")
    }

    /// List all vault entries (metadata only).
    pub async fn vault_list(&self) -> Result<Vec<VaultEntryResponse>> {
        let resp = self
            .client
            .get(format!("{}/api/v1/vault/entries", self.base_url))
            .header("x-api-key", &self.api_key)
            .send()
            .await
            .context("failed to send vault_list request")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("vault_list failed ({status}): {text}");
        }

        resp.json::<Vec<VaultEntryResponse>>()
            .await
            .context("failed to parse vault_list response")
    }

    // ---- Operation ----

    /// Submit an operation request for evaluation.
    pub async fn submit_operation(
        &self,
        mission_token: &str,
        resource: &str,
        operation: &str,
        justification: &str,
    ) -> Result<OperationDecisionResponse> {
        let body = serde_json::json!({
            "mission_token": mission_token,
            "resource": resource,
            "operation": operation,
            "context": {},
            "justification": justification,
        });

        let resp = self
            .client
            .post(format!("{}/api/v1/operations/request", self.base_url))
            .header("x-api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .context("failed to send submit_operation request")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("submit_operation failed ({status}): {text}");
        }

        resp.json::<OperationDecisionResponse>()
            .await
            .context("failed to parse submit_operation response")
    }

    // ---- Trace ----

    /// Retrieve trace events, optionally filtered by mission ID.
    pub async fn trace_events(
        &self,
        mission_id: Option<&str>,
    ) -> Result<Vec<serde_json::Value>> {
        let mut url = format!("{}/api/v1/trace/events", self.base_url);
        if let Some(mid) = mission_id {
            url.push_str(&format!("?mission={mid}"));
        }

        let resp = self
            .client
            .get(&url)
            .header("x-api-key", &self.api_key)
            .send()
            .await
            .context("failed to send trace_events request")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("trace_events failed ({status}): {text}");
        }

        resp.json::<Vec<serde_json::Value>>()
            .await
            .context("failed to parse trace_events response")
    }

    /// Export the mission graph in the specified format ("dot" or "json").
    pub async fn trace_graph(
        &self,
        mission_id: Option<&str>,
        format: &str,
    ) -> Result<String> {
        let mut params = vec![format!("format={format}")];
        if let Some(mid) = mission_id {
            params.push(format!("mission={mid}"));
        }
        let query = params.join("&");
        let url = format!("{}/api/v1/trace/graph?{}", self.base_url, query);

        let resp = self
            .client
            .get(&url)
            .header("x-api-key", &self.api_key)
            .send()
            .await
            .context("failed to send trace_graph request")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("trace_graph failed ({status}): {text}");
        }

        resp.text()
            .await
            .context("failed to read trace_graph response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_construction() {
        let client = MissionClearanceClient::new("http://localhost:9090", "my-api-key");
        assert_eq!(client.base_url(), "http://localhost:9090");
        assert_eq!(client.api_key(), "my-api-key");
    }

    #[test]
    fn test_client_trailing_slash_stripped() {
        let client = MissionClearanceClient::new("http://localhost:9090/", "key");
        assert_eq!(client.base_url(), "http://localhost:9090");
    }
}
