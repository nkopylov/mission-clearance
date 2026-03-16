use async_trait::async_trait;
use mc_core::principal::Principal;

use crate::provider::{AuthCredential, IdentityError, IdentityProvider};

/// Identity provider that resolves mission tokens to AI agent principals.
///
/// Currently a stub -- will be wired to MissionManager in a future phase.
pub struct MissionTokenProvider;

impl MissionTokenProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MissionTokenProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdentityProvider for MissionTokenProvider {
    async fn resolve(
        &self,
        credential: &AuthCredential,
    ) -> Result<Option<Principal>, IdentityError> {
        match credential {
            AuthCredential::MissionToken(_) => {
                // Will be wired to MissionManager in a future phase.
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    async fn validate(&self, _principal: &Principal) -> Result<bool, IdentityError> {
        // Mission tokens are validated elsewhere (by the mission lifecycle).
        Ok(true)
    }

    fn name(&self) -> &str {
        "mission_token"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_core::id::PrincipalId;
    use mc_core::principal::{
        PrincipalDetails, PrincipalKind, PrincipalStatus, PrincipalTrustLevel,
    };

    fn test_agent() -> Principal {
        Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::AiAgent,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::Agent,
            display_name: "test-agent".to_string(),
            details: PrincipalDetails::AiAgent {
                model: "claude-4".to_string(),
                spawned_by: None,
                spawning_mission: None,
            },
            org_position: None,
            teams: vec![],
        }
    }

    #[tokio::test]
    async fn test_resolve_mission_token_returns_none() {
        let provider = MissionTokenProvider::new();
        let cred = AuthCredential::MissionToken("mt-abc".to_string());
        let result = provider.resolve(&cred).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_resolve_non_mission_token_returns_none() {
        let provider = MissionTokenProvider::new();
        let cred = AuthCredential::ApiKey("key-123".to_string());
        let result = provider.resolve(&cred).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_validate_always_true() {
        let provider = MissionTokenProvider::new();
        let principal = test_agent();
        let result = provider.validate(&principal).await.unwrap();
        assert!(result);
    }
}
