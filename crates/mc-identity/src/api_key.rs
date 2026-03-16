use async_trait::async_trait;
use mc_core::principal::Principal;
use std::collections::HashMap;

use crate::provider::{AuthCredential, IdentityError, IdentityProvider};

/// Identity provider that maps static API keys to service account principals.
pub struct ApiKeyProvider {
    keys: HashMap<String, Principal>,
}

impl ApiKeyProvider {
    /// Create a new empty API key provider.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Register a mapping from an API key to a principal.
    pub fn register_key(&mut self, key: String, principal: Principal) {
        self.keys.insert(key, principal);
    }
}

impl Default for ApiKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdentityProvider for ApiKeyProvider {
    async fn resolve(
        &self,
        credential: &AuthCredential,
    ) -> Result<Option<Principal>, IdentityError> {
        match credential {
            AuthCredential::ApiKey(key) => Ok(self.keys.get(key).cloned()),
            _ => Ok(None),
        }
    }

    async fn validate(&self, principal: &Principal) -> Result<bool, IdentityError> {
        Ok(principal.is_active())
    }

    fn name(&self) -> &str {
        "api_key"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_core::id::PrincipalId;
    use mc_core::principal::{
        PrincipalDetails, PrincipalKind, PrincipalStatus, PrincipalTrustLevel,
    };

    fn test_service_account() -> Principal {
        let owner_id = PrincipalId::new();
        Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::ServiceAccount,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::ServiceAccount,
            display_name: "deploy-bot".to_string(),
            details: PrincipalDetails::ServiceAccount {
                purpose: "CI/CD deployments".to_string(),
                owner: owner_id,
            },
            org_position: None,
            teams: vec![],
        }
    }

    #[tokio::test]
    async fn test_register_and_resolve_key() {
        let mut provider = ApiKeyProvider::new();
        let principal = test_service_account();
        let principal_id = principal.id;
        provider.register_key("sk-test-123".to_string(), principal);

        let cred = AuthCredential::ApiKey("sk-test-123".to_string());
        let result = provider.resolve(&cred).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, principal_id);
    }

    #[tokio::test]
    async fn test_resolve_unknown_key_returns_none() {
        let provider = ApiKeyProvider::new();
        let cred = AuthCredential::ApiKey("sk-unknown".to_string());
        let result = provider.resolve(&cred).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_resolve_non_api_key_returns_none() {
        let mut provider = ApiKeyProvider::new();
        provider.register_key("sk-test-123".to_string(), test_service_account());

        let cred = AuthCredential::BearerToken("jwt-token".to_string());
        let result = provider.resolve(&cred).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_validate_active_principal() {
        let provider = ApiKeyProvider::new();
        let principal = test_service_account();
        let result = provider.validate(&principal).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_validate_suspended_principal() {
        let provider = ApiKeyProvider::new();
        let owner_id = PrincipalId::new();
        let principal = Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::ServiceAccount,
            status: PrincipalStatus::Suspended,
            trust_level: PrincipalTrustLevel::ServiceAccount,
            display_name: "suspended-bot".to_string(),
            details: PrincipalDetails::ServiceAccount {
                purpose: "test".to_string(),
                owner: owner_id,
            },
            org_position: None,
            teams: vec![],
        };
        let result = provider.validate(&principal).await.unwrap();
        assert!(!result);
    }
}
