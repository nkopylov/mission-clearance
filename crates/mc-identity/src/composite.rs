use async_trait::async_trait;
use mc_core::principal::Principal;
use tracing::debug;

use crate::provider::{AuthCredential, IdentityError, IdentityProvider};

/// Composite identity provider that tries each provider in order.
///
/// Returns the first successful `Some` result from any provider.
pub struct CompositeIdentityProvider {
    providers: Vec<Box<dyn IdentityProvider>>,
}

impl CompositeIdentityProvider {
    /// Create a new empty composite provider.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Add a provider to the chain.
    pub fn add_provider(&mut self, provider: Box<dyn IdentityProvider>) {
        self.providers.push(provider);
    }
}

impl Default for CompositeIdentityProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdentityProvider for CompositeIdentityProvider {
    async fn resolve(
        &self,
        credential: &AuthCredential,
    ) -> Result<Option<Principal>, IdentityError> {
        let mut last_error: Option<IdentityError> = None;

        for provider in &self.providers {
            match provider.resolve(credential).await {
                Ok(Some(principal)) => {
                    debug!(provider = provider.name(), "resolved principal");
                    return Ok(Some(principal));
                }
                Ok(None) => continue,
                Err(e) => {
                    debug!(
                        provider = provider.name(),
                        error = %e,
                        "provider returned error, trying next"
                    );
                    last_error = Some(e);
                }
            }
        }

        // If all providers returned None or errors, return None.
        // If there was at least one error and no None successes, propagate the last error.
        // But per spec, we return Ok(None) if no provider claimed the credential.
        match last_error {
            Some(_) => Ok(None),
            None => Ok(None),
        }
    }

    async fn validate(&self, principal: &Principal) -> Result<bool, IdentityError> {
        for provider in &self.providers {
            match provider.validate(principal).await {
                Ok(valid) => return Ok(valid),
                Err(_) => continue,
            }
        }

        // No provider could validate -- treat as invalid.
        Ok(false)
    }

    fn name(&self) -> &str {
        "composite"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_key::ApiKeyProvider;
    use crate::mission_token::MissionTokenProvider;
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
                purpose: "CI/CD".to_string(),
                owner: owner_id,
            },
            org_position: None,
            teams: vec![],
        }
    }

    #[tokio::test]
    async fn test_composite_resolve_through_api_key() {
        let mut api_key_provider = ApiKeyProvider::new();
        let principal = test_service_account();
        let principal_id = principal.id;
        api_key_provider.register_key("sk-composite-test".to_string(), principal);

        let mut composite = CompositeIdentityProvider::new();
        composite.add_provider(Box::new(MissionTokenProvider::new()));
        composite.add_provider(Box::new(api_key_provider));

        let cred = AuthCredential::ApiKey("sk-composite-test".to_string());
        let result = composite.resolve(&cred).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, principal_id);
    }

    #[tokio::test]
    async fn test_composite_resolve_no_match_returns_none() {
        let mut composite = CompositeIdentityProvider::new();
        composite.add_provider(Box::new(ApiKeyProvider::new()));
        composite.add_provider(Box::new(MissionTokenProvider::new()));

        let cred = AuthCredential::ApiKey("sk-unknown".to_string());
        let result = composite.resolve(&cred).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_composite_empty_returns_none() {
        let composite = CompositeIdentityProvider::new();
        let cred = AuthCredential::BearerToken("jwt".to_string());
        let result = composite.resolve(&cred).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_composite_validate_delegates() {
        let mut composite = CompositeIdentityProvider::new();
        composite.add_provider(Box::new(ApiKeyProvider::new()));

        let principal = test_service_account();
        let result = composite.validate(&principal).await.unwrap();
        assert!(result); // ApiKeyProvider checks is_active(), which is true
    }

    #[tokio::test]
    async fn test_composite_validate_empty_returns_false() {
        let composite = CompositeIdentityProvider::new();
        let principal = test_service_account();
        let result = composite.validate(&principal).await.unwrap();
        assert!(!result);
    }
}
