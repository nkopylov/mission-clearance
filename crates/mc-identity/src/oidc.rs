use async_trait::async_trait;
use mc_core::principal::Principal;
use std::collections::HashMap;

use crate::provider::{AuthCredential, IdentityError, IdentityProvider};

/// Configuration for an OIDC identity provider.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub jwks_uri: String,
    pub email_claim: String,
    pub group_claim: Option<String>,
    pub group_mapping: HashMap<String, String>,
}

/// OIDC identity provider that resolves bearer tokens to principals.
///
/// Currently a stub -- actual JWT validation will be added in a future phase.
pub struct OidcProvider {
    config: OidcConfig,
}

impl OidcProvider {
    pub fn new(config: OidcConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &OidcConfig {
        &self.config
    }
}

#[async_trait]
impl IdentityProvider for OidcProvider {
    async fn resolve(
        &self,
        _credential: &AuthCredential,
    ) -> Result<Option<Principal>, IdentityError> {
        Err(IdentityError::Unavailable(
            "OIDC not yet implemented".into(),
        ))
    }

    async fn validate(&self, _principal: &Principal) -> Result<bool, IdentityError> {
        Err(IdentityError::Unavailable(
            "OIDC not yet implemented".into(),
        ))
    }

    fn name(&self) -> &str {
        "oidc"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OidcConfig {
        OidcConfig {
            issuer: "https://accounts.example.com".to_string(),
            client_id: "my-app".to_string(),
            jwks_uri: "https://accounts.example.com/.well-known/jwks.json".to_string(),
            email_claim: "email".to_string(),
            group_claim: Some("groups".to_string()),
            group_mapping: HashMap::new(),
        }
    }

    #[test]
    fn test_oidc_provider_config() {
        let config = test_config();
        let provider = OidcProvider::new(config);
        assert_eq!(provider.config().issuer, "https://accounts.example.com");
        assert_eq!(provider.name(), "oidc");
    }

    #[tokio::test]
    async fn test_oidc_resolve_returns_unavailable() {
        let provider = OidcProvider::new(test_config());
        let cred = AuthCredential::BearerToken("some-jwt".to_string());
        let result = provider.resolve(&cred).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IdentityError::Unavailable(_)));
    }
}
