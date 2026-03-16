use async_trait::async_trait;
use mc_core::principal::Principal;
use thiserror::Error;

/// Errors that can occur during identity resolution.
#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("invalid credential: {0}")]
    InvalidCredential(String),
    #[error("principal not found")]
    NotFound,
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// The type of authentication credential presented.
#[derive(Debug, Clone)]
pub enum AuthCredential {
    /// OIDC JWT bearer token -- resolves to Human.
    BearerToken(String),
    /// Static API key -- resolves to ServiceAccount.
    ApiKey(String),
    /// Mission token -- resolves to AiAgent.
    MissionToken(String),
    /// Client certificate -- resolves to ServiceAccount.
    ClientCertificate { fingerprint: String },
}

/// Trait for identity providers that resolve credentials to principals.
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Resolve an auth credential to a principal.
    async fn resolve(
        &self,
        credential: &AuthCredential,
    ) -> Result<Option<Principal>, IdentityError>;

    /// Validate that a principal's session is still valid.
    async fn validate(&self, principal: &Principal) -> Result<bool, IdentityError>;

    /// The name of this provider for logging.
    fn name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_credential_bearer_token() {
        let cred = AuthCredential::BearerToken("tok-123".to_string());
        assert!(matches!(cred, AuthCredential::BearerToken(ref t) if t == "tok-123"));
    }

    #[test]
    fn test_auth_credential_api_key() {
        let cred = AuthCredential::ApiKey("key-abc".to_string());
        assert!(matches!(cred, AuthCredential::ApiKey(ref k) if k == "key-abc"));
    }

    #[test]
    fn test_auth_credential_mission_token() {
        let cred = AuthCredential::MissionToken("mt-xyz".to_string());
        assert!(matches!(cred, AuthCredential::MissionToken(ref t) if t == "mt-xyz"));
    }

    #[test]
    fn test_auth_credential_client_certificate() {
        let cred = AuthCredential::ClientCertificate {
            fingerprint: "sha256:abc123".to_string(),
        };
        assert!(
            matches!(cred, AuthCredential::ClientCertificate { ref fingerprint } if fingerprint == "sha256:abc123")
        );
    }

    #[test]
    fn test_identity_error_display() {
        let err = IdentityError::InvalidCredential("bad token".to_string());
        assert_eq!(err.to_string(), "invalid credential: bad token");

        let err = IdentityError::NotFound;
        assert_eq!(err.to_string(), "principal not found");

        let err = IdentityError::Unavailable("down".to_string());
        assert_eq!(err.to_string(), "provider unavailable: down");

        let err = IdentityError::Internal("oops".to_string());
        assert_eq!(err.to_string(), "internal error: oops");
    }
}
