use crate::id::VaultEntryId;
use crate::resource::ResourcePattern;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The type of secret stored in a vault entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretType {
    ApiKey,
    BearerToken,
    Certificate,
    ConnectionString,
    Password,
    SshKey,
    Custom,
}

/// Policy for automatic credential rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationPolicy {
    TimeBased { interval_days: u32 },
    UsageBased { max_uses: u64 },
}

/// Metadata for a vault entry (no secret value -- that stays encrypted in storage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntryMetadata {
    pub id: VaultEntryId,
    pub name: String,
    pub secret_type: SecretType,
    pub bound_to: HashSet<ResourcePattern>,
    pub rotation_policy: Option<RotationPolicy>,
    pub created_at: DateTime<Utc>,
    pub last_rotated: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// A decrypted credential ready for injection into a request.
///
/// This type holds the actual secret value and should be treated with care --
/// it exists only transiently during credential injection.
#[derive(Debug, Clone)]
pub struct Credential {
    pub entry_id: VaultEntryId,
    pub secret_type: SecretType,
    pub value: String,
}

/// How to inject a credential into an outbound request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionMethod {
    HttpHeader { name: String },
    HttpBearerToken,
    EnvironmentVariable { name: String },
    ConnectionStringRewrite,
    ToolCallParameter { parameter_name: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_type_variants() {
        let types = vec![
            SecretType::ApiKey,
            SecretType::BearerToken,
            SecretType::Certificate,
            SecretType::ConnectionString,
            SecretType::Password,
            SecretType::SshKey,
            SecretType::Custom,
        ];
        assert_eq!(types.len(), 7);
        for t in &types {
            let json = serde_json::to_string(t).unwrap();
            let deser: SecretType = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, t);
        }
    }

    #[test]
    fn test_rotation_policy_serialize() {
        let time_based = RotationPolicy::TimeBased { interval_days: 90 };
        let usage_based = RotationPolicy::UsageBased { max_uses: 1000 };

        let json = serde_json::to_string(&time_based).unwrap();
        let _: RotationPolicy = serde_json::from_str(&json).unwrap();

        let json = serde_json::to_string(&usage_based).unwrap();
        let _: RotationPolicy = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_vault_entry_metadata() {
        let mut bound_to = HashSet::new();
        bound_to.insert(ResourcePattern::new("http://api.github.com/**").unwrap());

        let metadata = VaultEntryMetadata {
            id: VaultEntryId::new(),
            name: "github-token".to_string(),
            secret_type: SecretType::BearerToken,
            bound_to,
            rotation_policy: Some(RotationPolicy::TimeBased { interval_days: 30 }),
            created_at: Utc::now(),
            last_rotated: None,
            revoked: false,
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let deser: VaultEntryMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.name, "github-token");
        assert_eq!(deser.secret_type, SecretType::BearerToken);
        assert!(!deser.revoked);
    }

    #[test]
    fn test_credential() {
        let cred = Credential {
            entry_id: VaultEntryId::new(),
            secret_type: SecretType::ApiKey,
            value: "sk-test-123".to_string(),
        };
        assert_eq!(cred.secret_type, SecretType::ApiKey);
        assert_eq!(cred.value, "sk-test-123");
    }

    #[test]
    fn test_injection_method_variants() {
        let methods = vec![
            InjectionMethod::HttpHeader {
                name: "X-API-Key".to_string(),
            },
            InjectionMethod::HttpBearerToken,
            InjectionMethod::EnvironmentVariable {
                name: "API_KEY".to_string(),
            },
            InjectionMethod::ConnectionStringRewrite,
            InjectionMethod::ToolCallParameter {
                parameter_name: "api_key".to_string(),
            },
        ];

        for method in &methods {
            let json = serde_json::to_string(method).unwrap();
            let _: InjectionMethod = serde_json::from_str(&json).unwrap();
        }
    }
}
