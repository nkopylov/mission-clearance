//! Shell adapter -- intercepts shell command execution.
//!
//! Parses command strings, classifies operations, and manages credential
//! injection via environment variables. Includes built-in awareness of
//! dangerous command patterns.

use anyhow::{Context, Result};
use async_trait::async_trait;
use mc_core::id::{MissionId, MissionToken, RequestId};
use mc_core::operation::{Operation, OperationContext, OperationRequest};
use mc_core::policy::PolicyDecision;
use mc_core::resource::ResourceUri;
use mc_core::vault::Credential;
use uuid::Uuid;

use crate::{ProtocolAdapter, RawRequest, RawResponse};

/// A pattern that indicates a potentially dangerous command.
#[derive(Debug, Clone)]
struct DangerousPattern {
    pattern: String,
    description: String,
}

/// Adapter for shell command execution.
pub struct ShellAdapter {
    dangerous_patterns: Vec<DangerousPattern>,
}

impl ShellAdapter {
    /// Create a new ShellAdapter with default dangerous patterns.
    pub fn new() -> Self {
        let dangerous_patterns = vec![
            DangerousPattern {
                pattern: "rm -rf".to_string(),
                description: "recursive force delete".to_string(),
            },
            DangerousPattern {
                pattern: "mkfs".to_string(),
                description: "filesystem format".to_string(),
            },
            DangerousPattern {
                pattern: "dd if=".to_string(),
                description: "raw disk write".to_string(),
            },
            DangerousPattern {
                pattern: "chmod 777".to_string(),
                description: "world-writable permissions".to_string(),
            },
            DangerousPattern {
                pattern: "> /dev/".to_string(),
                description: "write to device file".to_string(),
            },
            DangerousPattern {
                pattern: "curl | sh".to_string(),
                description: "pipe remote script to shell".to_string(),
            },
            DangerousPattern {
                pattern: "curl | bash".to_string(),
                description: "pipe remote script to bash".to_string(),
            },
            DangerousPattern {
                pattern: ":(){ :|:& };:".to_string(),
                description: "fork bomb".to_string(),
            },
            DangerousPattern {
                pattern: "shutdown".to_string(),
                description: "system shutdown".to_string(),
            },
            DangerousPattern {
                pattern: "reboot".to_string(),
                description: "system reboot".to_string(),
            },
        ];

        Self { dangerous_patterns }
    }

    /// Check if a command matches any dangerous pattern.
    pub fn check_dangerous(&self, command: &str) -> Option<&str> {
        for dp in &self.dangerous_patterns {
            if command.contains(&dp.pattern) {
                return Some(&dp.description);
            }
        }
        None
    }
}

impl Default for ShellAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a command string into (command_name, args).
/// For piped commands, uses the first command.
fn parse_command(command_str: &str) -> (String, Vec<String>) {
    let trimmed = command_str.trim();
    if trimmed.is_empty() {
        return (String::new(), vec![]);
    }

    // For piped commands, take the first segment
    let first_segment = trimmed.split('|').next().unwrap_or(trimmed).trim();

    // Split on whitespace
    let parts: Vec<&str> = first_segment.split_whitespace().collect();
    if parts.is_empty() {
        return (String::new(), vec![]);
    }

    let command_name = parts[0].to_string();
    let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
    (command_name, args)
}

#[async_trait]
impl ProtocolAdapter for ShellAdapter {
    fn name(&self) -> &str {
        "shell"
    }

    async fn identify_mission(&self, raw: &RawRequest) -> Result<MissionToken> {
        // Extract MISSION_TOKEN from metadata (simulating env var)
        let token_str = raw
            .metadata
            .get("MISSION_TOKEN")
            .or_else(|| raw.metadata.get("mission_token"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing MISSION_TOKEN in shell request metadata"))?;

        let uuid = Uuid::parse_str(token_str).context("invalid MISSION_TOKEN UUID")?;
        Ok(MissionToken::from_uuid(uuid))
    }

    async fn normalize(&self, raw: &RawRequest) -> Result<OperationRequest> {
        let command_str = raw
            .metadata
            .get("command")
            .and_then(|v| v.as_str())
            .or_else(|| std::str::from_utf8(&raw.data).ok())
            .ok_or_else(|| anyhow::anyhow!("missing command in shell request"))?
            .to_string();

        let working_dir = raw
            .metadata
            .get("working_dir")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let (command_name, args) = parse_command(&command_str);

        let mission_token = self.identify_mission(raw).await?;

        let resource_uri = ResourceUri::new(&format!("shell://localhost/bin/{command_name}"))
            .context("failed to construct shell resource URI")?;

        Ok(OperationRequest {
            id: RequestId::new(),
            mission_id: MissionId::from_uuid(*mission_token.as_uuid()),
            resource: resource_uri,
            operation: Operation::Execute,
            context: OperationContext::Shell {
                command: command_name,
                args,
                working_dir,
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
        // Add credentials as environment variables to metadata
        let env = raw
            .metadata
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("metadata is not an object"))?
            .entry("env")
            .or_insert_with(|| serde_json::json!({}));

        let env_obj = env
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("env is not an object"))?;

        for cred in creds {
            let env_name = match cred.secret_type {
                mc_core::vault::SecretType::ApiKey => "API_KEY",
                mc_core::vault::SecretType::BearerToken => "AUTH_TOKEN",
                mc_core::vault::SecretType::Password => "PASSWORD",
                mc_core::vault::SecretType::ConnectionString => "DATABASE_URL",
                mc_core::vault::SecretType::SshKey => "SSH_KEY",
                _ => "CREDENTIAL",
            };
            env_obj.insert(
                env_name.to_string(),
                serde_json::Value::String(cred.value.clone()),
            );
        }

        Ok(())
    }

    async fn forward(&self, raw: RawRequest) -> Result<RawResponse> {
        // Actual shell execution happens at the wrapper level.
        Ok(RawResponse {
            data: raw.data,
            metadata: raw.metadata,
        })
    }

    fn deny(&self, reason: &PolicyDecision) -> RawResponse {
        let command = "unknown"; // command info may not be available in deny context
        let body = serde_json::json!({
            "error": "denied",
            "command": command,
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

    fn make_shell_request(command: &str, token: &str) -> RawRequest {
        RawRequest {
            data: vec![],
            metadata: serde_json::json!({
                "command": command,
                "MISSION_TOKEN": token,
                "working_dir": "/home/user/project",
            }),
        }
    }

    #[tokio::test]
    async fn normalize_simple_command() {
        let adapter = ShellAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = make_shell_request("ls -la", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "shell://localhost/bin/ls");
        assert_eq!(op.operation, Operation::Execute);
        match &op.context {
            OperationContext::Shell { command, args, working_dir } => {
                assert_eq!(command, "ls");
                assert_eq!(args, &vec!["-la".to_string()]);
                assert_eq!(working_dir.as_deref(), Some("/home/user/project"));
            }
            _ => panic!("expected Shell context"),
        }
    }

    #[tokio::test]
    async fn normalize_complex_command() {
        let adapter = ShellAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = make_shell_request("git push origin main", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "shell://localhost/bin/git");
        match &op.context {
            OperationContext::Shell { command, args, .. } => {
                assert_eq!(command, "git");
                assert_eq!(
                    args,
                    &vec![
                        "push".to_string(),
                        "origin".to_string(),
                        "main".to_string()
                    ]
                );
            }
            _ => panic!("expected Shell context"),
        }
    }

    #[tokio::test]
    async fn normalize_pipe_command() {
        let adapter = ShellAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = make_shell_request("cat file.txt | grep pattern", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "shell://localhost/bin/cat");
        match &op.context {
            OperationContext::Shell { command, args, .. } => {
                assert_eq!(command, "cat");
                assert_eq!(args, &vec!["file.txt".to_string()]);
            }
            _ => panic!("expected Shell context"),
        }
    }

    #[tokio::test]
    async fn normalize_command_from_data() {
        let adapter = ShellAdapter::new();
        let token = Uuid::new_v4().to_string();
        let raw = RawRequest {
            data: b"echo hello world".to_vec(),
            metadata: serde_json::json!({
                "MISSION_TOKEN": token,
            }),
        };

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "shell://localhost/bin/echo");
    }

    #[tokio::test]
    async fn identify_mission_from_env() {
        let adapter = ShellAdapter::new();
        let uuid = Uuid::new_v4();
        let raw = make_shell_request("ls", &uuid.to_string());

        let token = adapter.identify_mission(&raw).await.unwrap();
        assert_eq!(*token.as_uuid(), uuid);
    }

    #[tokio::test]
    async fn identify_mission_missing() {
        let adapter = ShellAdapter::new();
        let raw = RawRequest {
            data: vec![],
            metadata: serde_json::json!({
                "command": "ls",
            }),
        };

        let result = adapter.identify_mission(&raw).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn inject_env_credentials() {
        let adapter = ShellAdapter::new();
        let token = Uuid::new_v4().to_string();
        let mut raw = make_shell_request("psql", &token);

        let cred = Credential {
            entry_id: VaultEntryId::new(),
            secret_type: SecretType::ConnectionString,
            value: "postgres://user:pass@localhost/db".to_string(),
        };

        adapter
            .inject_credentials(&mut raw, &[cred])
            .await
            .unwrap();

        let db_url = raw.metadata["env"]["DATABASE_URL"].as_str().unwrap();
        assert_eq!(db_url, "postgres://user:pass@localhost/db");
    }

    #[tokio::test]
    async fn inject_multiple_env_credentials() {
        let adapter = ShellAdapter::new();
        let token = Uuid::new_v4().to_string();
        let mut raw = make_shell_request("deploy", &token);

        let creds = vec![
            Credential {
                entry_id: VaultEntryId::new(),
                secret_type: SecretType::ApiKey,
                value: "key-123".to_string(),
            },
            Credential {
                entry_id: VaultEntryId::new(),
                secret_type: SecretType::Password,
                value: "secret-pass".to_string(),
            },
        ];

        adapter
            .inject_credentials(&mut raw, &creds)
            .await
            .unwrap();

        assert_eq!(raw.metadata["env"]["API_KEY"].as_str().unwrap(), "key-123");
        assert_eq!(
            raw.metadata["env"]["PASSWORD"].as_str().unwrap(),
            "secret-pass"
        );
    }

    #[tokio::test]
    async fn deny_response() {
        let adapter = ShellAdapter::new();
        let decision = PolicyDecision {
            policy_id: PolicyId::new(),
            kind: PolicyDecisionKind::Deny,
            reasoning: "dangerous command detected".to_string(),
            evaluator: PolicyEvaluatorType::Deterministic,
        };

        let resp = adapter.deny(&decision);
        let body: serde_json::Value = serde_json::from_slice(&resp.data).unwrap();
        assert_eq!(body["error"], "denied");
        assert_eq!(body["reason"], "dangerous command detected");
    }

    #[test]
    fn adapter_name() {
        let adapter = ShellAdapter::new();
        assert_eq!(adapter.name(), "shell");
    }

    #[test]
    fn check_dangerous_rm_rf() {
        let adapter = ShellAdapter::new();
        let result = adapter.check_dangerous("rm -rf /");
        assert!(result.is_some());
        assert!(result.unwrap().contains("recursive force delete"));
    }

    #[test]
    fn check_dangerous_mkfs() {
        let adapter = ShellAdapter::new();
        let result = adapter.check_dangerous("mkfs.ext4 /dev/sda1");
        assert!(result.is_some());
    }

    #[test]
    fn check_safe_command() {
        let adapter = ShellAdapter::new();
        let result = adapter.check_dangerous("ls -la /home");
        assert!(result.is_none());
    }

    #[test]
    fn check_dangerous_fork_bomb() {
        let adapter = ShellAdapter::new();
        let result = adapter.check_dangerous(":(){ :|:& };:");
        assert!(result.is_some());
        assert!(result.unwrap().contains("fork bomb"));
    }

    #[test]
    fn parse_empty_command() {
        let (cmd, args) = parse_command("");
        assert!(cmd.is_empty());
        assert!(args.is_empty());
    }

    #[test]
    fn parse_single_command() {
        let (cmd, args) = parse_command("ls");
        assert_eq!(cmd, "ls");
        assert!(args.is_empty());
    }

    #[test]
    fn parse_command_with_pipe() {
        let (cmd, args) = parse_command("ps aux | grep nginx | head -5");
        assert_eq!(cmd, "ps");
        assert_eq!(args, vec!["aux".to_string()]);
    }
}
