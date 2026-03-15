//! CLI binary for the Mission Clearance security harness.
//!
//! Starts the API server that the Claude Code hook communicates with.
//! All management operations (missions, vault, trace, policy) are handled
//! by MCP tools via the plugin — the CLI only needs to start the server.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(name = "mission-clearance")]
#[command(about = "Claude Code security harness — starts the Mission Clearance server")]
struct Cli {
    /// Path to configuration file
    #[arg(long, default_value = "mission-clearance.toml")]
    config: String,
}

// ---- Configuration ----

#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    kernel: KernelConfig,
    #[serde(default)]
    server: ServerConfig,
    #[serde(default)]
    vault: VaultConfig,
}

#[derive(Deserialize)]
struct KernelConfig {
    #[serde(default = "default_max_delegation_depth")]
    max_delegation_depth: u32,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            max_delegation_depth: default_max_delegation_depth(),
        }
    }
}

#[derive(Deserialize)]
struct ServerConfig {
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default = "default_listen")]
    listen: String,
    /// Expected API key. Override with MC_API_KEY env var.
    api_key: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            listen: default_listen(),
            api_key: None,
        }
    }
}

#[derive(Deserialize)]
struct VaultConfig {
    /// Vault passphrase. Override with MC_VAULT_PASSPHRASE env var.
    passphrase: Option<String>,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self { passphrase: None }
    }
}

fn default_max_delegation_depth() -> u32 {
    10
}

fn default_port() -> u16 {
    9090
}

fn default_listen() -> String {
    "127.0.0.1".to_string()
}

/// Resolve the vault passphrase from (in order of priority):
/// 1. MC_VAULT_PASSPHRASE environment variable
/// 2. Config file vault.passphrase
/// 3. A default with a warning log
fn resolve_vault_passphrase(config: &Config) -> String {
    if let Ok(env_pass) = std::env::var("MC_VAULT_PASSPHRASE") {
        if !env_pass.is_empty() {
            return env_pass;
        }
    }
    if let Some(ref pass) = config.vault.passphrase {
        if !pass.is_empty() {
            return pass.clone();
        }
    }
    tracing::warn!(
        "No vault passphrase configured. Set MC_VAULT_PASSPHRASE or vault.passphrase in config. \
         Using an ephemeral random passphrase for this session."
    );
    uuid::Uuid::new_v4().to_string()
}

/// Resolve the expected API key from (in order of priority):
/// 1. MC_API_KEY environment variable
/// 2. Config file server.api_key
/// 3. None (dev mode: any non-empty key accepted)
fn resolve_api_key(config: &Config) -> Option<String> {
    if let Ok(env_key) = std::env::var("MC_API_KEY") {
        if !env_key.is_empty() {
            return Some(env_key);
        }
    }
    config.server.api_key.clone()
}

fn load_config(path: &str) -> Config {
    match std::fs::read_to_string(path) {
        Ok(content) => toml::from_str(&content).unwrap_or_else(|e| {
            eprintln!("Warning: failed to parse config {path}: {e}");
            Config {
                kernel: KernelConfig::default(),
                server: ServerConfig::default(),
                vault: VaultConfig::default(),
            }
        }),
        Err(_) => Config {
            kernel: KernelConfig::default(),
            server: ServerConfig::default(),
            vault: VaultConfig::default(),
        },
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = load_config(&cli.config);

    cmd_start(config).await
}

// ---- Start command ----

async fn cmd_start(config: Config) -> Result<()> {
    use mc_policy::deterministic::DeterministicEvaluator;

    let vault_passphrase = resolve_vault_passphrase(&config);
    let expected_api_key = resolve_api_key(&config);

    if expected_api_key.is_none() {
        tracing::warn!(
            "No API key configured (MC_API_KEY not set, server.api_key not in config). \
             Any non-empty X-API-Key header will be accepted. \
             Do NOT run in production without setting MC_API_KEY."
        );
    }

    let state = Arc::new(mc_api::state::AppState {
        mission_manager: std::sync::Mutex::new(mc_kernel::manager::MissionManager::new(
            config.kernel.max_delegation_depth,
        )),
        vault: std::sync::Mutex::new(
            mc_vault::store::VaultStore::new(":memory:", &vault_passphrase)
                .context("failed to create vault")?,
        ),
        event_log: std::sync::Mutex::new(
            mc_trace::event_log::EventLog::new(":memory:")
                .context("failed to create event log")?,
        ),
        graph: std::sync::Mutex::new(
            mc_trace::graph::MissionGraph::new(":memory:")
                .context("failed to create mission graph")?,
        ),
        policy_pipeline: {
            let mut pipeline = mc_policy::pipeline::PolicyPipeline::new();
            pipeline.add_evaluator(Box::new(DeterministicEvaluator::with_defaults()));
            pipeline
        },
        #[cfg(feature = "feedback-loop")]
        feedback_loop: mc_policy::feedback::FeedbackLoop::auto_detect(),
        expected_api_key,
    });

    let app = mc_api::create_router(state);
    let addr = format!("{}:{}", config.server.listen, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("failed to bind server address")?;

    tracing::info!("Mission Clearance started on {}", addr);

    axum::serve(listener, app)
        .await
        .context("server error")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_help() {
        // Verify that the CLI parser is well-formed by trying to parse "--help".
        // clap returns an error (not a panic) for --help.
        let result = Cli::try_parse_from(["mission-clearance", "--help"]);
        assert!(result.is_err());
        // The error should be a DisplayHelp kind, not a real failure.
        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn test_cli_parse_defaults() {
        let cli = Cli::try_parse_from(["mission-clearance"]).unwrap();
        assert_eq!(cli.config, "mission-clearance.toml");
    }

    #[test]
    fn test_cli_parse_custom_config() {
        let cli =
            Cli::try_parse_from(["mission-clearance", "--config", "/etc/mc.toml"]).unwrap();
        assert_eq!(cli.config, "/etc/mc.toml");
    }

    #[test]
    fn test_load_config_defaults() {
        // Loading a nonexistent file should return defaults.
        let config = load_config("/nonexistent/path/config.toml");
        assert_eq!(config.kernel.max_delegation_depth, 10);
        assert_eq!(config.server.port, 9090);
        assert_eq!(config.server.listen, "127.0.0.1");
        assert!(config.server.api_key.is_none());
        assert!(config.vault.passphrase.is_none());
    }

    #[test]
    fn test_load_config_from_string() {
        let toml_str = r#"
            [kernel]
            max_delegation_depth = 5

            [server]
            port = 8080
            listen = "0.0.0.0"
            api_key = "my-secret"

            [vault]
            passphrase = "vault-secret"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.kernel.max_delegation_depth, 5);
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.listen, "0.0.0.0");
        assert_eq!(config.server.api_key.as_deref(), Some("my-secret"));
        assert_eq!(config.vault.passphrase.as_deref(), Some("vault-secret"));
    }
}
