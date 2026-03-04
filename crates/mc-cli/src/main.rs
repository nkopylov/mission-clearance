use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mc_sdk::EmbeddedKernel;
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(name = "mission-clearance")]
#[command(about = "Autonomous agent permission management system")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to configuration file
    #[arg(long, default_value = "mission-clearance.toml")]
    config: String,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the kernel with all adapters and the HTTP API server
    Start,

    /// Vault management
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },

    /// Mission management
    Mission {
        #[command(subcommand)]
        command: MissionCommands,
    },

    /// Trace and audit
    Trace {
        #[command(subcommand)]
        command: TraceCommands,
    },

    /// Policy management
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
}

#[derive(Debug, Subcommand)]
enum VaultCommands {
    /// Add a credential
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        secret_type: String,
        #[arg(long)]
        resource: Vec<String>,
        #[arg(long)]
        value: String,
    },
    /// List credentials
    List,
    /// Rotate a credential
    Rotate {
        /// Credential name
        name: String,
        #[arg(long)]
        value: String,
    },
    /// Revoke a credential
    Revoke {
        /// Credential name
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum MissionCommands {
    /// Create a root mission
    Create {
        #[arg(long)]
        goal: String,
    },
    /// List active missions
    List,
    /// Inspect a mission
    Inspect {
        /// Mission ID
        id: String,
    },
    /// Revoke a mission
    Revoke {
        /// Mission ID
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum TraceCommands {
    /// Show trace events for a mission
    Show {
        /// Mission ID
        mission_id: String,
    },
    /// Export mission graph
    Graph {
        /// Mission ID
        mission_id: String,
        #[arg(long, default_value = "dot")]
        format: String,
    },
    /// Show recent denials
    Denials,
    /// Show detected anomalies
    Anomalies,
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    /// List active policies
    List,
}

// ---- Configuration ----

#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    kernel: KernelConfig,
    #[serde(default)]
    server: ServerConfig,
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
        }
    }
}

fn default_max_delegation_depth() -> u32 {
    10
}

fn default_port() -> u16 {
    9090
}

fn load_config(path: &str) -> Config {
    match std::fs::read_to_string(path) {
        Ok(content) => toml::from_str(&content).unwrap_or_else(|e| {
            eprintln!("Warning: failed to parse config {path}: {e}");
            Config {
                kernel: KernelConfig::default(),
                server: ServerConfig::default(),
            }
        }),
        Err(_) => Config {
            kernel: KernelConfig::default(),
            server: ServerConfig::default(),
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

    match cli.command {
        Commands::Start => cmd_start(config).await,
        Commands::Vault { command } => cmd_vault(command, config),
        Commands::Mission { command } => cmd_mission(command, config),
        Commands::Trace { command } => cmd_trace(command, config),
        Commands::Policy { command } => cmd_policy(command, config),
    }
}

// ---- Start command ----

async fn cmd_start(config: Config) -> Result<()> {
    use mc_policy::deterministic::DeterministicEvaluator;

    let state = Arc::new(mc_api::state::AppState {
        mission_manager: std::sync::Mutex::new(mc_kernel::manager::MissionManager::new(
            config.kernel.max_delegation_depth,
        )),
        vault: std::sync::Mutex::new(
            mc_vault::store::VaultStore::new(":memory:", "mission-clearance")
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
    });

    let app = mc_api::create_router(state);
    let addr = format!("0.0.0.0:{}", config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("failed to bind server address")?;

    println!("Mission Clearance started on :{}", config.server.port);

    axum::serve(listener, app)
        .await
        .context("server error")?;

    Ok(())
}

// ---- Vault commands ----

fn cmd_vault(command: VaultCommands, config: Config) -> Result<()> {
    let kernel = EmbeddedKernel::new(config.kernel.max_delegation_depth)?;

    match command {
        VaultCommands::Add {
            name,
            secret_type,
            resource,
            value,
        } => {
            let id = kernel.vault_add(&name, &secret_type, &value, resource)?;
            println!("Added credential: {id}");
        }
        VaultCommands::List => {
            let entries = kernel.vault_list()?;
            if entries.is_empty() {
                println!("No credentials stored.");
            } else {
                for entry in entries {
                    println!(
                        "  {} [{}] type={} revoked={}",
                        entry.name, entry.id, entry.secret_type, entry.revoked
                    );
                }
            }
        }
        VaultCommands::Rotate { name, value } => {
            // Look up entry by name, then rotate.
            let entries = kernel.vault_list()?;
            let entry = entries
                .iter()
                .find(|e| e.name == name)
                .context("credential not found")?;

            let entry_id = uuid::Uuid::parse_str(&entry.id)
                .map(mc_core::id::VaultEntryId::from_uuid)
                .context("invalid vault entry ID")?;

            let vault = kernel.state().vault.lock().unwrap();
            vault.rotate(&entry_id, &value)?;
            println!("Rotated credential: {name}");
        }
        VaultCommands::Revoke { name } => {
            let entries = kernel.vault_list()?;
            let entry = entries
                .iter()
                .find(|e| e.name == name)
                .context("credential not found")?;

            let entry_id = uuid::Uuid::parse_str(&entry.id)
                .map(mc_core::id::VaultEntryId::from_uuid)
                .context("invalid vault entry ID")?;

            let vault = kernel.state().vault.lock().unwrap();
            vault.revoke(&entry_id)?;
            println!("Revoked credential: {name}");
        }
    }

    Ok(())
}

// ---- Mission commands ----

fn cmd_mission(command: MissionCommands, config: Config) -> Result<()> {
    let kernel = EmbeddedKernel::new(config.kernel.max_delegation_depth)?;

    match command {
        MissionCommands::Create { goal } => {
            let resp = kernel.create_mission(&goal, vec![], vec![])?;
            println!("Created mission:");
            println!("  ID:    {}", resp.id);
            println!("  Token: {}", resp.token);
            println!("  Goal:  {}", resp.goal);
        }
        MissionCommands::List => {
            // The embedded kernel doesn't have a list-all method, so we print a note.
            println!("Mission listing requires a running server or persistent state.");
            println!("Use 'mission-clearance start' and query via the API.");
        }
        MissionCommands::Inspect { id } => {
            let resp = kernel.get_mission(&id)?;
            println!("Mission {}:", resp.id);
            println!("  Goal:   {}", resp.goal);
            println!("  Status: {}", resp.status);
            println!("  Depth:  {}", resp.depth);
            if let Some(parent) = &resp.parent {
                println!("  Parent: {parent}");
            }
            println!("  Created: {}", resp.created_at);
        }
        MissionCommands::Revoke { id } => {
            let revoked = kernel.revoke_mission(&id)?;
            println!("Revoked {} mission(s):", revoked.len());
            for rid in &revoked {
                println!("  {rid}");
            }
        }
    }

    Ok(())
}

// ---- Trace commands ----

fn cmd_trace(command: TraceCommands, config: Config) -> Result<()> {
    let kernel = EmbeddedKernel::new(config.kernel.max_delegation_depth)?;

    match command {
        TraceCommands::Show { mission_id } => {
            let mid = uuid::Uuid::parse_str(&mission_id)
                .map(mc_core::id::MissionId::from_uuid)
                .context("invalid mission ID")?;

            let log = kernel.state().event_log.lock().unwrap();
            let events = log.get_events_for_mission(mid)?;

            if events.is_empty() {
                println!("No trace events for mission {mission_id}.");
            } else {
                for event in &events {
                    println!(
                        "[{}] seq={} type={:?}",
                        event.timestamp, event.sequence, event.event_type
                    );
                    println!("  payload: {}", event.payload);
                }
            }
        }
        TraceCommands::Graph {
            mission_id: _,
            format,
        } => {
            let graph = kernel.state().graph.lock().unwrap();
            let fmt = match format.as_str() {
                "dot" => mc_core::trace::GraphFormat::Dot,
                "json" => mc_core::trace::GraphFormat::Json,
                other => anyhow::bail!("unsupported format: {other}"),
            };
            let output = graph.export(fmt)?;
            println!("{output}");
        }
        TraceCommands::Denials => {
            let log = kernel.state().event_log.lock().unwrap();
            let events = log.get_recent(100)?;
            let denials: Vec<_> = events
                .into_iter()
                .filter(|e| e.event_type == mc_core::trace::TraceEventType::OperationDenied)
                .collect();

            if denials.is_empty() {
                println!("No recent denials.");
            } else {
                for d in &denials {
                    println!(
                        "[{}] mission={} payload={}",
                        d.timestamp, d.mission_id, d.payload
                    );
                }
            }
        }
        TraceCommands::Anomalies => {
            let log = kernel.state().event_log.lock().unwrap();
            let events = log.get_recent(200)?;
            let anomaly_types = [
                mc_core::trace::TraceEventType::TaintDetected,
                mc_core::trace::TraceEventType::GoalDriftDetected,
                mc_core::trace::TraceEventType::PromptInjectionSuspected,
            ];
            let anomalies: Vec<_> = events
                .into_iter()
                .filter(|e| anomaly_types.contains(&e.event_type))
                .collect();

            if anomalies.is_empty() {
                println!("No anomalies detected.");
            } else {
                for a in &anomalies {
                    println!(
                        "[{}] type={:?} mission={} payload={}",
                        a.timestamp, a.event_type, a.mission_id, a.payload
                    );
                }
            }
        }
    }

    Ok(())
}

// ---- Policy commands ----

fn cmd_policy(command: PolicyCommands, config: Config) -> Result<()> {
    let kernel = EmbeddedKernel::new(config.kernel.max_delegation_depth)?;

    match command {
        PolicyCommands::List => {
            let count = kernel.state().policy_pipeline.evaluator_count();
            println!("Policy pipeline has {count} evaluator(s).");
        }
    }

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
    fn test_cli_parse_start() {
        let cli = Cli::try_parse_from(["mission-clearance", "start"]).unwrap();
        assert!(matches!(cli.command, Commands::Start));
        assert_eq!(cli.config, "mission-clearance.toml");
    }

    #[test]
    fn test_cli_parse_vault_add() {
        let cli = Cli::try_parse_from([
            "mission-clearance",
            "vault",
            "add",
            "--name",
            "my-key",
            "--secret-type",
            "ApiKey",
            "--value",
            "sk-123",
            "--resource",
            "http://api.com/**",
        ])
        .unwrap();

        match cli.command {
            Commands::Vault {
                command: VaultCommands::Add {
                    name,
                    secret_type,
                    value,
                    resource,
                },
            } => {
                assert_eq!(name, "my-key");
                assert_eq!(secret_type, "ApiKey");
                assert_eq!(value, "sk-123");
                assert_eq!(resource, vec!["http://api.com/**"]);
            }
            _ => panic!("expected Vault::Add command"),
        }
    }

    #[test]
    fn test_cli_parse_mission_create() {
        let cli =
            Cli::try_parse_from(["mission-clearance", "mission", "create", "--goal", "deploy"])
                .unwrap();

        match cli.command {
            Commands::Mission {
                command: MissionCommands::Create { goal },
            } => {
                assert_eq!(goal, "deploy");
            }
            _ => panic!("expected Mission::Create command"),
        }
    }

    #[test]
    fn test_cli_parse_trace_show() {
        let cli = Cli::try_parse_from([
            "mission-clearance",
            "trace",
            "show",
            "550e8400-e29b-41d4-a716-446655440000",
        ])
        .unwrap();

        match cli.command {
            Commands::Trace {
                command: TraceCommands::Show { mission_id },
            } => {
                assert_eq!(mission_id, "550e8400-e29b-41d4-a716-446655440000");
            }
            _ => panic!("expected Trace::Show command"),
        }
    }

    #[test]
    fn test_cli_parse_custom_config() {
        let cli =
            Cli::try_parse_from(["mission-clearance", "--config", "/etc/mc.toml", "start"])
                .unwrap();
        assert_eq!(cli.config, "/etc/mc.toml");
        assert!(matches!(cli.command, Commands::Start));
    }

    #[test]
    fn test_load_config_defaults() {
        // Loading a nonexistent file should return defaults.
        let config = load_config("/nonexistent/path/config.toml");
        assert_eq!(config.kernel.max_delegation_depth, 10);
        assert_eq!(config.server.port, 9090);
    }

    #[test]
    fn test_load_config_from_string() {
        let toml_str = r#"
            [kernel]
            max_delegation_depth = 5

            [server]
            port = 8080
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.kernel.max_delegation_depth, 5);
        assert_eq!(config.server.port, 8080);
    }
}
