//! Database proxy adapter -- intercepts database queries (Postgres).
//!
//! Uses `sqlparser` to parse SQL queries, extract table names, and classify
//! operations (SELECT->Read, INSERT/UPDATE->Write, DELETE/DROP/TRUNCATE->Delete).

use anyhow::{Context, Result};
use async_trait::async_trait;
use mc_core::id::{MissionId, MissionToken, RequestId};
use mc_core::operation::{Operation, OperationContext, OperationRequest};
use mc_core::policy::PolicyDecision;
use mc_core::resource::ResourceUri;
use mc_core::vault::Credential;
use sqlparser::ast::Statement;
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use uuid::Uuid;

use crate::{ProtocolAdapter, RawRequest, RawResponse};

/// Adapter for Postgres database queries.
pub struct DbProxyAdapter {
    upstream_host: String,
    #[allow(dead_code)]
    upstream_port: u16,
    database: String,
}

impl DbProxyAdapter {
    pub fn new(host: &str, port: u16, database: &str) -> Self {
        Self {
            upstream_host: host.to_string(),
            upstream_port: port,
            database: database.to_string(),
        }
    }
}

/// Result of parsing a SQL query: operation type and primary table name.
struct SqlAnalysis {
    operation: Operation,
    table_name: String,
}

/// Analyze a SQL query to determine operation type and target table.
fn analyze_sql(sql: &str) -> Result<SqlAnalysis> {
    let dialect = PostgreSqlDialect {};
    let statements = Parser::parse_sql(&dialect, sql).context("failed to parse SQL")?;

    if statements.is_empty() {
        anyhow::bail!("empty SQL statement");
    }

    let stmt = &statements[0];
    match stmt {
        Statement::Query(query) => {
            let table_name = extract_table_from_query(query);
            Ok(SqlAnalysis {
                operation: Operation::Read,
                table_name,
            })
        }
        Statement::Insert(insert) => {
            let table_name = insert.table_name.to_string();
            // Remove any schema prefix for clean table name
            let table_name = clean_table_name(&table_name);
            Ok(SqlAnalysis {
                operation: Operation::Write,
                table_name,
            })
        }
        Statement::Update { table, .. } => {
            let table_name = table.relation.to_string();
            let table_name = clean_table_name(&table_name);
            Ok(SqlAnalysis {
                operation: Operation::Write,
                table_name,
            })
        }
        Statement::Delete(delete) => {
            let tables = match &delete.from {
                sqlparser::ast::FromTable::WithFromKeyword(tables) => tables,
                sqlparser::ast::FromTable::WithoutKeyword(tables) => tables,
            };
            let table_name = tables
                .first()
                .map(|t| t.relation.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let table_name = clean_table_name(&table_name);
            Ok(SqlAnalysis {
                operation: Operation::Delete,
                table_name,
            })
        }
        Statement::Drop { names, .. } => {
            let table_name = names
                .first()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let table_name = clean_table_name(&table_name);
            Ok(SqlAnalysis {
                operation: Operation::Delete,
                table_name,
            })
        }
        Statement::Truncate { table_names, .. } => {
            let table_name = table_names
                .first()
                .map(|t| t.name.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let table_name = clean_table_name(&table_name);
            Ok(SqlAnalysis {
                operation: Operation::Delete,
                table_name,
            })
        }
        Statement::AlterTable { name, .. } => {
            let table_name = clean_table_name(&name.to_string());
            Ok(SqlAnalysis {
                operation: Operation::Delete, // DDL treated as destructive
                table_name,
            })
        }
        Statement::CreateTable(create) => {
            let table_name = clean_table_name(&create.name.to_string());
            Ok(SqlAnalysis {
                operation: Operation::Write,
                table_name,
            })
        }
        _ => {
            // For unrecognized statements, use Execute and "unknown"
            Ok(SqlAnalysis {
                operation: Operation::Execute,
                table_name: "unknown".to_string(),
            })
        }
    }
}

/// Extract a clean table name from a TableFactor.
fn table_name_from_factor(factor: &sqlparser::ast::TableFactor) -> String {
    match factor {
        sqlparser::ast::TableFactor::Table { name, .. } => clean_table_name(&name.to_string()),
        other => clean_table_name(&other.to_string()),
    }
}

/// Extract the first table name from a SELECT query's FROM clause.
fn extract_table_from_query(query: &sqlparser::ast::Query) -> String {
    use sqlparser::ast::SetExpr;

    if let SetExpr::Select(select) = query.body.as_ref() {
        if let Some(from) = select.from.first() {
            return table_name_from_factor(&from.relation);
        }
    }
    "unknown".to_string()
}

/// Clean a table name by extracting just the table part from potentially
/// schema-qualified names.
fn clean_table_name(name: &str) -> String {
    // Handle schema.table notation -- take the last part
    name.split('.').last().unwrap_or(name).trim().to_string()
}

#[async_trait]
impl ProtocolAdapter for DbProxyAdapter {
    fn name(&self) -> &str {
        "db"
    }

    async fn identify_mission(&self, raw: &RawRequest) -> Result<MissionToken> {
        // Extract mission token from metadata (application_name or connection tag)
        let token_str = raw
            .metadata
            .get("application_name")
            .or_else(|| raw.metadata.get("mission_token"))
            .or_else(|| raw.metadata.get("connection_tag"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!("missing mission token in database connection metadata")
            })?;

        let uuid = Uuid::parse_str(token_str).context("invalid mission token UUID")?;
        Ok(MissionToken::from_uuid(uuid))
    }

    async fn normalize(&self, raw: &RawRequest) -> Result<OperationRequest> {
        let query = raw
            .metadata
            .get("query")
            .and_then(|v| v.as_str())
            .or_else(|| std::str::from_utf8(&raw.data).ok())
            .ok_or_else(|| anyhow::anyhow!("missing SQL query"))?
            .to_string();

        let mission_token = self.identify_mission(raw).await?;

        let analysis = analyze_sql(&query)?;

        let resource_uri = ResourceUri::new(&format!(
            "db://{}/{}/{}",
            self.upstream_host, self.database, analysis.table_name
        ))
        .context("failed to construct database resource URI")?;

        Ok(OperationRequest {
            id: RequestId::new(),
            mission_id: MissionId::from_uuid(*mission_token.as_uuid()),
            resource: resource_uri,
            operation: analysis.operation,
            context: OperationContext::Database {
                query,
                database: self.database.clone(),
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
        // Rewrite connection credentials in metadata
        let meta = raw
            .metadata
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("metadata is not an object"))?;

        for cred in creds {
            match cred.secret_type {
                mc_core::vault::SecretType::ConnectionString => {
                    meta.insert(
                        "connection_string".to_string(),
                        serde_json::Value::String(cred.value.clone()),
                    );
                }
                mc_core::vault::SecretType::Password => {
                    meta.insert(
                        "password".to_string(),
                        serde_json::Value::String(cred.value.clone()),
                    );
                }
                _ => {
                    meta.insert(
                        "credential".to_string(),
                        serde_json::Value::String(cred.value.clone()),
                    );
                }
            }
        }

        Ok(())
    }

    async fn forward(&self, raw: RawRequest) -> Result<RawResponse> {
        // Actual forwarding happens at the proxy server level.
        Ok(RawResponse {
            data: raw.data,
            metadata: raw.metadata,
        })
    }

    fn deny(&self, reason: &PolicyDecision) -> RawResponse {
        let body = serde_json::json!({
            "error": "denied",
            "query": "redacted",
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

    fn make_db_request(query: &str, token: &str) -> RawRequest {
        RawRequest {
            data: vec![],
            metadata: serde_json::json!({
                "query": query,
                "application_name": token,
            }),
        }
    }

    fn adapter() -> DbProxyAdapter {
        DbProxyAdapter::new("localhost", 5432, "mydb")
    }

    #[tokio::test]
    async fn normalize_select() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let raw = make_db_request("SELECT * FROM users", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "db://localhost/mydb/users");
        assert_eq!(op.operation, Operation::Read);
        match &op.context {
            OperationContext::Database { query, database } => {
                assert_eq!(query, "SELECT * FROM users");
                assert_eq!(database, "mydb");
            }
            _ => panic!("expected Database context"),
        }
    }

    #[tokio::test]
    async fn normalize_select_with_where() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let raw = make_db_request(
            "SELECT id, name FROM users WHERE active = true",
            &token,
        );

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "db://localhost/mydb/users");
        assert_eq!(op.operation, Operation::Read);
    }

    #[tokio::test]
    async fn normalize_insert() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let raw = make_db_request(
            "INSERT INTO orders (user_id, total) VALUES (1, 99.99)",
            &token,
        );

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "db://localhost/mydb/orders");
        assert_eq!(op.operation, Operation::Write);
    }

    #[tokio::test]
    async fn normalize_update() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let raw = make_db_request("UPDATE users SET name = 'Bob' WHERE id = 1", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "db://localhost/mydb/users");
        assert_eq!(op.operation, Operation::Write);
    }

    #[tokio::test]
    async fn normalize_delete() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let raw = make_db_request("DELETE FROM logs WHERE created_at < '2024-01-01'", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "db://localhost/mydb/logs");
        assert_eq!(op.operation, Operation::Delete);
    }

    #[tokio::test]
    async fn normalize_drop() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let raw = make_db_request("DROP TABLE users", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "db://localhost/mydb/users");
        assert_eq!(op.operation, Operation::Delete);
    }

    #[tokio::test]
    async fn normalize_truncate() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let raw = make_db_request("TRUNCATE TABLE sessions", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "db://localhost/mydb/sessions");
        assert_eq!(op.operation, Operation::Delete);
    }

    #[tokio::test]
    async fn normalize_alter_table() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let raw = make_db_request("ALTER TABLE users ADD COLUMN email VARCHAR(255)", &token);

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "db://localhost/mydb/users");
        assert_eq!(op.operation, Operation::Delete); // DDL is destructive
    }

    #[tokio::test]
    async fn normalize_create_table() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let raw = make_db_request(
            "CREATE TABLE products (id SERIAL PRIMARY KEY, name TEXT)",
            &token,
        );

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "db://localhost/mydb/products");
        assert_eq!(op.operation, Operation::Write);
    }

    #[tokio::test]
    async fn normalize_join() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let raw = make_db_request(
            "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
            &token,
        );

        let op = adapter.normalize(&raw).await.unwrap();
        // Uses the first table in FROM clause (alias stripped)
        assert_eq!(op.resource.as_str(), "db://localhost/mydb/users");
        assert_eq!(op.operation, Operation::Read);
    }

    #[tokio::test]
    async fn identify_mission_from_application_name() {
        let adapter = adapter();
        let uuid = Uuid::new_v4();
        let raw = make_db_request("SELECT 1", &uuid.to_string());

        let token = adapter.identify_mission(&raw).await.unwrap();
        assert_eq!(*token.as_uuid(), uuid);
    }

    #[tokio::test]
    async fn identify_mission_from_connection_tag() {
        let adapter = adapter();
        let uuid = Uuid::new_v4();
        let raw = RawRequest {
            data: vec![],
            metadata: serde_json::json!({
                "query": "SELECT 1",
                "connection_tag": uuid.to_string(),
            }),
        };

        let token = adapter.identify_mission(&raw).await.unwrap();
        assert_eq!(*token.as_uuid(), uuid);
    }

    #[tokio::test]
    async fn identify_mission_missing() {
        let adapter = adapter();
        let raw = RawRequest {
            data: vec![],
            metadata: serde_json::json!({
                "query": "SELECT 1",
            }),
        };

        let result = adapter.identify_mission(&raw).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn inject_connection_string() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let mut raw = make_db_request("SELECT 1", &token);

        let cred = Credential {
            entry_id: VaultEntryId::new(),
            secret_type: SecretType::ConnectionString,
            value: "postgres://admin:secret@db.example.com:5432/prod".to_string(),
        };

        adapter
            .inject_credentials(&mut raw, &[cred])
            .await
            .unwrap();

        let conn = raw.metadata["connection_string"].as_str().unwrap();
        assert_eq!(conn, "postgres://admin:secret@db.example.com:5432/prod");
    }

    #[tokio::test]
    async fn inject_password() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let mut raw = make_db_request("SELECT 1", &token);

        let cred = Credential {
            entry_id: VaultEntryId::new(),
            secret_type: SecretType::Password,
            value: "super-secret-password".to_string(),
        };

        adapter
            .inject_credentials(&mut raw, &[cred])
            .await
            .unwrap();

        let pass = raw.metadata["password"].as_str().unwrap();
        assert_eq!(pass, "super-secret-password");
    }

    #[tokio::test]
    async fn deny_response() {
        let adapter = adapter();
        let decision = PolicyDecision {
            policy_id: PolicyId::new(),
            kind: PolicyDecisionKind::Deny,
            reasoning: "write to production table denied".to_string(),
            evaluator: PolicyEvaluatorType::Deterministic,
        };

        let resp = adapter.deny(&decision);
        let body: serde_json::Value = serde_json::from_slice(&resp.data).unwrap();
        assert_eq!(body["error"], "denied");
        assert_eq!(body["reason"], "write to production table denied");
        assert_eq!(body["query"], "redacted"); // query is redacted in denial
    }

    #[test]
    fn adapter_name() {
        let adapter = adapter();
        assert_eq!(adapter.name(), "db");
    }

    #[test]
    fn analyze_invalid_sql() {
        let result = analyze_sql("NOT VALID SQL AT ALL ???");
        assert!(result.is_err());
    }

    #[test]
    fn analyze_empty_sql() {
        let result = analyze_sql("");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn normalize_query_from_data() {
        let adapter = adapter();
        let token = Uuid::new_v4().to_string();
        let raw = RawRequest {
            data: b"SELECT count(*) FROM events".to_vec(),
            metadata: serde_json::json!({
                "application_name": token,
            }),
        };

        let op = adapter.normalize(&raw).await.unwrap();
        assert_eq!(op.resource.as_str(), "db://localhost/mydb/events");
        assert_eq!(op.operation, Operation::Read);
    }

    #[test]
    fn clean_table_name_simple() {
        assert_eq!(clean_table_name("users"), "users");
    }

    #[test]
    fn clean_table_name_schema_qualified() {
        assert_eq!(clean_table_name("public.users"), "users");
    }
}
