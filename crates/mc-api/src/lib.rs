//! HTTP API server for Mission Clearance.
//!
//! Provides REST endpoints for mission management, operation submission,
//! vault administration, policy inspection, and trace querying via axum.

pub mod auth;
pub mod routes;
pub mod state;

use std::sync::Arc;

use state::AppState;

/// Create the full application router with auth middleware.
pub fn create_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .nest("/api/v1", api_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_api_key,
        ))
        .with_state(state)
}

/// Build the versioned API route tree.
fn api_routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new()
        .nest("/missions", routes::missions::router())
        .nest("/vault", routes::vault::router())
        .nest("/trace", routes::trace::router())
        .nest("/policies", routes::policies::router())
        .nest("/operations", routes::operations::router())
        .nest("/principals", routes::principals::router())
        .nest("/roles", routes::roles::router())
        .nest("/org", routes::org::router())
        .nest("/permissions", routes::permissions::router())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> axum::Router {
        let state = AppState::new_for_testing();
        create_router(state)
    }

    async fn body_to_json(body: Body) -> serde_json::Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ----- Auth tests -----

    #[tokio::test]
    async fn test_auth_required() {
        let app = app();
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/policies")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_with_key() {
        let app = app();
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/policies")
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ----- Mission tests -----

    #[tokio::test]
    async fn test_create_mission() {
        let app = app();
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/missions")
            .header("content-type", "application/json")
            .header("x-api-key", "test-key")
            .body(Body::from(
                r#"{"goal":"test","capabilities":[],"policies":[]}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        assert_eq!(json["goal"], "test");
        assert!(json["id"].is_string());
        assert!(json["token"].is_string());
    }

    #[tokio::test]
    async fn test_get_mission() {
        let state = AppState::new_for_testing();
        let mission = {
            let mut mgr = state.mission_manager.lock().unwrap();
            mgr.create_root_mission("lookup-test".to_string(), vec![], vec![])
                .unwrap()
        };

        let app = create_router(state);
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/missions/{}", mission.id))
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        assert_eq!(json["goal"], "lookup-test");
    }

    #[tokio::test]
    async fn test_get_mission_not_found() {
        let app = app();
        let fake_id = uuid::Uuid::new_v4();
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/missions/{}", fake_id))
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delegate_mission() {
        let state = AppState::new_for_testing();

        // Create a root mission with a delegatable capability.
        let parent_id = {
            use mc_core::capability::{Capability, Constraints};
            use mc_core::id::CapabilityId;
            use mc_core::operation::Operation;
            use mc_core::resource::ResourcePattern;

            let cap = Capability {
                id: CapabilityId::new(),
                resource_pattern: ResourcePattern::new("http://api.com/**").unwrap(),
                operations: [Operation::Read, Operation::Write].into_iter().collect(),
                constraints: Constraints::default(),
                delegatable: true,
            };

            let mut mgr = state.mission_manager.lock().unwrap();
            let mission = mgr
                .create_root_mission("parent".to_string(), vec![cap], vec![])
                .unwrap();
            mission.id
        };

        let app = create_router(state);
        let body = serde_json::json!({
            "goal": "child-task",
            "capabilities": [
                {
                    "resource_pattern": "http://api.com/repos/*",
                    "operations": ["Read"],
                    "delegatable": false
                }
            ],
            "policies": []
        });
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/missions/{}/delegate", parent_id))
            .header("content-type", "application/json")
            .header("x-api-key", "test-key")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        assert_eq!(json["goal"], "child-task");
        assert_eq!(json["parent"], parent_id.to_string());
        assert_eq!(json["depth"], 1);
    }

    #[tokio::test]
    async fn test_revoke_mission() {
        let state = AppState::new_for_testing();
        let mission_id = {
            let mut mgr = state.mission_manager.lock().unwrap();
            let m = mgr
                .create_root_mission("to-revoke".to_string(), vec![], vec![])
                .unwrap();
            m.id
        };

        let app = create_router(state);
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/missions/{}", mission_id))
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        assert!(json["revoked"].is_array());
    }

    // ----- Vault tests -----

    #[tokio::test]
    async fn test_vault_add() {
        let app = app();
        let body = serde_json::json!({
            "name": "test-secret",
            "secret_type": "ApiKey",
            "value": "sk-test-123",
            "bound_to": ["http://api.example.com/**"]
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/vault/entries")
            .header("content-type", "application/json")
            .header("x-api-key", "test-key")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        assert!(json["id"].is_string());
    }

    #[tokio::test]
    async fn test_vault_list() {
        let state = AppState::new_for_testing();

        // Pre-populate the vault.
        {
            use mc_core::resource::ResourcePattern;
            use mc_core::vault::SecretType;
            use std::collections::HashSet;

            let vault = state.vault.lock().unwrap();
            let mut bound = HashSet::new();
            bound.insert(ResourcePattern::new("http://api.com/**").unwrap());
            vault
                .add("list-test", SecretType::ApiKey, "val", bound)
                .unwrap();
        }

        let app = create_router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/vault/entries")
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        let entries = json.as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "list-test");
    }

    // ----- Trace tests -----

    #[tokio::test]
    async fn test_trace_events() {
        let state = AppState::new_for_testing();

        // Pre-populate the event log.
        {
            let log = state.event_log.lock().unwrap();
            let mid = mc_core::id::MissionId::new();
            log.append(
                mid,
                mc_core::trace::TraceEventType::MissionCreated,
                None,
                serde_json::json!({"goal": "test"}),
            )
            .unwrap();
        }

        let app = create_router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/trace/events")
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        let events = json.as_array().unwrap();
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn test_trace_graph() {
        let app = app();
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/trace/graph?format=dot")
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ----- Policy tests -----

    #[tokio::test]
    async fn test_policies_list() {
        let app = app();
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/policies")
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        // Empty pipeline by default.
        assert_eq!(json["evaluator_count"], 0);
    }

    // ----- Operation tests -----

    #[tokio::test]
    async fn test_operation_submit() {
        use mc_core::capability::{Capability, Constraints};
        use mc_core::id::CapabilityId;
        use mc_core::operation::Operation;
        use mc_core::resource::ResourcePattern;
        use mc_policy::deterministic::DeterministicEvaluator;

        let state = Arc::new(state::AppState {
            mission_manager: std::sync::Mutex::new(
                mc_kernel::manager::MissionManager::new(10),
            ),
            vault: std::sync::Mutex::new(
                mc_vault::store::VaultStore::new(":memory:", "test-pass").unwrap(),
            ),
            event_log: std::sync::Mutex::new(
                mc_trace::event_log::EventLog::new(":memory:").unwrap(),
            ),
            graph: std::sync::Mutex::new(
                mc_trace::graph::MissionGraph::new(":memory:").unwrap(),
            ),
            policy_pipeline: {
                let mut pipeline = mc_policy::pipeline::PolicyPipeline::new();
                // Add deterministic evaluator (allows normal operations).
                pipeline.add_evaluator(Box::new(DeterministicEvaluator::with_defaults()));
                pipeline
            },
            #[cfg(feature = "feedback-loop")]
            feedback_loop: None,
            expected_api_key: None,
            permission_graph: std::sync::Mutex::new(
                mc_graph::store::PermissionGraphStore::new(":memory:").unwrap(),
            ),
            delegation_engine: mc_graph::delegation_engine::DelegationChecker::permissive(),
        });

        let mission_token = {
            let cap = Capability {
                id: CapabilityId::new(),
                resource_pattern: ResourcePattern::new("http://api.com/**").unwrap(),
                operations: [Operation::Read].into_iter().collect(),
                constraints: Constraints::default(),
                delegatable: false,
            };
            let mut mgr = state.mission_manager.lock().unwrap();
            let m = mgr
                .create_root_mission("op-test".to_string(), vec![cap], vec![])
                .unwrap();
            m.token.to_string()
        };

        let app = create_router(state);
        let body = serde_json::json!({
            "mission_token": mission_token,
            "resource": "http://api.com/repos/foo",
            "operation": "Read",
            "context": {},
            "justification": "test operation"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/operations/request")
            .header("content-type", "application/json")
            .header("x-api-key", "test-key")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        assert_eq!(json["decision"], "allowed");
        assert!(json["request_id"].is_string());
    }

    #[tokio::test]
    async fn test_operation_denied_no_capability() {
        let state = AppState::new_for_testing();

        // Create a mission with NO capabilities.
        let mission_token = {
            let mut mgr = state.mission_manager.lock().unwrap();
            let m = mgr
                .create_root_mission("no-caps".to_string(), vec![], vec![])
                .unwrap();
            m.token.to_string()
        };

        let app = create_router(state);
        let body = serde_json::json!({
            "mission_token": mission_token,
            "resource": "http://api.com/repos/foo",
            "operation": "Read",
            "context": {},
            "justification": "should be denied"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/operations/request")
            .header("content-type", "application/json")
            .header("x-api-key", "test-key")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        assert_eq!(json["decision"], "denied");
        assert!(json["reasoning"]
            .as_str()
            .unwrap()
            .contains("No matching capability"));
    }

    // ----- Full flow test -----

    #[tokio::test]
    async fn test_full_flow() {
        use mc_core::capability::{Capability, Constraints};
        use mc_core::id::CapabilityId;
        use mc_core::operation::Operation;
        use mc_core::resource::ResourcePattern;
        use mc_policy::deterministic::DeterministicEvaluator;

        let state = Arc::new(state::AppState {
            mission_manager: std::sync::Mutex::new(
                mc_kernel::manager::MissionManager::new(10),
            ),
            vault: std::sync::Mutex::new(
                mc_vault::store::VaultStore::new(":memory:", "test-pass").unwrap(),
            ),
            event_log: std::sync::Mutex::new(
                mc_trace::event_log::EventLog::new(":memory:").unwrap(),
            ),
            graph: std::sync::Mutex::new(
                mc_trace::graph::MissionGraph::new(":memory:").unwrap(),
            ),
            policy_pipeline: {
                let mut pipeline = mc_policy::pipeline::PolicyPipeline::new();
                pipeline.add_evaluator(Box::new(DeterministicEvaluator::with_defaults()));
                pipeline
            },
            #[cfg(feature = "feedback-loop")]
            feedback_loop: None,
            expected_api_key: None,
            permission_graph: std::sync::Mutex::new(
                mc_graph::store::PermissionGraphStore::new(":memory:").unwrap(),
            ),
            delegation_engine: mc_graph::delegation_engine::DelegationChecker::permissive(),
        });

        // Step 1: Create a mission with capability.
        let (_mission_id, mission_token) = {
            let cap = Capability {
                id: CapabilityId::new(),
                resource_pattern: ResourcePattern::new("http://api.com/**").unwrap(),
                operations: [Operation::Read, Operation::Write].into_iter().collect(),
                constraints: Constraints::default(),
                delegatable: true,
            };
            let mut mgr = state.mission_manager.lock().unwrap();
            let m = mgr
                .create_root_mission("full-flow".to_string(), vec![cap], vec![])
                .unwrap();
            (m.id.to_string(), m.token.to_string())
        };

        // Step 2: Add a vault entry.
        let app = create_router(state.clone());
        let vault_body = serde_json::json!({
            "name": "flow-secret",
            "secret_type": "ApiKey",
            "value": "sk-flow-123",
            "bound_to": ["http://api.com/**"]
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/vault/entries")
            .header("content-type", "application/json")
            .header("x-api-key", "test-key")
            .body(Body::from(serde_json::to_string(&vault_body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Step 3: Submit an operation.
        let app = create_router(state.clone());
        let op_body = serde_json::json!({
            "mission_token": mission_token,
            "resource": "http://api.com/repos/myrepo",
            "operation": "Read",
            "context": {},
            "justification": "read repo data"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/operations/request")
            .header("content-type", "application/json")
            .header("x-api-key", "test-key")
            .body(Body::from(serde_json::to_string(&op_body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let op_json = body_to_json(resp.into_body()).await;
        assert_eq!(op_json["decision"], "allowed");

        // Step 4: Check trace events were logged.
        let app = create_router(state.clone());
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/trace/events")
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let trace_json = body_to_json(resp.into_body()).await;
        let events = trace_json.as_array().unwrap();
        // We should have at least one event (the operation allowed event).
        assert!(!events.is_empty(), "trace should contain events");
    }

    // ----- Mission tree test -----

    #[tokio::test]
    async fn test_mission_tree() {
        use mc_core::capability::{Capability, Constraints};
        use mc_core::id::CapabilityId;
        use mc_core::operation::Operation;
        use mc_core::resource::ResourcePattern;

        let state = AppState::new_for_testing();

        let root_id = {
            let cap = Capability {
                id: CapabilityId::new(),
                resource_pattern: ResourcePattern::new("http://api.com/**").unwrap(),
                operations: [Operation::Read].into_iter().collect(),
                constraints: Constraints::default(),
                delegatable: true,
            };
            let mut mgr = state.mission_manager.lock().unwrap();
            let root = mgr
                .create_root_mission("root".to_string(), vec![cap], vec![])
                .unwrap();

            let child_cap = Capability {
                id: CapabilityId::new(),
                resource_pattern: ResourcePattern::new("http://api.com/repos/*").unwrap(),
                operations: [Operation::Read].into_iter().collect(),
                constraints: Constraints::default(),
                delegatable: false,
            };
            mgr.delegate(root.id, "child".to_string(), vec![child_cap], vec![])
                .unwrap();

            root.id
        };

        let app = create_router(state);
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/missions/{}/tree", root_id))
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        assert_eq!(json["mission"]["goal"], "root");
        let children = json["children"].as_array().unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0]["mission"]["goal"], "child");
    }

    // ----- Vault rotate test -----

    #[tokio::test]
    async fn test_vault_rotate() {
        let state = AppState::new_for_testing();

        let entry_id = {
            use mc_core::resource::ResourcePattern;
            use mc_core::vault::SecretType;
            use std::collections::HashSet;

            let vault = state.vault.lock().unwrap();
            let mut bound = HashSet::new();
            bound.insert(ResourcePattern::new("http://api.com/**").unwrap());
            vault
                .add("rotate-test", SecretType::ApiKey, "old-val", bound)
                .unwrap()
        };

        let app = create_router(state);
        let body = serde_json::json!({ "new_value": "new-val" });
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/vault/entries/{}/rotate", entry_id))
            .header("content-type", "application/json")
            .header("x-api-key", "test-key")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        assert_eq!(json["status"], "rotated");
    }

    // ----- Vault revoke test -----

    #[tokio::test]
    async fn test_vault_revoke() {
        let state = AppState::new_for_testing();

        let entry_id = {
            use mc_core::resource::ResourcePattern;
            use mc_core::vault::SecretType;
            use std::collections::HashSet;

            let vault = state.vault.lock().unwrap();
            let mut bound = HashSet::new();
            bound.insert(ResourcePattern::new("http://api.com/**").unwrap());
            vault
                .add("revoke-test", SecretType::ApiKey, "val", bound)
                .unwrap()
        };

        let app = create_router(state);
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/vault/entries/{}", entry_id))
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        assert_eq!(json["status"], "revoked");
    }

    // ----- Policy dry-run test -----

    #[tokio::test]
    async fn test_policy_dry_run() {
        use mc_policy::deterministic::DeterministicEvaluator;

        let state = Arc::new(state::AppState {
            mission_manager: std::sync::Mutex::new(
                mc_kernel::manager::MissionManager::new(10),
            ),
            vault: std::sync::Mutex::new(
                mc_vault::store::VaultStore::new(":memory:", "test-pass").unwrap(),
            ),
            event_log: std::sync::Mutex::new(
                mc_trace::event_log::EventLog::new(":memory:").unwrap(),
            ),
            graph: std::sync::Mutex::new(
                mc_trace::graph::MissionGraph::new(":memory:").unwrap(),
            ),
            policy_pipeline: {
                let mut pipeline = mc_policy::pipeline::PolicyPipeline::new();
                pipeline.add_evaluator(Box::new(DeterministicEvaluator::with_defaults()));
                pipeline
            },
            #[cfg(feature = "feedback-loop")]
            feedback_loop: None,
            expected_api_key: None,
            permission_graph: std::sync::Mutex::new(
                mc_graph::store::PermissionGraphStore::new(":memory:").unwrap(),
            ),
            delegation_engine: mc_graph::delegation_engine::DelegationChecker::permissive(),
        });

        let app = create_router(state);
        let body = serde_json::json!({
            "resource": "http://api.github.com/repos/org/repo",
            "operation": "Read",
            "justification": "test dry run",
            "mission_goal": "deploy"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/policies/test")
            .header("content-type", "application/json")
            .header("x-api-key", "test-key")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        assert_eq!(json["decision"], "Allow");
    }

    // ----- Trace anomalies test -----

    #[tokio::test]
    async fn test_trace_anomalies() {
        let state = AppState::new_for_testing();

        // Add an anomaly event.
        {
            let log = state.event_log.lock().unwrap();
            let mid = mc_core::id::MissionId::new();
            log.append(
                mid,
                mc_core::trace::TraceEventType::TaintDetected,
                None,
                serde_json::json!({"source": "test"}),
            )
            .unwrap();
            // Also add a non-anomaly event.
            log.append(
                mid,
                mc_core::trace::TraceEventType::MissionCreated,
                None,
                serde_json::json!({"goal": "test"}),
            )
            .unwrap();
        }

        let app = create_router(state);
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/trace/anomalies")
            .header("x-api-key", "test-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_to_json(resp.into_body()).await;
        let anomalies = json.as_array().unwrap();
        // Only the TaintDetected event should appear, not MissionCreated.
        assert_eq!(anomalies.len(), 1);
    }
}
