//! End-to-end integration tests for Mission Clearance.
//!
//! These tests exercise the full system through the `EmbeddedKernel` interface,
//! validating that all subsystems (kernel, vault, policy pipeline, trace) work
//! together correctly.

use mc_sdk::{CapabilitySpec, EmbeddedKernel, OperationContext};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn kernel() -> EmbeddedKernel {
    EmbeddedKernel::new(10).expect("failed to create embedded kernel")
}

fn cap(pattern: &str, ops: &[&str], delegatable: bool) -> CapabilitySpec {
    CapabilitySpec {
        resource_pattern: pattern.to_string(),
        operations: ops.iter().map(|s| s.to_string()).collect(),
        delegatable,
    }
}

// ---------------------------------------------------------------------------
// Test 1: Full tool call flow through pipeline
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_tool_call_flow() {
    let k = kernel();

    // 1. Add vault entry: API key bound to "tool://weather-api"
    let _vault_id = k
        .vault_add(
            "weather-api-key",
            "ApiKey",
            "sk-weather-123",
            vec!["tool://weather-api".to_string()],
        )
        .expect("failed to add vault entry");

    // 2. Create root mission with capability for "tool://weather-api" (Read + Execute)
    let mission = k
        .create_mission(
            "fetch weather data",
            vec![cap("tool://weather-api", &["Read", "Execute"], false)],
            vec![],
        )
        .expect("failed to create mission");

    assert_eq!(mission.status, "Active");

    // 3. Submit operation: Execute on "tool://weather-api" with justification
    let result = k
        .submit_operation(
            &mission.token,
            "tool://weather-api",
            "Execute",
            "Calling weather API to get forecast",
        )
        .expect("failed to submit operation");

    // 4. Assert: decision is "allowed"
    assert_eq!(result.decision, "allowed", "Execute on tool://weather-api should be allowed");

    // 5. Submit operation: Write on "tool://weather-api" (not in capabilities)
    let result = k
        .submit_operation(
            &mission.token,
            "tool://weather-api",
            "Write",
            "Attempting to write to weather API",
        )
        .expect("failed to submit operation");

    // 6. Assert: decision is "denied"
    assert_eq!(result.decision, "denied", "Write on tool://weather-api should be denied");
    assert!(
        result.reasoning.contains("No matching capability"),
        "denial should be due to missing capability"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Hierarchical delegation with narrowing
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_delegation_narrowing() {
    let k = kernel();

    // 1. Create root mission with broad capability: "http://api.github.com/**" (Read + Write, delegatable)
    let root = k
        .create_mission(
            "manage github repos",
            vec![cap(
                "http://api.github.com/**",
                &["Read", "Write"],
                true,
            )],
            vec![],
        )
        .expect("failed to create root mission");

    // 2. Delegate sub-mission with narrower cap: "http://api.github.com/repos/myorg/*" (Read only)
    let child = k
        .delegate_mission(
            &root.id,
            "read myorg repos",
            vec![cap(
                "http://api.github.com/repos/myorg/*",
                &["Read"],
                false,
            )],
            vec![],
        )
        .expect("failed to delegate child mission");

    assert_eq!(child.depth, 1);
    assert_eq!(child.parent.as_deref(), Some(root.id.as_str()));

    // 3. Submit operation as child: Read on "http://api.github.com/repos/myorg/repo1"
    let result = k
        .submit_operation(
            &child.token,
            "http://api.github.com/repos/myorg/repo1",
            "Read",
            "reading repo metadata",
        )
        .expect("failed to submit child operation");

    // 4. Assert: allowed
    assert_eq!(result.decision, "allowed", "child Read within scope should be allowed");

    // 5. Submit operation as child: Write on "http://api.github.com/repos/myorg/repo1"
    let result = k
        .submit_operation(
            &child.token,
            "http://api.github.com/repos/myorg/repo1",
            "Write",
            "attempting to write to repo",
        )
        .expect("failed to submit child write operation");

    // 6. Assert: denied (child only has Read)
    assert_eq!(result.decision, "denied", "child Write should be denied (only has Read)");

    // 7. Submit operation as child: Read on "http://api.github.com/users" (outside child's scope)
    let result = k
        .submit_operation(
            &child.token,
            "http://api.github.com/users",
            "Read",
            "attempting to read users endpoint",
        )
        .expect("failed to submit out-of-scope operation");

    // 8. Assert: denied (outside child's resource pattern)
    assert_eq!(
        result.decision, "denied",
        "child Read outside resource pattern should be denied"
    );

    // 9. Revoke root mission
    let revoked = k.revoke_mission(&root.id).expect("failed to revoke root");

    // Both root and child should be revoked
    assert!(revoked.contains(&root.id));
    assert!(revoked.contains(&child.id));

    // 10. Submit operation as child: should be denied (child revoked via cascade)
    let result = k.submit_operation(
        &child.token,
        "http://api.github.com/repos/myorg/repo1",
        "Read",
        "attempt after revocation",
    );

    // The operation should fail because the mission is no longer active.
    assert!(
        result.is_err(),
        "operation on revoked mission should fail"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Dangerous operation blocked by policy
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_dangerous_operations_blocked() {
    let k = kernel();

    // 1. Create mission with broad shell capability: "shell://localhost/**" (Execute)
    let mission = k
        .create_mission(
            "system administration",
            vec![cap("shell://localhost/**", &["Execute"], false)],
            vec![],
        )
        .expect("failed to create shell mission");

    // 2. Submit safe operation: Execute "git status" on "shell://localhost/bin/git"
    //    with Shell context where classification yields Destructiveness::None, Reversibility::Reversible
    let safe_result = k
        .submit_operation_with_context(
            &mission.token,
            "shell://localhost/bin/git",
            "Execute",
            "checking repo status",
            OperationContext::Shell {
                command: "git".to_string(),
                args: vec!["status".to_string()],
                working_dir: None,
            },
        )
        .expect("failed to submit safe operation");

    // 3. Assert: allowed (safe operation)
    assert_eq!(safe_result.decision, "allowed", "git status should be allowed");

    // 4. Submit dangerous operation: Execute "rm -rf /" on "shell://localhost/bin/rm"
    //    with Shell context where classification yields Destructiveness::Catastrophic, Reversibility::Irreversible
    let dangerous_result = k
        .submit_operation_with_context(
            &mission.token,
            "shell://localhost/bin/rm",
            "Execute",
            "cleaning up system",
            OperationContext::Shell {
                command: "rm".to_string(),
                args: vec!["-rf".to_string(), "/".to_string()],
                working_dir: None,
            },
        )
        .expect("failed to submit dangerous operation");

    // 5. Assert: denied (no-catastrophic-destruction policy)
    assert_eq!(
        dangerous_result.decision, "denied",
        "rm -rf / should be denied by catastrophic destruction policy"
    );
    assert!(
        dangerous_result.reasoning.contains("no-catastrophic-destruction"),
        "denial reason should reference the no-catastrophic-destruction rule, got: {}",
        dangerous_result.reasoning
    );
}

// ---------------------------------------------------------------------------
// Test 4: Vault credential lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_vault_lifecycle() {
    let k = kernel();

    // 1. Add vault entry: "github-token" of type BearerToken
    let entry_id = k
        .vault_add(
            "github-token",
            "BearerToken",
            "ghp_initial_value_123",
            vec!["http://api.github.com/**".to_string()],
        )
        .expect("failed to add vault entry");

    assert!(!entry_id.is_empty());

    // 2. List vault entries: assert 1 entry, name matches
    let entries = k.vault_list().expect("failed to list vault entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "github-token");
    assert_eq!(entries[0].secret_type, "BearerToken");
    assert!(!entries[0].revoked);

    // 3. Rotate: update to new value
    k.vault_rotate(&entry_id, "ghp_rotated_value_456")
        .expect("failed to rotate vault entry");

    // 4. List: assert still 1 entry
    let entries = k.vault_list().expect("failed to list after rotation");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "github-token");
    assert!(!entries[0].revoked);

    // 5. Revoke the entry
    k.vault_revoke(&entry_id)
        .expect("failed to revoke vault entry");

    // 6. List: assert entry is marked revoked
    let entries = k.vault_list().expect("failed to list after revocation");
    assert_eq!(entries.len(), 1);
    assert!(entries[0].revoked, "entry should be marked as revoked");
}

// ---------------------------------------------------------------------------
// Test 5: Mission lifecycle states
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_mission_lifecycle() {
    let k = kernel();

    // 1. Create root mission: status should be Active
    let root = k
        .create_mission(
            "deploy microservice",
            vec![cap("http://api.internal.com/**", &["Read", "Write"], true)],
            vec![],
        )
        .expect("failed to create root mission");

    assert_eq!(root.status, "Active");
    assert_eq!(root.depth, 0);
    assert!(root.parent.is_none());

    // 2. Get mission: verify goal, status
    let fetched = k.get_mission(&root.id).expect("failed to get mission");
    assert_eq!(fetched.id, root.id);
    assert_eq!(fetched.goal, "deploy microservice");
    assert_eq!(fetched.status, "Active");

    // 3. Delegate child: verify parent/child relationship
    let child = k
        .delegate_mission(
            &root.id,
            "configure service",
            vec![cap(
                "http://api.internal.com/config/*",
                &["Read"],
                false,
            )],
            vec![],
        )
        .expect("failed to delegate child");

    assert_eq!(child.parent.as_deref(), Some(root.id.as_str()));
    assert_eq!(child.depth, 1);
    assert_eq!(child.status, "Active");

    // 4. Revoke root: verify root and child both revoked
    let revoked = k.revoke_mission(&root.id).expect("failed to revoke root");
    assert_eq!(revoked.len(), 2);
    assert!(revoked.contains(&root.id));
    assert!(revoked.contains(&child.id));

    // Verify root is revoked
    let root_after = k.get_mission(&root.id).expect("failed to get revoked root");
    assert_eq!(root_after.status, "Revoked");

    // Verify child is revoked
    let child_after = k.get_mission(&child.id).expect("failed to get revoked child");
    assert_eq!(child_after.status, "Revoked");

    // 5. Create another mission: verify it works independently
    let independent = k
        .create_mission(
            "independent task",
            vec![cap("http://api.external.com/**", &["Read"], false)],
            vec![],
        )
        .expect("failed to create independent mission");

    assert_eq!(independent.status, "Active");
    assert!(independent.parent.is_none());
    assert_ne!(independent.id, root.id);
}

// ---------------------------------------------------------------------------
// Test 6: Multi-level delegation chain
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_deep_delegation_chain() {
    // 1. Create embedded kernel with max_depth=3
    let k = EmbeddedKernel::new(3).expect("failed to create kernel with depth 3");

    // 2. Create root (depth 0) with broad cap (delegatable)
    let root = k
        .create_mission(
            "root orchestrator",
            vec![cap("http://api.example.com/**", &["Read", "Write", "Execute"], true)],
            vec![],
        )
        .expect("failed to create root");

    assert_eq!(root.depth, 0);

    // 3. Delegate level 1 (depth 1) with narrower cap (delegatable)
    let level1 = k
        .delegate_mission(
            &root.id,
            "team-level agent",
            vec![cap(
                "http://api.example.com/repos/**",
                &["Read", "Write"],
                true,
            )],
            vec![],
        )
        .expect("failed to delegate level 1");

    assert_eq!(level1.depth, 1);

    // 4. Delegate level 2 (depth 2) with even narrower cap
    let level2 = k
        .delegate_mission(
            &level1.id,
            "repo-specific agent",
            vec![cap(
                "http://api.example.com/repos/myrepo/*",
                &["Read"],
                true,
            )],
            vec![],
        )
        .expect("failed to delegate level 2");

    assert_eq!(level2.depth, 2);

    // 5. Assert: level 2 can operate within its narrow scope
    let result = k
        .submit_operation(
            &level2.token,
            "http://api.example.com/repos/myrepo/README.md",
            "Read",
            "reading readme",
        )
        .expect("failed to submit level 2 operation");

    assert_eq!(result.decision, "allowed", "level 2 Read within scope should be allowed");

    // Level 2 should be denied for Write (only has Read)
    let result = k
        .submit_operation(
            &level2.token,
            "http://api.example.com/repos/myrepo/README.md",
            "Write",
            "attempting write",
        )
        .expect("failed to submit level 2 write");

    assert_eq!(result.decision, "denied", "level 2 Write should be denied");

    // Level 2 should be denied outside its scope
    let result = k
        .submit_operation(
            &level2.token,
            "http://api.example.com/repos/otherrepo/file",
            "Read",
            "attempting read outside scope",
        )
        .expect("failed to submit out-of-scope read");

    assert_eq!(result.decision, "denied", "level 2 Read outside scope should be denied");

    // 6. Try to delegate level 3 (depth 3) -- should fail (depth limit is 3, max valid depth is 3-1=2... actually max_depth=3 means max depth is 3)
    let level3 = k.delegate_mission(
        &level2.id,
        "leaf agent",
        vec![cap(
            "http://api.example.com/repos/myrepo/src",
            &["Read"],
            false,
        )],
        vec![],
    );

    assert_eq!(level3.as_ref().map(|m| m.depth).unwrap_or(0), 3, "level 3 should be at depth 3");

    // Delegate level 4 (depth 4) should fail -- exceeds max_depth=3
    if let Ok(l3) = &level3 {
        let level4 = k.delegate_mission(
            &l3.id,
            "too-deep agent",
            vec![cap(
                "http://api.example.com/repos/myrepo/src",
                &["Read"],
                false,
            )],
            vec![],
        );
        assert!(level4.is_err(), "depth 4 delegation should fail when max_depth=3");
    }
}
