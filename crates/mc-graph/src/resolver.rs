use anyhow::{Context, Result};
use mc_core::id::{PrincipalId, RoleId};
use mc_core::operation::Operation;
use mc_core::resource::{ResourcePattern, ResourceUri};
use mc_core::role::{Role, RoleAssignmentScope, RolePermission};
use std::collections::HashSet;

use crate::store::PermissionGraphStore;

/// A resolved effective permission for a principal.
#[derive(Debug, Clone)]
pub struct EffectivePermission {
    pub resource_pattern: ResourcePattern,
    pub operations: HashSet<Operation>,
    pub delegatable: bool,
    pub source_role: RoleId,
    pub scope: RoleAssignmentScope,
}

/// Resolves role-based permissions for principals.
pub struct RoleResolver<'a> {
    store: &'a PermissionGraphStore,
}

impl<'a> RoleResolver<'a> {
    /// Create a new role resolver backed by the given store.
    pub fn new(store: &'a PermissionGraphStore) -> Self {
        Self { store }
    }

    /// Resolve all effective permissions for a principal.
    ///
    /// 1. Get all role assignments for the principal.
    /// 2. For each assignment, fetch the role.
    /// 3. Recursively expand composite role includes (with cycle detection).
    /// 4. Collect all `RolePermission`s and return as `EffectivePermission`s.
    pub fn resolve_effective_permissions(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Vec<EffectivePermission>> {
        let assignments = self
            .store
            .get_principal_roles(principal_id)
            .context("failed to get role assignments")?;

        let mut effective = Vec::new();

        for (_assignment_id, role_id, scope) in &assignments {
            let role = self
                .store
                .get_role(role_id)
                .context("failed to get role")?;

            let role = match role {
                Some(r) => r,
                None => continue,
            };

            // Expand includes recursively with cycle detection
            let mut all_permissions: Vec<(RolePermission, RoleId)> = Vec::new();
            let mut visited: HashSet<RoleId> = HashSet::new();
            self.collect_role_permissions(&role, &mut all_permissions, &mut visited)?;

            for (perm, source_role_id) in all_permissions {
                effective.push(EffectivePermission {
                    resource_pattern: perm.resource_pattern,
                    operations: perm.operations,
                    delegatable: perm.delegatable,
                    source_role: source_role_id,
                    scope: *scope,
                });
            }
        }

        Ok(effective)
    }

    /// Recursively collect all permissions from a role and its includes.
    fn collect_role_permissions(
        &self,
        role: &Role,
        out: &mut Vec<(RolePermission, RoleId)>,
        visited: &mut HashSet<RoleId>,
    ) -> Result<()> {
        if !visited.insert(role.id) {
            // Cycle detected -- skip to avoid infinite recursion
            return Ok(());
        }

        // Add this role's own permissions
        for perm in &role.permissions {
            out.push((perm.clone(), role.id));
        }

        // Recurse into included roles
        for included_id in &role.includes {
            if let Some(included_role) = self
                .store
                .get_role(included_id)
                .context("failed to get included role")?
            {
                self.collect_role_permissions(&included_role, out, visited)?;
            }
        }

        Ok(())
    }

    /// Check separation of duties: returns any of the principal's current roles
    /// that conflict with the proposed new role.
    pub fn check_separation_of_duties(
        &self,
        principal_id: &PrincipalId,
        new_role_id: &RoleId,
    ) -> Result<Vec<RoleId>> {
        let new_role = self
            .store
            .get_role(new_role_id)
            .context("failed to get new role")?;

        let new_role = match new_role {
            Some(r) => r,
            None => return Ok(vec![]),
        };

        let conflict_set: HashSet<RoleId> = new_role.conflicts_with.iter().copied().collect();

        if conflict_set.is_empty() {
            return Ok(vec![]);
        }

        let assignments = self
            .store
            .get_principal_roles(principal_id)
            .context("failed to get principal roles")?;

        let mut conflicts = Vec::new();
        for (_assignment_id, role_id, _scope) in &assignments {
            if conflict_set.contains(role_id) {
                conflicts.push(*role_id);
            }
        }

        Ok(conflicts)
    }

    /// Check whether a principal meets the org-level requirement of a role.
    ///
    /// Returns `true` if the role has no `min_org_level` requirement.
    /// Returns `false` if the role requires a minimum level but the principal
    /// has no org position.
    pub fn check_org_level_requirement(
        &self,
        principal_id: &PrincipalId,
        role: &Role,
    ) -> Result<bool> {
        let min_level = match role.min_org_level {
            Some(level) => level,
            None => return Ok(true),
        };

        let principal = self
            .store
            .get_principal(principal_id)
            .context("failed to get principal")?;

        let principal = match principal {
            Some(p) => p,
            None => return Ok(false),
        };

        let org_pos_id = match principal.org_position {
            Some(id) => id,
            None => return Ok(false),
        };

        let org_position = self
            .store
            .get_org_position(&org_pos_id)
            .context("failed to get org position")?;

        match org_position {
            Some(pos) => Ok(pos.level >= min_level),
            None => Ok(false),
        }
    }

    /// Check whether a principal has a specific permission on a resource.
    ///
    /// Resolves all effective permissions and checks if any covers the
    /// given resource URI and operation.
    pub fn has_permission(
        &self,
        principal_id: &PrincipalId,
        resource: &ResourceUri,
        operation: &Operation,
    ) -> Result<bool> {
        let permissions = self.resolve_effective_permissions(principal_id)?;

        for perm in &permissions {
            if perm.resource_pattern.matches(resource) && perm.operations.contains(operation) {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_core::id::{OrgPositionId, PrincipalId, RoleId};
    use mc_core::operation::Operation;
    use mc_core::org::{OrgLevel, OrgPosition};
    use mc_core::principal::{
        Principal, PrincipalDetails, PrincipalKind, PrincipalStatus, PrincipalTrustLevel,
    };
    use mc_core::resource::ResourcePattern;
    use mc_core::role::{Role, RoleAssignmentScope, RolePermission};
    use std::collections::HashSet;

    fn test_store() -> PermissionGraphStore {
        PermissionGraphStore::new(":memory:").expect("in-memory DB should open")
    }

    fn make_principal(name: &str) -> Principal {
        Principal {
            id: PrincipalId::new(),
            kind: PrincipalKind::Human,
            status: PrincipalStatus::Active,
            trust_level: PrincipalTrustLevel::Human,
            display_name: name.to_string(),
            details: PrincipalDetails::Human {
                email: format!("{name}@example.com"),
                external_id: None,
            },
            org_position: None,
            teams: vec![],
        }
    }

    fn make_role(name: &str, permissions: Vec<RolePermission>) -> Role {
        Role {
            id: RoleId::new(),
            name: name.to_string(),
            permissions,
            includes: vec![],
            min_org_level: None,
            conflicts_with: vec![],
        }
    }

    fn make_permission(pattern: &str, ops: &[Operation], delegatable: bool) -> RolePermission {
        RolePermission {
            resource_pattern: ResourcePattern::new(pattern).unwrap(),
            operations: ops.iter().copied().collect(),
            delegatable,
            delegation_restrictions: None,
        }
    }

    #[test]
    fn principal_with_no_roles_has_no_permissions() {
        let store = test_store();
        let principal = make_principal("alice");
        store.add_principal(&principal).unwrap();

        let resolver = RoleResolver::new(&store);
        let perms = resolver
            .resolve_effective_permissions(&principal.id)
            .unwrap();

        assert!(perms.is_empty());
    }

    #[test]
    fn principal_with_role_has_role_permissions() {
        let store = test_store();
        let principal = make_principal("bob");
        store.add_principal(&principal).unwrap();

        let role = make_role(
            "developer",
            vec![make_permission(
                "file:///src/**",
                &[Operation::Read, Operation::Write],
                false,
            )],
        );
        store.add_role(&role).unwrap();
        store
            .assign_role(&principal.id, &role.id, RoleAssignmentScope::Global, None)
            .unwrap();

        let resolver = RoleResolver::new(&store);
        let perms = resolver
            .resolve_effective_permissions(&principal.id)
            .unwrap();

        assert_eq!(perms.len(), 1);
        assert!(perms[0].operations.contains(&Operation::Read));
        assert!(perms[0].operations.contains(&Operation::Write));
        assert_eq!(perms[0].source_role, role.id);
        assert_eq!(perms[0].scope, RoleAssignmentScope::Global);
    }

    #[test]
    fn composite_role_includes_parent_permissions() {
        let store = test_store();
        let principal = make_principal("charlie");
        store.add_principal(&principal).unwrap();

        // Base role: read access
        let base_role = make_role(
            "reader",
            vec![make_permission("file:///docs/**", &[Operation::Read], false)],
        );
        store.add_role(&base_role).unwrap();

        // Composite role: includes base + its own write permission
        let composite = Role {
            id: RoleId::new(),
            name: "editor".to_string(),
            permissions: vec![make_permission(
                "file:///docs/**",
                &[Operation::Write],
                true,
            )],
            includes: vec![base_role.id],
            min_org_level: None,
            conflicts_with: vec![],
        };
        store.add_role(&composite).unwrap();

        store
            .assign_role(
                &principal.id,
                &composite.id,
                RoleAssignmentScope::Global,
                None,
            )
            .unwrap();

        let resolver = RoleResolver::new(&store);
        let perms = resolver
            .resolve_effective_permissions(&principal.id)
            .unwrap();

        // Should have 2 effective permissions: one from composite, one from base
        assert_eq!(perms.len(), 2);

        let ops: HashSet<Operation> = perms.iter().flat_map(|p| p.operations.iter().copied()).collect();
        assert!(ops.contains(&Operation::Read));
        assert!(ops.contains(&Operation::Write));

        // One permission is from the composite role, one from the base
        let source_roles: HashSet<RoleId> = perms.iter().map(|p| p.source_role).collect();
        assert!(source_roles.contains(&composite.id));
        assert!(source_roles.contains(&base_role.id));
    }

    #[test]
    fn separation_of_duties_detects_conflicts() {
        let store = test_store();
        let principal = make_principal("dave");
        store.add_principal(&principal).unwrap();

        let auditor_role = make_role(
            "auditor",
            vec![make_permission(
                "http://audit.example.com/**",
                &[Operation::Read],
                false,
            )],
        );
        store.add_role(&auditor_role).unwrap();

        // Developer role conflicts with auditor
        let developer_role = Role {
            id: RoleId::new(),
            name: "developer".to_string(),
            permissions: vec![make_permission(
                "file:///src/**",
                &[Operation::Read, Operation::Write],
                false,
            )],
            includes: vec![],
            min_org_level: None,
            conflicts_with: vec![auditor_role.id],
        };
        store.add_role(&developer_role).unwrap();

        // Assign auditor to principal
        store
            .assign_role(
                &principal.id,
                &auditor_role.id,
                RoleAssignmentScope::Global,
                None,
            )
            .unwrap();

        let resolver = RoleResolver::new(&store);
        let conflicts = resolver
            .check_separation_of_duties(&principal.id, &developer_role.id)
            .unwrap();

        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0], auditor_role.id);
    }

    #[test]
    fn separation_of_duties_no_conflict() {
        let store = test_store();
        let principal = make_principal("eve");
        store.add_principal(&principal).unwrap();

        let role_a = make_role(
            "role_a",
            vec![make_permission("file:///a/**", &[Operation::Read], false)],
        );
        store.add_role(&role_a).unwrap();

        let role_b = make_role(
            "role_b",
            vec![make_permission("file:///b/**", &[Operation::Read], false)],
        );
        store.add_role(&role_b).unwrap();

        store
            .assign_role(
                &principal.id,
                &role_a.id,
                RoleAssignmentScope::Global,
                None,
            )
            .unwrap();

        let resolver = RoleResolver::new(&store);
        let conflicts = resolver
            .check_separation_of_duties(&principal.id, &role_b.id)
            .unwrap();

        assert!(conflicts.is_empty());
    }

    #[test]
    fn org_level_check_meets_requirement() {
        let store = test_store();

        let org_pos_id = OrgPositionId::new();
        let org_pos = OrgPosition {
            id: org_pos_id,
            title: "Engineering Manager".to_string(),
            level: OrgLevel::Manager,
            reports_to: None,
            team: None,
            holder: None,
        };
        store.add_org_position(&org_pos).unwrap();

        let mut principal = make_principal("frank");
        principal.org_position = Some(org_pos_id);
        store.add_principal(&principal).unwrap();

        let role = Role {
            id: RoleId::new(),
            name: "manager_role".to_string(),
            permissions: vec![],
            includes: vec![],
            min_org_level: Some(OrgLevel::Lead),
            conflicts_with: vec![],
        };

        let resolver = RoleResolver::new(&store);
        let result = resolver
            .check_org_level_requirement(&principal.id, &role)
            .unwrap();

        assert!(result, "Manager should meet Lead requirement");
    }

    #[test]
    fn org_level_check_does_not_meet_requirement() {
        let store = test_store();

        let org_pos_id = OrgPositionId::new();
        let org_pos = OrgPosition {
            id: org_pos_id,
            title: "Individual Contributor".to_string(),
            level: OrgLevel::Individual,
            reports_to: None,
            team: None,
            holder: None,
        };
        store.add_org_position(&org_pos).unwrap();

        let mut principal = make_principal("grace");
        principal.org_position = Some(org_pos_id);
        store.add_principal(&principal).unwrap();

        let role = Role {
            id: RoleId::new(),
            name: "director_role".to_string(),
            permissions: vec![],
            includes: vec![],
            min_org_level: Some(OrgLevel::Director),
            conflicts_with: vec![],
        };

        let resolver = RoleResolver::new(&store);
        let result = resolver
            .check_org_level_requirement(&principal.id, &role)
            .unwrap();

        assert!(!result, "Individual should not meet Director requirement");
    }

    #[test]
    fn org_level_check_no_requirement_returns_true() {
        let store = test_store();
        let principal = make_principal("hank");
        store.add_principal(&principal).unwrap();

        let role = make_role("basic_role", vec![]);

        let resolver = RoleResolver::new(&store);
        let result = resolver
            .check_org_level_requirement(&principal.id, &role)
            .unwrap();

        assert!(result, "No min_org_level means anyone qualifies");
    }

    #[test]
    fn org_level_check_no_org_position_returns_false() {
        let store = test_store();
        let principal = make_principal("iris");
        store.add_principal(&principal).unwrap();

        let role = Role {
            id: RoleId::new(),
            name: "vp_role".to_string(),
            permissions: vec![],
            includes: vec![],
            min_org_level: Some(OrgLevel::VP),
            conflicts_with: vec![],
        };

        let resolver = RoleResolver::new(&store);
        let result = resolver
            .check_org_level_requirement(&principal.id, &role)
            .unwrap();

        assert!(
            !result,
            "Principal without org position should not meet any level requirement"
        );
    }

    #[test]
    fn has_permission_returns_true_for_matching() {
        let store = test_store();
        let principal = make_principal("jack");
        store.add_principal(&principal).unwrap();

        let role = make_role(
            "file_reader",
            vec![make_permission("file:///data/**", &[Operation::Read], false)],
        );
        store.add_role(&role).unwrap();
        store
            .assign_role(&principal.id, &role.id, RoleAssignmentScope::Global, None)
            .unwrap();

        let resolver = RoleResolver::new(&store);
        let resource = ResourceUri::new("file:///data/reports/q1.csv").unwrap();
        let result = resolver
            .has_permission(&principal.id, &resource, &Operation::Read)
            .unwrap();

        assert!(result);
    }

    #[test]
    fn has_permission_returns_false_for_wrong_operation() {
        let store = test_store();
        let principal = make_principal("kate");
        store.add_principal(&principal).unwrap();

        let role = make_role(
            "file_reader_only",
            vec![make_permission("file:///data/**", &[Operation::Read], false)],
        );
        store.add_role(&role).unwrap();
        store
            .assign_role(&principal.id, &role.id, RoleAssignmentScope::Global, None)
            .unwrap();

        let resolver = RoleResolver::new(&store);
        let resource = ResourceUri::new("file:///data/reports/q1.csv").unwrap();
        let result = resolver
            .has_permission(&principal.id, &resource, &Operation::Write)
            .unwrap();

        assert!(!result);
    }

    #[test]
    fn has_permission_returns_false_for_wrong_resource() {
        let store = test_store();
        let principal = make_principal("leo");
        store.add_principal(&principal).unwrap();

        let role = make_role(
            "src_reader",
            vec![make_permission("file:///src/**", &[Operation::Read], false)],
        );
        store.add_role(&role).unwrap();
        store
            .assign_role(&principal.id, &role.id, RoleAssignmentScope::Global, None)
            .unwrap();

        let resolver = RoleResolver::new(&store);
        let resource = ResourceUri::new("file:///etc/passwd").unwrap();
        let result = resolver
            .has_permission(&principal.id, &resource, &Operation::Read)
            .unwrap();

        assert!(!result);
    }

    #[test]
    fn composite_role_cycle_does_not_infinite_loop() {
        let store = test_store();
        let principal = make_principal("mary");
        store.add_principal(&principal).unwrap();

        let role_a_id = RoleId::new();
        let role_b_id = RoleId::new();

        // role_a includes role_b, role_b includes role_a (cycle)
        let role_a = Role {
            id: role_a_id,
            name: "cycle_a".to_string(),
            permissions: vec![make_permission(
                "file:///a/**",
                &[Operation::Read],
                false,
            )],
            includes: vec![role_b_id],
            min_org_level: None,
            conflicts_with: vec![],
        };
        let role_b = Role {
            id: role_b_id,
            name: "cycle_b".to_string(),
            permissions: vec![make_permission(
                "file:///b/**",
                &[Operation::Write],
                false,
            )],
            includes: vec![role_a_id],
            min_org_level: None,
            conflicts_with: vec![],
        };
        store.add_role(&role_a).unwrap();
        store.add_role(&role_b).unwrap();

        store
            .assign_role(
                &principal.id,
                &role_a_id,
                RoleAssignmentScope::Global,
                None,
            )
            .unwrap();

        let resolver = RoleResolver::new(&store);
        let perms = resolver
            .resolve_effective_permissions(&principal.id)
            .unwrap();

        // Should get both permissions without infinite loop
        assert_eq!(perms.len(), 2);
    }
}
