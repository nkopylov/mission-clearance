use crate::id::RoleId;
use crate::operation::Operation;
use crate::principal::PrincipalKind;
use crate::resource::ResourcePattern;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::org::OrgLevel;

/// A permission granted by a role -- scoped to a resource pattern and operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolePermission {
    pub resource_pattern: ResourcePattern,
    pub operations: HashSet<Operation>,
    pub delegatable: bool,
    pub delegation_restrictions: Option<DelegationRestriction>,
}

/// Restrictions on how a role permission may be delegated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRestriction {
    pub max_depth: Option<u32>,
    pub allowed_target_types: Option<Vec<PrincipalKind>>,
    pub delegatable_operations: Option<HashSet<Operation>>,
    pub allow_re_delegation: bool,
    pub requires_approval: bool,
}

/// A named bundle of permissions with optional hierarchy and conflict declarations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub permissions: Vec<RolePermission>,
    /// Composite roles: this role includes all permissions from these parent roles.
    pub includes: Vec<RoleId>,
    /// Minimum org level required to hold this role.
    pub min_org_level: Option<OrgLevel>,
    /// Roles that conflict with this one (separation of duties).
    pub conflicts_with: Vec<RoleId>,
}

/// The scope at which a role is assigned to a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoleAssignmentScope {
    /// Role applies globally.
    Global,
    /// Role applies only within a specific team.
    Team,
    /// Role applies only to a specific resource pattern.
    Resource,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_serialize() {
        let role = Role {
            id: RoleId::new(),
            name: "developer".to_string(),
            permissions: vec![],
            includes: vec![],
            min_org_level: None,
            conflicts_with: vec![],
        };
        let json = serde_json::to_string(&role).unwrap();
        let deser: Role = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.name, "developer");
    }

    #[test]
    fn test_role_assignment_scope_variants() {
        let scopes = [
            RoleAssignmentScope::Global,
            RoleAssignmentScope::Team,
            RoleAssignmentScope::Resource,
        ];
        for scope in &scopes {
            let json = serde_json::to_string(scope).unwrap();
            let deser: RoleAssignmentScope = serde_json::from_str(&json).unwrap();
            assert_eq!(&deser, scope);
        }
    }

    #[test]
    fn test_delegation_restriction() {
        let restriction = DelegationRestriction {
            max_depth: Some(3),
            allowed_target_types: Some(vec![PrincipalKind::AiAgent]),
            delegatable_operations: None,
            allow_re_delegation: false,
            requires_approval: true,
        };
        let json = serde_json::to_string(&restriction).unwrap();
        let deser: DelegationRestriction = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.max_depth, Some(3));
        assert!(!deser.allow_re_delegation);
    }
}
