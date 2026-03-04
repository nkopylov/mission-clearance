use crate::id::CapabilityId;
use crate::operation::Operation;
use crate::resource::ResourcePattern;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Rate/time constraints on a capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    /// Maximum operations per window.
    pub max_rate: Option<u32>,
    /// Window duration in seconds.
    pub rate_window_secs: Option<u64>,
    /// Absolute expiry time.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for Constraints {
    fn default() -> Self {
        Self {
            max_rate: None,
            rate_window_secs: None,
            expires_at: None,
        }
    }
}

/// A bounded permission over a resource -- like a file descriptor.
///
/// Grants specific operations on a specific resource scope,
/// optionally with rate/time constraints and delegation rights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: CapabilityId,
    pub resource_pattern: ResourcePattern,
    pub operations: HashSet<Operation>,
    pub constraints: Constraints,
    pub delegatable: bool,
}

impl Capability {
    /// Check if this capability covers the given resource and operation.
    pub fn covers(&self, resource: &crate::resource::ResourceUri, op: &Operation) -> bool {
        self.operations.contains(op) && self.resource_pattern.matches(resource)
    }

    /// Check if a proposed child capability is a valid narrowing of this one.
    ///
    /// Validates three conditions:
    /// 1. This capability must be delegatable.
    /// 2. Child operations must be a subset of parent operations.
    /// 3. Child resource pattern must be a subset (narrower or equal) of parent pattern.
    pub fn can_delegate_to(&self, child: &Capability) -> bool {
        if !self.delegatable {
            return false;
        }
        // Child operations must be a subset
        if !child.operations.is_subset(&self.operations) {
            return false;
        }
        // Child resource pattern must be a subset (narrower or equal)
        child.resource_pattern.is_subset_of(&self.resource_pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{ResourcePattern, ResourceUri};

    fn make_cap(pattern: &str, ops: &[Operation], delegatable: bool) -> Capability {
        Capability {
            id: CapabilityId::new(),
            resource_pattern: ResourcePattern::new(pattern).unwrap(),
            operations: ops.iter().cloned().collect(),
            constraints: Constraints::default(),
            delegatable,
        }
    }

    #[test]
    fn test_covers_matching() {
        let cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let uri = ResourceUri::new("http://api.com/repos/foo").unwrap();
        assert!(cap.covers(&uri, &Operation::Read));
    }

    #[test]
    fn test_covers_wrong_operation() {
        let cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let uri = ResourceUri::new("http://api.com/repos/foo").unwrap();
        assert!(!cap.covers(&uri, &Operation::Write));
    }

    #[test]
    fn test_covers_wrong_resource() {
        let cap = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let uri = ResourceUri::new("http://api.com/users/foo").unwrap();
        assert!(!cap.covers(&uri, &Operation::Read));
    }

    #[test]
    fn test_delegation_valid_narrowing() {
        let parent = make_cap(
            "http://api.com/repos/*",
            &[Operation::Read, Operation::Write],
            true,
        );
        let child = make_cap("http://api.com/repos/foo", &[Operation::Read], true);
        assert!(parent.can_delegate_to(&child));
    }

    #[test]
    fn test_delegation_same_scope() {
        let parent = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let child = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        assert!(parent.can_delegate_to(&child));
    }

    #[test]
    fn test_delegation_rejects_broadening() {
        let parent = make_cap("http://api.com/repos/foo", &[Operation::Read], true);
        let child = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        assert!(!parent.can_delegate_to(&child));
    }

    #[test]
    fn test_delegation_rejects_extra_operations() {
        let parent = make_cap("http://api.com/repos/*", &[Operation::Read], true);
        let child = make_cap(
            "http://api.com/repos/foo",
            &[Operation::Read, Operation::Write],
            true,
        );
        assert!(!parent.can_delegate_to(&child));
    }

    #[test]
    fn test_delegation_rejects_non_delegatable() {
        let parent = make_cap("http://api.com/**", &[Operation::Read], false);
        let child = make_cap("http://api.com/repos/foo", &[Operation::Read], true);
        assert!(!parent.can_delegate_to(&child));
    }
}
