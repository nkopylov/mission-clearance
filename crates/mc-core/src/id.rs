use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

define_id!(MissionId);
define_id!(CapabilityId);
define_id!(RequestId);
define_id!(PolicyId);
define_id!(VaultEntryId);
define_id!(EventId);
define_id!(MissionToken);

// Permission graph IDs
define_id!(PrincipalId);
define_id!(RoleId);
define_id!(TeamId);
define_id!(OrgPositionId);
define_id!(RoleAssignmentId);
define_id!(DelegationEdgeId);
define_id!(GrantId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_uniqueness() {
        let a = MissionId::new();
        let b = MissionId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn test_id_from_uuid() {
        let uuid = Uuid::new_v4();
        let id = MissionId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), &uuid);
    }

    #[test]
    fn test_id_display() {
        let uuid = Uuid::new_v4();
        let id = MissionId::from_uuid(uuid);
        assert_eq!(format!("{id}"), format!("{uuid}"));
    }

    #[test]
    fn test_id_default() {
        let id = MissionId::default();
        // Default creates a new v4 UUID, so it should be valid
        assert_ne!(id.as_uuid().to_string(), "");
    }

    #[test]
    fn test_id_clone_eq() {
        let id = CapabilityId::new();
        let cloned = id;
        assert_eq!(id, cloned);
    }

    #[test]
    fn test_id_serialize_deserialize() {
        let id = RequestId::new();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: RequestId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deserialized);
    }

    #[test]
    fn test_all_id_types_exist() {
        // Verify all ID types can be constructed
        let _ = MissionId::new();
        let _ = CapabilityId::new();
        let _ = RequestId::new();
        let _ = PolicyId::new();
        let _ = VaultEntryId::new();
        let _ = EventId::new();
        let _ = MissionToken::new();
        // Permission graph IDs
        let _ = PrincipalId::new();
        let _ = RoleId::new();
        let _ = TeamId::new();
        let _ = OrgPositionId::new();
        let _ = RoleAssignmentId::new();
        let _ = DelegationEdgeId::new();
        let _ = GrantId::new();
    }
}
