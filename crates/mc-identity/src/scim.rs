/// SCIM sync for org chart from external directory.
///
/// Will be used to sync org positions, teams, and group memberships
/// from SCIM-compatible identity providers (Okta, Azure AD, etc.).
pub struct ScimSync;

impl ScimSync {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ScimSync {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scim_sync_constructible() {
        let _sync = ScimSync::new();
        let _default = ScimSync::default();
    }
}
