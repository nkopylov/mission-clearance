//! Identity provider integration for Mission Clearance.
//!
//! Resolves external credentials (OIDC JWT, API keys, mission tokens)
//! to internal principals.

pub mod api_key;
pub mod composite;
pub mod mission_token;
pub mod oidc;
pub mod provider;
pub mod scim;
