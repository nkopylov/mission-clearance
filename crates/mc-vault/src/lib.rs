//! AES-256-GCM encrypted credential vault with Argon2id key derivation.
//!
//! Stores secrets bound to resource patterns and supports rotation and
//! revocation. Credentials are only released when policy allows.

pub mod crypto;
pub mod rotation;
pub mod store;
