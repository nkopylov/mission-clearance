use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use mc_core::id::VaultEntryId;
use mc_core::resource::{ResourcePattern, ResourceUri};
use mc_core::vault::{Credential, RotationPolicy, SecretType, VaultEntryMetadata};
use rusqlite::{Connection, params};
use tracing::{debug, info};
use uuid::Uuid;

use crate::crypto;

/// Encrypted credential store backed by SQLite.
///
/// Each credential is individually encrypted with AES-256-GCM. The master key
/// is derived from a passphrase using Argon2id and is held in memory for the
/// lifetime of this struct.
pub struct VaultStore {
    conn: Connection,
    master_key: [u8; 32],
}

impl Drop for VaultStore {
    fn drop(&mut self) {
        crypto::zeroize_key(&mut self.master_key);
    }
}

impl VaultStore {
    /// Open (or create) a vault database at `path`.
    ///
    /// The master encryption key is derived from `passphrase` combined with a
    /// salt that is stored in the database. On first open the salt is generated
    /// and persisted; on subsequent opens the existing salt is loaded.
    pub fn new(path: &str, passphrase: &str) -> Result<Self> {
        let conn = Connection::open(path).context("failed to open vault database")?;
        Self::init_schema(&conn)?;

        let salt = Self::load_or_create_salt(&conn)?;
        let master_key = crypto::derive_key(passphrase, &salt)
            .context("failed to derive master key from passphrase")?;

        info!("vault opened at {path}");
        Ok(Self { conn, master_key })
    }

    /// Initialize the database schema (idempotent).
    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_meta (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entries (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL UNIQUE,
                secret_type     TEXT NOT NULL,
                encrypted_value BLOB NOT NULL,
                bound_to        TEXT NOT NULL,
                rotation_policy TEXT,
                created_at      TEXT NOT NULL,
                last_rotated    TEXT,
                revoked         INTEGER NOT NULL DEFAULT 0
            );",
        )
        .context("failed to initialize vault schema")?;
        Ok(())
    }

    /// Load the existing salt or generate and store a new one.
    fn load_or_create_salt(conn: &Connection) -> Result<Vec<u8>> {
        let mut stmt = conn
            .prepare("SELECT value FROM vault_meta WHERE key = 'salt'")
            .context("failed to prepare salt query")?;

        let salt: Option<Vec<u8>> = stmt
            .query_row([], |row| row.get(0))
            .ok();

        match salt {
            Some(s) => {
                debug!("loaded existing vault salt");
                Ok(s)
            }
            None => {
                let s = crypto::generate_salt();
                conn.execute(
                    "INSERT INTO vault_meta (key, value) VALUES ('salt', ?1)",
                    params![s.as_slice()],
                )
                .context("failed to store vault salt")?;
                debug!("generated and stored new vault salt");
                Ok(s.to_vec())
            }
        }
    }

    /// Add a new credential to the vault.
    ///
    /// The `value` is encrypted before storage. `bound_to` specifies which
    /// resource patterns this credential should be injected for.
    pub fn add(
        &self,
        name: &str,
        secret_type: SecretType,
        value: &str,
        bound_to: HashSet<ResourcePattern>,
    ) -> Result<VaultEntryId> {
        let id = VaultEntryId::new();
        let encrypted = crypto::encrypt(&self.master_key, value.as_bytes())
            .context("failed to encrypt credential value")?;

        let secret_type_json = serde_json::to_string(&secret_type)?;
        let bound_to_json = serde_json::to_string(&bound_to)?;
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT INTO entries (id, name, secret_type, encrypted_value, bound_to, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id.to_string(),
                name,
                secret_type_json,
                encrypted,
                bound_to_json,
                now,
            ],
        ).context("failed to insert vault entry")?;

        info!(entry_id = %id, name, "added credential to vault");
        Ok(id)
    }

    /// Retrieve and decrypt a credential by ID.
    ///
    /// Returns an error if the entry is revoked.
    pub fn get_credential(&self, id: &VaultEntryId) -> Result<Credential> {
        let (secret_type_json, encrypted, revoked): (String, Vec<u8>, bool) = self
            .conn
            .query_row(
                "SELECT secret_type, encrypted_value, revoked FROM entries WHERE id = ?1",
                params![id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i32>(2)? != 0)),
            )
            .context("vault entry not found")?;

        if revoked {
            bail!("credential {id} has been revoked");
        }

        let secret_type: SecretType = serde_json::from_str(&secret_type_json)?;
        let decrypted = crypto::decrypt(&self.master_key, &encrypted)
            .context("failed to decrypt credential")?;
        let value =
            String::from_utf8(decrypted).context("decrypted credential is not valid UTF-8")?;

        Ok(Credential {
            entry_id: *id,
            secret_type,
            value,
        })
    }

    /// Find vault entries whose `bound_to` patterns match the given resource URI.
    pub fn find_for_resource(&self, resource: &ResourceUri) -> Result<Vec<VaultEntryId>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, bound_to FROM entries WHERE revoked = 0")?;

        let rows = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            let bound_to_json: String = row.get(1)?;
            Ok((id_str, bound_to_json))
        })?;

        let mut matches = Vec::new();
        for row in rows {
            let (id_str, bound_to_json) = row?;
            let bound_to: HashSet<ResourcePattern> = serde_json::from_str(&bound_to_json)
                .unwrap_or_default();

            if bound_to.iter().any(|pattern| pattern.matches(resource)) {
                let uuid = Uuid::parse_str(&id_str)
                    .context("invalid UUID in vault entry")?;
                matches.push(VaultEntryId::from_uuid(uuid));
            }
        }

        Ok(matches)
    }

    /// List all vault entries (metadata only, secrets are not decrypted).
    pub fn list(&self) -> Result<Vec<VaultEntryMetadata>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, secret_type, bound_to, rotation_policy,
                    created_at, last_rotated, revoked
             FROM entries",
        )?;

        let rows = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            let name: String = row.get(1)?;
            let secret_type_json: String = row.get(2)?;
            let bound_to_json: String = row.get(3)?;
            let rotation_policy_json: Option<String> = row.get(4)?;
            let created_at_str: String = row.get(5)?;
            let last_rotated_str: Option<String> = row.get(6)?;
            let revoked: i32 = row.get(7)?;
            Ok((
                id_str,
                name,
                secret_type_json,
                bound_to_json,
                rotation_policy_json,
                created_at_str,
                last_rotated_str,
                revoked,
            ))
        })?;

        let mut entries = Vec::new();
        for row in rows {
            let (
                id_str,
                name,
                secret_type_json,
                bound_to_json,
                rotation_policy_json,
                created_at_str,
                last_rotated_str,
                revoked,
            ) = row?;

            let uuid = Uuid::parse_str(&id_str).context("invalid UUID")?;
            let id = VaultEntryId::from_uuid(uuid);
            let secret_type: SecretType = serde_json::from_str(&secret_type_json)?;
            let bound_to: HashSet<ResourcePattern> = serde_json::from_str(&bound_to_json)?;
            let rotation_policy: Option<RotationPolicy> = rotation_policy_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?;
            let created_at: DateTime<Utc> = created_at_str
                .parse()
                .context("invalid created_at timestamp")?;
            let last_rotated: Option<DateTime<Utc>> = last_rotated_str
                .map(|s| s.parse())
                .transpose()
                .context("invalid last_rotated timestamp")?;

            entries.push(VaultEntryMetadata {
                id,
                name,
                secret_type,
                bound_to,
                rotation_policy,
                created_at,
                last_rotated,
                revoked: revoked != 0,
            });
        }

        Ok(entries)
    }

    /// Mark a vault entry as revoked. Revoked entries cannot be retrieved.
    pub fn revoke(&self, id: &VaultEntryId) -> Result<()> {
        let affected = self.conn.execute(
            "UPDATE entries SET revoked = 1 WHERE id = ?1",
            params![id.to_string()],
        )?;

        if affected == 0 {
            bail!("vault entry {id} not found");
        }

        info!(entry_id = %id, "revoked credential");
        Ok(())
    }

    /// Rotate a credential: re-encrypt with a new value and update `last_rotated`.
    pub fn rotate(&self, id: &VaultEntryId, new_value: &str) -> Result<()> {
        // Verify the entry exists and is not revoked.
        let revoked: bool = self
            .conn
            .query_row(
                "SELECT revoked FROM entries WHERE id = ?1",
                params![id.to_string()],
                |row| Ok(row.get::<_, i32>(0)? != 0),
            )
            .context("vault entry not found")?;

        if revoked {
            bail!("cannot rotate revoked credential {id}");
        }

        let encrypted = crypto::encrypt(&self.master_key, new_value.as_bytes())
            .context("failed to encrypt new credential value")?;
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            "UPDATE entries SET encrypted_value = ?1, last_rotated = ?2 WHERE id = ?3",
            params![encrypted, now, id.to_string()],
        )?;

        info!(entry_id = %id, "rotated credential");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_vault() -> VaultStore {
        VaultStore::new(":memory:", "test-passphrase").expect("failed to open in-memory vault")
    }

    fn github_patterns() -> HashSet<ResourcePattern> {
        let mut set = HashSet::new();
        set.insert(ResourcePattern::new("http://api.github.com/**").unwrap());
        set
    }

    #[test]
    fn add_and_retrieve() {
        let vault = temp_vault();
        let id = vault
            .add("github-token", SecretType::BearerToken, "ghp_abc123", github_patterns())
            .unwrap();

        let cred = vault.get_credential(&id).unwrap();
        assert_eq!(cred.value, "ghp_abc123");
        assert_eq!(cred.secret_type, SecretType::BearerToken);
        assert_eq!(cred.entry_id, id);
    }

    #[test]
    fn find_for_resource() {
        let vault = temp_vault();
        let id = vault
            .add("github-token", SecretType::BearerToken, "ghp_abc123", github_patterns())
            .unwrap();

        // Add another entry bound to a different resource.
        let mut aws_patterns = HashSet::new();
        aws_patterns.insert(ResourcePattern::new("http://s3.amazonaws.com/**").unwrap());
        vault
            .add("aws-key", SecretType::ApiKey, "AKIA...", aws_patterns)
            .unwrap();

        let uri = ResourceUri::new("http://api.github.com/repos/myorg/repo1").unwrap();
        let found = vault.find_for_resource(&uri).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], id);

        // An unrelated resource should find nothing.
        let other = ResourceUri::new("http://example.com/api").unwrap();
        let found = vault.find_for_resource(&other).unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn revoke() {
        let vault = temp_vault();
        let id = vault
            .add("revocable", SecretType::ApiKey, "key-123", github_patterns())
            .unwrap();

        vault.revoke(&id).unwrap();

        let result = vault.get_credential(&id);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("revoked"),
        );
    }

    #[test]
    fn list() {
        let vault = temp_vault();
        vault
            .add("entry-a", SecretType::ApiKey, "val-a", github_patterns())
            .unwrap();

        let mut aws = HashSet::new();
        aws.insert(ResourcePattern::new("http://s3.amazonaws.com/**").unwrap());
        vault.add("entry-b", SecretType::Password, "val-b", aws).unwrap();

        let entries = vault.list().unwrap();
        assert_eq!(entries.len(), 2);

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"entry-a"));
        assert!(names.contains(&"entry-b"));

        // Verify metadata fields are populated but no secrets are exposed.
        for entry in &entries {
            assert!(!entry.revoked);
            assert!(entry.rotation_policy.is_none());
        }
    }

    #[test]
    fn rotate() {
        let vault = temp_vault();
        let id = vault
            .add("rotatable", SecretType::ApiKey, "old-value", github_patterns())
            .unwrap();

        vault.rotate(&id, "new-value").unwrap();

        let cred = vault.get_credential(&id).unwrap();
        assert_eq!(cred.value, "new-value");
    }

    #[test]
    fn rotate_revoked_fails() {
        let vault = temp_vault();
        let id = vault
            .add("temp", SecretType::ApiKey, "val", github_patterns())
            .unwrap();
        vault.revoke(&id).unwrap();

        let result = vault.rotate(&id, "new");
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_name_fails() {
        let vault = temp_vault();
        vault
            .add("dup", SecretType::ApiKey, "val1", github_patterns())
            .unwrap();
        let result = vault.add("dup", SecretType::ApiKey, "val2", github_patterns());
        assert!(result.is_err());
    }

    #[test]
    fn find_excludes_revoked() {
        let vault = temp_vault();
        let id = vault
            .add("ghtoken", SecretType::BearerToken, "ghp_xyz", github_patterns())
            .unwrap();
        vault.revoke(&id).unwrap();

        let uri = ResourceUri::new("http://api.github.com/repos/foo/bar").unwrap();
        let found = vault.find_for_resource(&uri).unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn reopen_vault_same_passphrase() {
        // Use a temp file so we can reopen.
        let dir = std::env::temp_dir().join(format!("mc_vault_test_{}", std::process::id()));
        let path = dir.join("vault.db");
        std::fs::create_dir_all(&dir).unwrap();

        let path_str = path.to_str().unwrap();

        let id = {
            let vault = VaultStore::new(path_str, "my-passphrase").unwrap();
            vault
                .add("token", SecretType::BearerToken, "secret-value", github_patterns())
                .unwrap()
        };

        // Reopen with same passphrase.
        {
            let vault = VaultStore::new(path_str, "my-passphrase").unwrap();
            let cred = vault.get_credential(&id).unwrap();
            assert_eq!(cred.value, "secret-value");
        }

        // Reopen with wrong passphrase -- decryption should fail.
        {
            let vault = VaultStore::new(path_str, "wrong-passphrase").unwrap();
            let result = vault.get_credential(&id);
            assert!(result.is_err());
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}
