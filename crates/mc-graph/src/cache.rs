use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Cached result of a chain verification.
#[derive(Debug, Clone)]
pub struct CachedChainResult {
    pub verified: bool,
    pub root_principal_id: Option<String>,
}

/// A simple versioned cache for chain verification results.
///
/// Stores results keyed by mission ID. Each entry is stamped with the
/// cache version at insertion time. When the cache is invalidated (via
/// `invalidate()`), the version counter is bumped, causing all previous
/// entries to be treated as stale.
pub struct PermissionCache {
    version: AtomicU64,
    chain_cache: RwLock<HashMap<String, (u64, CachedChainResult)>>,
}

impl PermissionCache {
    /// Create a new empty cache at version 0.
    pub fn new() -> Self {
        Self {
            version: AtomicU64::new(0),
            chain_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Look up a cached chain result by mission ID.
    ///
    /// Returns `Some` only if the entry exists and was stored at the current
    /// version. Stale entries (from a previous version) are ignored.
    pub fn get(&self, mission_id: &str) -> Option<CachedChainResult> {
        let current_version = self.version.load(Ordering::Acquire);
        let cache = self.chain_cache.read().ok()?;
        if let Some((entry_version, result)) = cache.get(mission_id) {
            if *entry_version == current_version {
                return Some(result.clone());
            }
        }
        None
    }

    /// Store a chain result for the given mission ID at the current version.
    pub fn put(&self, mission_id: &str, result: CachedChainResult) {
        let current_version = self.version.load(Ordering::Acquire);
        if let Ok(mut cache) = self.chain_cache.write() {
            cache.insert(mission_id.to_string(), (current_version, result));
        }
    }

    /// Invalidate all cache entries by bumping the version counter.
    ///
    /// Existing entries remain in memory but will not be returned by `get()`
    /// because their version will no longer match.
    pub fn invalidate(&self) {
        self.version.fetch_add(1, Ordering::Release);
    }

    /// Return the current cache version.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }
}

impl Default for PermissionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_miss_returns_none() {
        let cache = PermissionCache::new();
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_cache_hit_returns_result() {
        let cache = PermissionCache::new();
        cache.put(
            "mission-1",
            CachedChainResult {
                verified: true,
                root_principal_id: Some("principal-abc".to_string()),
            },
        );

        let result = cache.get("mission-1");
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.verified);
        assert_eq!(result.root_principal_id.as_deref(), Some("principal-abc"));
    }

    #[test]
    fn test_invalidate_clears_cache() {
        let cache = PermissionCache::new();
        assert_eq!(cache.version(), 0);

        cache.put(
            "mission-1",
            CachedChainResult {
                verified: true,
                root_principal_id: Some("p-1".to_string()),
            },
        );

        // Entry is accessible before invalidation
        assert!(cache.get("mission-1").is_some());

        // Invalidate bumps the version
        cache.invalidate();
        assert_eq!(cache.version(), 1);

        // Previously cached entry is now stale
        assert!(cache.get("mission-1").is_none());
    }

    #[test]
    fn test_put_after_invalidate_works() {
        let cache = PermissionCache::new();
        cache.put(
            "mission-1",
            CachedChainResult {
                verified: true,
                root_principal_id: None,
            },
        );

        cache.invalidate();
        assert!(cache.get("mission-1").is_none());

        // Put a new entry at the new version
        cache.put(
            "mission-1",
            CachedChainResult {
                verified: false,
                root_principal_id: None,
            },
        );

        let result = cache.get("mission-1").unwrap();
        assert!(!result.verified);
    }

    #[test]
    fn test_multiple_invalidations() {
        let cache = PermissionCache::new();
        cache.invalidate();
        cache.invalidate();
        cache.invalidate();
        assert_eq!(cache.version(), 3);

        cache.put(
            "m",
            CachedChainResult {
                verified: true,
                root_principal_id: None,
            },
        );
        assert!(cache.get("m").is_some());

        cache.invalidate();
        assert_eq!(cache.version(), 4);
        assert!(cache.get("m").is_none());
    }

    #[test]
    fn test_different_missions_independent() {
        let cache = PermissionCache::new();
        cache.put(
            "a",
            CachedChainResult {
                verified: true,
                root_principal_id: Some("p1".to_string()),
            },
        );
        cache.put(
            "b",
            CachedChainResult {
                verified: false,
                root_principal_id: None,
            },
        );

        let a = cache.get("a").unwrap();
        assert!(a.verified);

        let b = cache.get("b").unwrap();
        assert!(!b.verified);
    }
}
