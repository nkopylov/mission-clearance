use sha2::{Digest, Sha256};
use std::collections::HashSet;
use zeroize::Zeroizing;

/// Tracks tainted values from the vault for exfiltration prevention.
///
/// When a vault credential is accessed, the value is registered as tainted.
/// Before any outbound operation, the taint tracker checks whether the
/// request content contains any tainted value, preventing secret exfiltration.
///
/// Secret values are wrapped in [`Zeroizing`] so that their memory is
/// overwritten with zeros when they are removed or when the tracker is dropped,
/// mitigating the risk of secrets lingering in heap memory.
pub struct TaintTracker {
    /// SHA-256 hashes of tainted values (for identification/logging).
    tainted_hashes: HashSet<String>,
    /// The actual tainted values, stored for substring matching.
    /// Wrapped in `Zeroizing` to ensure secrets are cleared from memory on drop.
    tainted_values: Vec<Zeroizing<String>>,
}

impl TaintTracker {
    /// Create a new empty taint tracker.
    pub fn new() -> Self {
        Self {
            tainted_hashes: HashSet::new(),
            tainted_values: Vec::new(),
        }
    }

    /// Register a value as tainted (called when a vault credential is accessed).
    ///
    /// Stores a SHA-256 hash for identification and the value itself (wrapped
    /// in a zeroizing container) for substring matching during content checks.
    pub fn register_taint(&mut self, value: &str) {
        let hash = Self::hash_value(value);
        self.tainted_hashes.insert(hash);
        // Avoid duplicates while keeping zeroization guarantees.
        if !self.tainted_values.iter().any(|v| v.as_str() == value) {
            self.tainted_values.push(Zeroizing::new(value.to_string()));
        }
    }

    /// Check if any tainted value appears as a substring of the given content.
    ///
    /// Returns `true` if taint is detected, meaning the content contains
    /// at least one registered secret.
    pub fn check_taint(&self, content: &str) -> bool {
        for value in &self.tainted_values {
            if content.contains(value.as_str()) {
                return true;
            }
        }
        false
    }

    /// Register a derived taint -- when a tainted value is transformed
    /// (e.g., base64-encoded), the derived form should also be tracked.
    pub fn register_derived_taint(&mut self, derived_value: &str) {
        let hash = Self::hash_value(derived_value);
        self.tainted_hashes.insert(hash);
        if !self
            .tainted_values
            .iter()
            .any(|v| v.as_str() == derived_value)
        {
            self.tainted_values
                .push(Zeroizing::new(derived_value.to_string()));
        }
    }

    /// Return the set of tainted value hashes (for logging/auditing).
    pub fn tainted_hashes(&self) -> &HashSet<String> {
        &self.tainted_hashes
    }

    /// Return the number of tracked tainted values.
    pub fn taint_count(&self) -> usize {
        self.tainted_values.len()
    }

    /// Compute SHA-256 hash of a value.
    fn hash_value(value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl Default for TaintTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_detect() {
        let mut tracker = TaintTracker::new();
        tracker.register_taint("super-secret-api-key-12345");

        assert!(tracker.check_taint("Authorization: Bearer super-secret-api-key-12345"));
    }

    #[test]
    fn no_false_positive() {
        let mut tracker = TaintTracker::new();
        tracker.register_taint("my-secret-value");

        assert!(!tracker.check_taint("This content has nothing sensitive in it."));
    }

    #[test]
    fn derived_taint() {
        let mut tracker = TaintTracker::new();
        tracker.register_taint("original-secret");
        tracker.register_derived_taint("b3JpZ2luYWwtc2VjcmV0"); // base64 of "original-secret"

        assert!(tracker.check_taint("data: b3JpZ2luYWwtc2VjcmV0"));
    }

    #[test]
    fn multiple_tainted_values() {
        let mut tracker = TaintTracker::new();
        tracker.register_taint("secret-one");
        tracker.register_taint("secret-two");
        tracker.register_taint("secret-three");

        assert!(tracker.check_taint("Found secret-two in output"));
        assert!(tracker.check_taint("Also found secret-one here"));
        assert!(!tracker.check_taint("No secrets here at all"));
    }

    #[test]
    fn partial_match_detects() {
        let mut tracker = TaintTracker::new();
        tracker.register_taint("secret123");

        // Tainted value found as substring in larger string
        assert!(tracker.check_taint("my-secret123-key"));
    }

    #[test]
    fn empty_tracker_no_taint() {
        let tracker = TaintTracker::new();
        assert!(!tracker.check_taint("anything at all"));
    }

    #[test]
    fn hash_stored_on_register() {
        let mut tracker = TaintTracker::new();
        tracker.register_taint("test-value");

        assert_eq!(tracker.tainted_hashes().len(), 1);
        assert_eq!(tracker.taint_count(), 1);
    }

    #[test]
    fn derived_taint_adds_separate_hash() {
        let mut tracker = TaintTracker::new();
        tracker.register_taint("original");
        tracker.register_derived_taint("derived");

        assert_eq!(tracker.tainted_hashes().len(), 2);
        assert_eq!(tracker.taint_count(), 2);
    }

    #[test]
    fn default_creates_empty() {
        let tracker = TaintTracker::default();
        assert_eq!(tracker.taint_count(), 0);
        assert!(!tracker.check_taint("test"));
    }

    #[test]
    fn duplicate_register_does_not_increase_count() {
        let mut tracker = TaintTracker::new();
        tracker.register_taint("same-secret");
        tracker.register_taint("same-secret");

        assert_eq!(tracker.taint_count(), 1);
    }

    #[test]
    fn duplicate_derived_does_not_increase_count() {
        let mut tracker = TaintTracker::new();
        tracker.register_derived_taint("derived-val");
        tracker.register_derived_taint("derived-val");

        assert_eq!(tracker.taint_count(), 1);
    }
}
