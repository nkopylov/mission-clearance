use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ResourceError {
    #[error("invalid resource URI: {0}")]
    InvalidUri(String),
    #[error("invalid resource pattern: {0}")]
    InvalidPattern(String),
}

/// A concrete resource URI like `http://api.github.com/repos/myorg/repo1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceUri(String);

/// A resource pattern with optional wildcards like `http://api.github.com/repos/myorg/*`.
///
/// Supports `*` for single-segment wildcards and `**` for any-depth wildcards.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourcePattern(String);

impl ResourceUri {
    pub fn new(uri: &str) -> Result<Self, ResourceError> {
        if uri.is_empty() {
            return Err(ResourceError::InvalidUri("empty URI".into()));
        }
        // Must have a scheme
        if !uri.contains("://") {
            return Err(ResourceError::InvalidUri(format!("missing scheme: {uri}")));
        }
        Ok(Self(uri.to_string()))
    }

    pub fn scheme(&self) -> &str {
        self.0.split("://").next().unwrap_or("")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ResourcePattern {
    pub fn new(pattern: &str) -> Result<Self, ResourceError> {
        if pattern.is_empty() {
            return Err(ResourceError::InvalidPattern("empty pattern".into()));
        }
        if !pattern.contains("://") {
            return Err(ResourceError::InvalidPattern(format!(
                "missing scheme: {pattern}"
            )));
        }
        Ok(Self(pattern.to_string()))
    }

    /// Check if a concrete `ResourceUri` matches this pattern.
    ///
    /// Supports `*` as a wildcard for a single path segment and `**` for any depth.
    pub fn matches(&self, uri: &ResourceUri) -> bool {
        let pattern = &self.0;
        let target = uri.as_str();

        // Split into scheme + rest
        let (pat_scheme, pat_path) = match pattern.split_once("://") {
            Some(parts) => parts,
            None => return false,
        };
        let (uri_scheme, uri_path) = match target.split_once("://") {
            Some(parts) => parts,
            None => return false,
        };

        if pat_scheme != uri_scheme {
            return false;
        }

        let pat_segments: Vec<&str> = pat_path.split('/').collect();
        let uri_segments: Vec<&str> = uri_path.split('/').collect();

        Self::match_segments(&pat_segments, &uri_segments)
    }

    fn match_segments(pattern: &[&str], target: &[&str]) -> bool {
        if pattern.is_empty() && target.is_empty() {
            return true;
        }
        if pattern.is_empty() {
            return false;
        }

        if pattern[0] == "**" {
            // ** matches zero or more segments
            for i in 0..=target.len() {
                if Self::match_segments(&pattern[1..], &target[i..]) {
                    return true;
                }
            }
            return false;
        }

        if target.is_empty() {
            return false;
        }

        if pattern[0] == "*" || pattern[0] == target[0] {
            return Self::match_segments(&pattern[1..], &target[1..]);
        }

        false
    }

    /// Check if this pattern is a subset of (narrower than or equal to) another pattern.
    ///
    /// Used for delegation validation -- child patterns must be subsets of parent patterns.
    /// A pattern A is a subset of B if every URI matching A also matches B.
    pub fn is_subset_of(&self, parent: &ResourcePattern) -> bool {
        let (self_scheme, self_path) = match self.0.split_once("://") {
            Some(parts) => parts,
            None => return false,
        };
        let (parent_scheme, parent_path) = match parent.0.split_once("://") {
            Some(parts) => parts,
            None => return false,
        };

        if self_scheme != parent_scheme {
            return false;
        }

        let self_segs: Vec<&str> = self_path.split('/').collect();
        let parent_segs: Vec<&str> = parent_path.split('/').collect();

        Self::subset_segments(&self_segs, &parent_segs)
    }

    fn subset_segments(child: &[&str], parent: &[&str]) -> bool {
        // If parent is empty, child must also be empty
        if parent.is_empty() {
            return child.is_empty();
        }

        // Parent ** matches anything -- child is always a subset
        if parent[0] == "**" {
            return true;
        }

        if child.is_empty() {
            return false;
        }

        // If child has **, it can match anything -- only subset if parent also has **
        if child[0] == "**" {
            return parent[0] == "**";
        }

        // Child * is subset of parent * or parent **
        if child[0] == "*" {
            if parent[0] == "*" || parent[0] == "**" {
                return Self::subset_segments(&child[1..], &parent[1..]);
            }
            return false;
        }

        // Child is literal
        if parent[0] == "*" || parent[0] == child[0] {
            return Self::subset_segments(&child[1..], &parent[1..]);
        }

        false
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for ResourcePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_uri_valid() {
        let uri = ResourceUri::new("http://api.github.com/repos/myorg/repo1").unwrap();
        assert_eq!(uri.scheme(), "http");
        assert_eq!(uri.as_str(), "http://api.github.com/repos/myorg/repo1");
    }

    #[test]
    fn test_resource_uri_invalid() {
        assert!(ResourceUri::new("").is_err());
        assert!(ResourceUri::new("no-scheme").is_err());
    }

    #[test]
    fn test_pattern_exact_match() {
        let pattern =
            ResourcePattern::new("http://api.github.com/repos/myorg/repo1").unwrap();
        let uri = ResourceUri::new("http://api.github.com/repos/myorg/repo1").unwrap();
        assert!(pattern.matches(&uri));
    }

    #[test]
    fn test_pattern_exact_mismatch() {
        let pattern =
            ResourcePattern::new("http://api.github.com/repos/myorg/repo1").unwrap();
        let uri = ResourceUri::new("http://api.github.com/repos/myorg/repo2").unwrap();
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn test_pattern_wildcard_single() {
        let pattern = ResourcePattern::new("http://api.github.com/repos/myorg/*").unwrap();
        let uri1 = ResourceUri::new("http://api.github.com/repos/myorg/repo1").unwrap();
        let uri2 = ResourceUri::new("http://api.github.com/repos/myorg/repo2").unwrap();
        let uri3 = ResourceUri::new("http://api.github.com/repos/other/repo1").unwrap();
        assert!(pattern.matches(&uri1));
        assert!(pattern.matches(&uri2));
        assert!(!pattern.matches(&uri3));
    }

    #[test]
    fn test_pattern_wildcard_single_does_not_cross_segments() {
        let pattern = ResourcePattern::new("http://api.github.com/repos/*").unwrap();
        let uri = ResourceUri::new("http://api.github.com/repos/myorg/repo1").unwrap();
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn test_pattern_wildcard_deep() {
        let pattern = ResourcePattern::new("http://api.github.com/**").unwrap();
        let uri1 = ResourceUri::new("http://api.github.com/repos/myorg/repo1").unwrap();
        let uri2 = ResourceUri::new("http://api.github.com/users").unwrap();
        assert!(pattern.matches(&uri1));
        assert!(pattern.matches(&uri2));
    }

    #[test]
    fn test_pattern_scheme_mismatch() {
        let pattern = ResourcePattern::new("https://api.github.com/**").unwrap();
        let uri = ResourceUri::new("http://api.github.com/repos").unwrap();
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn test_subset_exact_of_wildcard() {
        let child = ResourcePattern::new("http://a.com/x/y").unwrap();
        let parent = ResourcePattern::new("http://a.com/x/*").unwrap();
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn test_subset_wildcard_of_doublestar() {
        let child = ResourcePattern::new("http://a.com/x/*").unwrap();
        let parent = ResourcePattern::new("http://a.com/**").unwrap();
        assert!(child.is_subset_of(&parent));
    }

    #[test]
    fn test_subset_doublestar_not_of_wildcard() {
        let child = ResourcePattern::new("http://a.com/**").unwrap();
        let parent = ResourcePattern::new("http://a.com/x/*").unwrap();
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn test_subset_same_pattern() {
        let a = ResourcePattern::new("http://a.com/x/*").unwrap();
        let b = ResourcePattern::new("http://a.com/x/*").unwrap();
        assert!(a.is_subset_of(&b));
    }

    #[test]
    fn test_subset_scheme_mismatch() {
        let child = ResourcePattern::new("http://a.com/x/y").unwrap();
        let parent = ResourcePattern::new("https://a.com/x/*").unwrap();
        assert!(!child.is_subset_of(&parent));
    }

    #[test]
    fn test_display() {
        let uri = ResourceUri::new("http://example.com/path").unwrap();
        assert_eq!(format!("{uri}"), "http://example.com/path");

        let pattern = ResourcePattern::new("http://example.com/**").unwrap();
        assert_eq!(format!("{pattern}"), "http://example.com/**");
    }
}
