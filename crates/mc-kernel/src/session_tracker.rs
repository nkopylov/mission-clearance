use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Tracks files written during the current session.
///
/// When a file is written and then later executed in the same session,
/// this is flagged as a potential "write-then-execute" attack pattern
/// (e.g., write a benign-looking script, then execute it with malicious intent).
#[derive(Debug, Clone)]
pub struct SessionTracker {
    written_files: Arc<Mutex<HashSet<String>>>,
}

impl SessionTracker {
    /// Create a new empty session tracker.
    pub fn new() -> Self {
        Self {
            written_files: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Record that a file was written in this session.
    pub fn record_write(&self, path: &str) {
        let normalized = Self::normalize_path(path);
        let mut files = self.written_files.lock().unwrap();
        files.insert(normalized);
    }

    /// Check if a file was written in this session (for execute-after-write detection).
    pub fn was_written_in_session(&self, path: &str) -> bool {
        let normalized = Self::normalize_path(path);
        let files = self.written_files.lock().unwrap();
        files.contains(&normalized)
    }

    /// Check if any of the given paths were written in this session.
    pub fn any_written_in_session(&self, paths: &[&str]) -> bool {
        let files = self.written_files.lock().unwrap();
        paths
            .iter()
            .any(|p| files.contains(&Self::normalize_path(p)))
    }

    /// Extract file paths referenced in a shell command.
    /// Returns paths that could be execution targets.
    pub fn extract_paths_from_command(command: &str, args: &[String]) -> Vec<String> {
        let mut paths = Vec::new();

        // Check if the command itself is a path
        if command.starts_with('/') || command.starts_with("./") || command.starts_with("../") {
            paths.push(command.to_string());
        }

        // Check args for file paths
        for arg in args {
            let trimmed = arg.trim();
            if trimmed.starts_with('/')
                || trimmed.starts_with("./")
                || trimmed.starts_with("../")
            {
                paths.push(trimmed.to_string());
            }
        }

        // For bash -c / sh -c, extract paths from the inline command
        let full_cmd = format!("{} {}", command, args.join(" "));
        let lower = full_cmd.to_lowercase();
        if lower.contains("bash ") || lower.contains("sh ") || lower.contains("python") {
            // Find -c argument and extract paths from it
            for arg in args {
                if arg.starts_with('/') || arg.contains("./") {
                    // Look for path-like strings in the -c argument
                    for word in arg.split_whitespace() {
                        if word.starts_with('/')
                            || word.starts_with("./")
                            || word.starts_with("../")
                        {
                            paths.push(word.to_string());
                        }
                    }
                }
            }
        }

        paths
    }

    /// Normalize a file path for consistent comparison.
    fn normalize_path(path: &str) -> String {
        // Strip file:// prefix if present
        let path = path.strip_prefix("file://").unwrap_or(path);
        // Remove authority part if present (e.g., localhost)
        let path = if let Some(rest) = path.strip_prefix("//") {
            if let Some(idx) = rest.find('/') {
                &rest[idx..]
            } else {
                rest
            }
        } else {
            path
        };
        path.to_string()
    }

    /// Clear all tracked files (e.g., on session reset).
    pub fn clear(&self) {
        let mut files = self.written_files.lock().unwrap();
        files.clear();
    }
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn track_write_then_detect_execute() {
        let tracker = SessionTracker::new();

        tracker.record_write("/tmp/script.sh");
        assert!(tracker.was_written_in_session("/tmp/script.sh"));
        assert!(!tracker.was_written_in_session("/tmp/other.sh"));
    }

    #[test]
    fn track_file_uri_write() {
        let tracker = SessionTracker::new();

        tracker.record_write("file:///tmp/evil.sh");
        assert!(tracker.was_written_in_session("/tmp/evil.sh"));
    }

    #[test]
    fn any_written_checks_multiple() {
        let tracker = SessionTracker::new();

        tracker.record_write("/tmp/a.sh");
        assert!(tracker.any_written_in_session(&["/tmp/b.sh", "/tmp/a.sh"]));
        assert!(!tracker.any_written_in_session(&["/tmp/b.sh", "/tmp/c.sh"]));
    }

    #[test]
    fn extract_paths_from_direct_command() {
        let paths = SessionTracker::extract_paths_from_command(
            "/tmp/script.sh",
            &[],
        );
        assert!(paths.contains(&"/tmp/script.sh".to_string()));
    }

    #[test]
    fn extract_paths_from_args() {
        let paths = SessionTracker::extract_paths_from_command(
            "bash",
            &["/tmp/malicious.sh".to_string()],
        );
        assert!(paths.contains(&"/tmp/malicious.sh".to_string()));
    }

    #[test]
    fn clear_resets_tracker() {
        let tracker = SessionTracker::new();
        tracker.record_write("/tmp/script.sh");
        tracker.clear();
        assert!(!tracker.was_written_in_session("/tmp/script.sh"));
    }
}
