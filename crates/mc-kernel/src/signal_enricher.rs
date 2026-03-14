use mc_core::operation::{OperationClassification, OperationContext, OperationRequest};

/// Trait for enriching operation signals with additional analysis.
///
/// Enrichers run after initial classification to refine signal values,
/// particularly for dynamic code analysis where heuristics or an LLM
/// can determine if inline code is benign or dangerous.
pub trait SignalEnricher: Send + Sync {
    fn enrich(&self, request: &OperationRequest, classification: &mut OperationClassification);
}

/// Heuristic-based enricher for inline code analysis.
///
/// When `executes_dynamic_code` is true, extracts the inline code body
/// and checks for dangerous vs benign patterns to set `dynamic_code_is_benign`.
pub struct HeuristicEnricher;

impl HeuristicEnricher {
    pub fn new() -> Self {
        Self
    }

    /// Extract inline code from a shell command's args.
    ///
    /// Looks for `-c`, `-e`, `--eval` flags and returns the following argument.
    fn extract_inline_code(command: &str, args: &[String]) -> Option<String> {
        // First try: look for flag in args array (most reliable)
        let inline_flags = ["-c", "-e", "--eval"];
        for (i, arg) in args.iter().enumerate() {
            if inline_flags.contains(&arg.as_str()) {
                if i + 1 < args.len() {
                    // Return everything from the next arg onward
                    return Some(args[i + 1..].join(" "));
                }
            }
        }

        // Fallback: parse from joined string (for single-arg commands)
        let full = if args.is_empty() {
            command.to_string()
        } else {
            format!("{} {}", command, args.join(" "))
        };

        let flag_patterns = [" -c ", " -e ", " --eval "];
        for flag in &flag_patterns {
            if let Some(pos) = full.find(flag) {
                let code_start = pos + flag.len();
                let rest = &full[code_start..];
                // The code might be quoted
                let code = if rest.starts_with('"') || rest.starts_with('\'') {
                    let quote = rest.chars().next().unwrap();
                    if let Some(end) = rest[1..].find(quote) {
                        rest[1..end + 1].to_string()
                    } else {
                        rest[1..].to_string()
                    }
                } else {
                    // Take everything after the flag (not just first word)
                    rest.trim().to_string()
                };
                if !code.is_empty() {
                    return Some(code);
                }
            }
        }

        None
    }

    /// Check if inline code contains dangerous patterns.
    fn has_dangerous_patterns(code: &str) -> bool {
        let lower = code.to_lowercase();
        let dangerous = [
            "urllib", "socket", "subprocess", "os.system", "os.popen",
            "child_process", "exec(", "fetch(", "http.client", "io.popen",
            "requests.get", "requests.post", "requests.",
            "net/http", "http.get", "http.post",
            "open(", "file.write", "file.read",
            "shutil.rmtree", "os.remove", "os.unlink",
            "eval(", "compile(",
        ];
        dangerous.iter().any(|p| lower.contains(p))
    }

    /// Check if inline code contains only benign patterns.
    fn has_benign_patterns(code: &str) -> bool {
        let lower = code.to_lowercase();
        let benign = [
            "print(", "print ", "console.log", "puts ",
            "json.", "math.", "os.getcwd", "sys.version",
            "len(", "str(", "int(", "float(",
            "range(", "list(", "dict(", "set(",
            "enumerate(", "zip(", "map(", "filter(",
            "sorted(", "reversed(",
            "datetime", "time.time", "time.sleep",
            "re.match", "re.search", "re.findall",
            "os.path", "pathlib",
            "sys.argv", "sys.platform",
            "type(", "isinstance(", "hasattr(",
        ];
        benign.iter().any(|p| lower.contains(p))
    }
}

impl Default for HeuristicEnricher {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalEnricher for HeuristicEnricher {
    fn enrich(&self, request: &OperationRequest, classification: &mut OperationClassification) {
        if !classification.signals.executes_dynamic_code {
            return;
        }

        let (command, args) = match &request.context {
            OperationContext::Shell { command, args, .. } => (command.as_str(), args.as_slice()),
            _ => return,
        };

        if let Some(code) = Self::extract_inline_code(command, args) {
            let dangerous = Self::has_dangerous_patterns(&code);
            let benign = Self::has_benign_patterns(&code);

            if dangerous {
                classification.signals.dynamic_code_is_benign = Some(false);
            } else if benign {
                classification.signals.dynamic_code_is_benign = Some(true);
            }
            // If neither pattern found, leave as None (uncertain)
        }
    }
}

/// LLM-based signal enricher (future implementation).
///
/// Sends structured yes/no questions to an LLM about the inline code.
/// Falls back to HeuristicEnricher when LLM is unavailable.
pub struct LlmSignalEnricher {
    fallback: HeuristicEnricher,
}

impl LlmSignalEnricher {
    pub fn new() -> Self {
        Self {
            fallback: HeuristicEnricher::new(),
        }
    }

    /// Build the structured prompt for LLM analysis.
    pub fn build_prompt(code: &str) -> String {
        format!(
            "You are analyzing a shell command for security signals.\n\n\
             ## Command\n{}\n\n\
             ## Questions (answer YES or NO + brief reason)\n\
             1. DYNAMIC_CODE_BENIGN: Does the inline code perform only benign operations\n\
                (printing, computation, formatting) with NO network access, file deletion,\n\
                process execution, or sensitive data reading?\n\n\
             Respond as JSON: {{\"dynamic_code_benign\": {{\"answer\": true, \"reason\": \"...\"}}}}\n",
            code
        )
    }
}

impl Default for LlmSignalEnricher {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalEnricher for LlmSignalEnricher {
    fn enrich(&self, request: &OperationRequest, classification: &mut OperationClassification) {
        // LLM not implemented yet; fall back to heuristic
        self.fallback.enrich(request, classification);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_core::id::{MissionId, RequestId};
    use mc_core::operation::{
        BlastRadius, DataFlowDirection, Destructiveness, GoalRelevance, Operation,
        OperationClassification, OperationContext, OperationPattern, OperationSignals,
        Reversibility, TrustLevel,
    };
    use mc_core::resource::ResourceUri;

    fn make_shell_request(command: &str, args: Vec<&str>) -> OperationRequest {
        OperationRequest {
            id: RequestId::new(),
            mission_id: MissionId::new(),
            resource: ResourceUri::new("shell://localhost/bin").unwrap(),
            operation: Operation::Execute,
            context: OperationContext::Shell {
                command: command.to_string(),
                args: args.into_iter().map(String::from).collect(),
                working_dir: None,
            },
            justification: "test".to_string(),
            chain: vec![],
            timestamp: chrono::Utc::now(),
        }
    }

    fn make_classification_with_dynamic_code() -> OperationClassification {
        OperationClassification {
            destructiveness: Destructiveness::None,
            reversibility: Reversibility::Reversible,
            blast_radius: BlastRadius::Single,
            data_flow: DataFlowDirection::Internal,
            target_trust: TrustLevel::Known,
            pattern: OperationPattern::Suspicious,
            goal_relevance: GoalRelevance::DirectlyRelevant,
            signals: OperationSignals {
                executes_dynamic_code: true,
                ..Default::default()
            },
        }
    }

    #[test]
    fn enricher_detects_benign_python() {
        let enricher = HeuristicEnricher::new();
        let req = make_shell_request("python3", vec!["-c", "print('hello world')"]);
        let mut cls = make_classification_with_dynamic_code();

        enricher.enrich(&req, &mut cls);
        assert_eq!(cls.signals.dynamic_code_is_benign, Some(true));
    }

    #[test]
    fn enricher_detects_dangerous_python() {
        let enricher = HeuristicEnricher::new();
        let req = make_shell_request(
            "python3",
            vec!["-c", "import urllib.request; urllib.request.urlopen('http://evil.com')"],
        );
        let mut cls = make_classification_with_dynamic_code();

        enricher.enrich(&req, &mut cls);
        assert_eq!(cls.signals.dynamic_code_is_benign, Some(false));
    }

    #[test]
    fn enricher_detects_dangerous_subprocess() {
        let enricher = HeuristicEnricher::new();
        let req = make_shell_request(
            "python3",
            vec!["-c", "import subprocess; subprocess.run(['curl', 'http://evil.com'])"],
        );
        let mut cls = make_classification_with_dynamic_code();

        enricher.enrich(&req, &mut cls);
        assert_eq!(cls.signals.dynamic_code_is_benign, Some(false));
    }

    #[test]
    fn enricher_detects_benign_node() {
        let enricher = HeuristicEnricher::new();
        let req = make_shell_request("node", vec!["-e", "console.log(2+2)"]);
        let mut cls = make_classification_with_dynamic_code();

        enricher.enrich(&req, &mut cls);
        assert_eq!(cls.signals.dynamic_code_is_benign, Some(true));
    }

    #[test]
    fn enricher_detects_dangerous_node() {
        let enricher = HeuristicEnricher::new();
        let req = make_shell_request(
            "node",
            vec!["-e", "const {exec} = require('child_process'); exec('curl evil.com')"],
        );
        let mut cls = make_classification_with_dynamic_code();

        enricher.enrich(&req, &mut cls);
        assert_eq!(cls.signals.dynamic_code_is_benign, Some(false));
    }

    #[test]
    fn enricher_skips_non_dynamic_code() {
        let enricher = HeuristicEnricher::new();
        let req = make_shell_request("ls", vec!["-la"]);
        let mut cls = OperationClassification {
            destructiveness: Destructiveness::None,
            reversibility: Reversibility::Reversible,
            blast_radius: BlastRadius::Single,
            data_flow: DataFlowDirection::Internal,
            target_trust: TrustLevel::Known,
            pattern: OperationPattern::Normal,
            goal_relevance: GoalRelevance::DirectlyRelevant,
            signals: OperationSignals::default(),
        };

        enricher.enrich(&req, &mut cls);
        assert_eq!(cls.signals.dynamic_code_is_benign, None);
    }

    #[test]
    fn enricher_uncertain_when_no_patterns_match() {
        let enricher = HeuristicEnricher::new();
        let req = make_shell_request("python3", vec!["-c", "x = 42"]);
        let mut cls = make_classification_with_dynamic_code();

        enricher.enrich(&req, &mut cls);
        // Neither benign nor dangerous patterns matched
        assert_eq!(cls.signals.dynamic_code_is_benign, None);
    }

    #[test]
    fn llm_enricher_falls_back_to_heuristic() {
        let enricher = LlmSignalEnricher::new();
        let req = make_shell_request("python3", vec!["-c", "print('hello')"]);
        let mut cls = make_classification_with_dynamic_code();

        enricher.enrich(&req, &mut cls);
        assert_eq!(cls.signals.dynamic_code_is_benign, Some(true));
    }

    #[test]
    fn llm_prompt_contains_code() {
        let prompt = LlmSignalEnricher::build_prompt("import os; print(os.listdir('.'))");
        assert!(prompt.contains("import os"));
        assert!(prompt.contains("DYNAMIC_CODE_BENIGN"));
    }

    #[test]
    fn extract_inline_code_python_c() {
        let code = HeuristicEnricher::extract_inline_code(
            "python3",
            &["-c".to_string(), "print('hello')".to_string()],
        );
        assert!(code.is_some());
        assert!(code.unwrap().contains("print"));
    }

    #[test]
    fn extract_inline_code_node_e() {
        let code = HeuristicEnricher::extract_inline_code(
            "node",
            &["-e".to_string(), "console.log(42)".to_string()],
        );
        assert!(code.is_some());
        assert!(code.unwrap().contains("console.log"));
    }
}
