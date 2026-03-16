use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// Decision from the LLM chain evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainLlmDecision {
    Approve,
    Deny,
    EscalateToHuman,
}

/// Full result from LLM chain evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainLlmResult {
    pub decision: ChainLlmDecision,
    pub reasoning: String,
    pub confidence: f64,
}

/// Configuration for the chain LLM evaluator.
///
/// Builds prompts from a template and caches results. The actual LLM call is
/// NOT performed here -- the calling code (API layer) is responsible for
/// sending the prompt to an LLM and parsing the response.
pub struct ChainLlmEvaluator {
    prompt_template: String,
    cache: RwLock<HashMap<String, ChainLlmResult>>,
}

impl ChainLlmEvaluator {
    /// Create a new evaluator with the given prompt template and an empty cache.
    ///
    /// The template may contain the following placeholders:
    /// `{chain_summary}`, `{operation}`, `{resource}`, `{org_context}`,
    /// `{edge_constraints}`, `{goal_coherence_score}`, `{chain_depth}`,
    /// `{median_depth}`, `{delegation_time_seconds}`.
    pub fn new(prompt_template: String) -> Self {
        Self {
            prompt_template,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Fill in the prompt template with the provided values.
    pub fn build_prompt(
        &self,
        chain_summary: &str,
        operation: &str,
        resource: &str,
        org_context: &str,
        edge_constraints: &str,
        goal_coherence_score: f64,
        chain_depth: u32,
        median_depth: u32,
        delegation_time_seconds: f64,
    ) -> String {
        self.prompt_template
            .replace("{chain_summary}", chain_summary)
            .replace("{operation}", operation)
            .replace("{resource}", resource)
            .replace("{org_context}", org_context)
            .replace("{edge_constraints}", edge_constraints)
            .replace(
                "{goal_coherence_score}",
                &goal_coherence_score.to_string(),
            )
            .replace("{chain_depth}", &chain_depth.to_string())
            .replace("{median_depth}", &median_depth.to_string())
            .replace(
                "{delegation_time_seconds}",
                &delegation_time_seconds.to_string(),
            )
    }

    /// Build a cache key from chain hash, resource pattern, and operation.
    pub fn cache_key(chain_hash: &str, resource_pattern: &str, operation: &str) -> String {
        format!("{chain_hash}:{resource_pattern}:{operation}")
    }

    /// Look up a cached result by key.
    pub fn get_cached(&self, key: &str) -> Option<ChainLlmResult> {
        let cache = self.cache.read().expect("cache lock poisoned");
        cache.get(key).cloned()
    }

    /// Store a result in the cache.
    pub fn cache_result(&self, key: &str, result: ChainLlmResult) {
        let mut cache = self.cache.write().expect("cache lock poisoned");
        cache.insert(key.to_string(), result);
    }

    /// Clear all cached results.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().expect("cache lock poisoned");
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_template() -> String {
        "Chain: {chain_summary}\n\
         Operation: {operation}\n\
         Resource: {resource}\n\
         Org: {org_context}\n\
         Constraints: {edge_constraints}\n\
         Coherence: {goal_coherence_score}\n\
         Depth: {chain_depth}/{median_depth}\n\
         Time: {delegation_time_seconds}s"
            .to_string()
    }

    #[test]
    fn build_prompt_fills_all_placeholders() {
        let evaluator = ChainLlmEvaluator::new(sample_template());
        let prompt = evaluator.build_prompt(
            "alice -> bob -> agent",
            "Write",
            "file:///etc/config",
            "Engineering team",
            "max_depth=3",
            0.85,
            2,
            1,
            120.5,
        );

        assert!(prompt.contains("alice -> bob -> agent"));
        assert!(prompt.contains("Write"));
        assert!(prompt.contains("file:///etc/config"));
        assert!(prompt.contains("Engineering team"));
        assert!(prompt.contains("max_depth=3"));
        assert!(prompt.contains("0.85"));
        assert!(prompt.contains("2"));
        assert!(prompt.contains("1"));
        assert!(prompt.contains("120.5"));
        // Verify no leftover placeholders
        assert!(!prompt.contains("{chain_summary}"));
        assert!(!prompt.contains("{operation}"));
        assert!(!prompt.contains("{resource}"));
        assert!(!prompt.contains("{org_context}"));
        assert!(!prompt.contains("{edge_constraints}"));
        assert!(!prompt.contains("{goal_coherence_score}"));
        assert!(!prompt.contains("{chain_depth}"));
        assert!(!prompt.contains("{median_depth}"));
        assert!(!prompt.contains("{delegation_time_seconds}"));
    }

    #[test]
    fn cache_miss_returns_none() {
        let evaluator = ChainLlmEvaluator::new(String::new());
        assert!(evaluator.get_cached("nonexistent").is_none());
    }

    #[test]
    fn cache_hit_returns_stored_result() {
        let evaluator = ChainLlmEvaluator::new(String::new());
        let key = ChainLlmEvaluator::cache_key("abc123", "file:///**", "Write");
        let result = ChainLlmResult {
            decision: ChainLlmDecision::Approve,
            reasoning: "looks good".to_string(),
            confidence: 0.95,
        };

        evaluator.cache_result(&key, result.clone());
        let cached = evaluator.get_cached(&key).expect("should be cached");

        assert_eq!(cached.decision, ChainLlmDecision::Approve);
        assert_eq!(cached.reasoning, "looks good");
        assert!((cached.confidence - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn clear_cache_removes_all_entries() {
        let evaluator = ChainLlmEvaluator::new(String::new());
        let key1 = ChainLlmEvaluator::cache_key("h1", "file:///**", "Read");
        let key2 = ChainLlmEvaluator::cache_key("h2", "http://api.example.com/*", "Write");

        evaluator.cache_result(
            &key1,
            ChainLlmResult {
                decision: ChainLlmDecision::Approve,
                reasoning: "ok".to_string(),
                confidence: 0.9,
            },
        );
        evaluator.cache_result(
            &key2,
            ChainLlmResult {
                decision: ChainLlmDecision::Deny,
                reasoning: "no".to_string(),
                confidence: 0.8,
            },
        );

        assert!(evaluator.get_cached(&key1).is_some());
        assert!(evaluator.get_cached(&key2).is_some());

        evaluator.clear_cache();

        assert!(evaluator.get_cached(&key1).is_none());
        assert!(evaluator.get_cached(&key2).is_none());
    }

    #[test]
    fn cache_key_format() {
        let key = ChainLlmEvaluator::cache_key("deadbeef", "http://api.com/**", "Execute");
        assert_eq!(key, "deadbeef:http://api.com/**:Execute");
    }

    #[test]
    fn chain_llm_result_serializes() {
        let result = ChainLlmResult {
            decision: ChainLlmDecision::EscalateToHuman,
            reasoning: "uncertain".to_string(),
            confidence: 0.5,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deser: ChainLlmResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.decision, ChainLlmDecision::EscalateToHuman);
        assert_eq!(deser.reasoning, "uncertain");
    }
}
