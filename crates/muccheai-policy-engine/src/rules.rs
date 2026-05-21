//! Policy rule engine for MuccheAI
//!
//! Deterministic, formally verifiable rule evaluation.
//! Default-deny. No ambiguity.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{Datelike, Timelike};
use muccheai_types::ActionProposal;
use serde::{Deserialize, Serialize};

/// Collection of policy rules
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyRules {
    /// Ordered rules (first match wins)
    pub rules: Vec<PolicyRule>,
    /// Default action if no rule matches
    pub default_action: RuleAction,
    /// Rate limit counters: rule_id -> (window_start_minute, count)
    #[serde(skip)]
    pub rate_counters: Mutex<HashMap<String, (u64, u64)>>,
}

impl Clone for PolicyRules {
    fn clone(&self) -> Self {
        let counters = self.rate_counters.lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        Self {
            rules: self.rules.clone(),
            default_action: self.default_action.clone(),
            rate_counters: Mutex::new(counters),
        }
    }
}

impl Default for PolicyRules {
    fn default() -> Self {
        Self {
            rules: vec![],
            default_action: RuleAction::Deny,
            rate_counters: Mutex::new(HashMap::new()),
        }
    }
}

impl PartialEq for PolicyRules {
    fn eq(&self, other: &Self) -> bool {
        self.rules == other.rules && self.default_action == other.default_action
    }
}

impl Eq for PolicyRules {}

impl PolicyRules {
    /// Evaluate a proposal against all rules
    /// Returns the action of the first matching rule, or default_action
    pub fn evaluate(&mut self, proposal: &ActionProposal) -> RuleAction {
        let now_minute = muccheai_types::Timestamp::now().0 / 60_000;
        for rule in &self.rules {
            if rule.matches(proposal) {
                // Check rate limit if applicable
                if let Some(max_per_minute) = rule.conditions.rate_limit() {
                    let mut counters = self.rate_counters.lock().unwrap();
                    let entry = counters.entry(rule.id.clone()).or_insert((now_minute, 0));
                    if entry.0 != now_minute {
                        entry.0 = now_minute;
                        entry.1 = 0;
                    }
                    entry.1 += 1;
                    if entry.1 > max_per_minute {
                        return RuleAction::Deny;
                    }
                }
                return rule.action;
            }
        }
        self.default_action
    }
}

/// A single policy rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule identifier
    pub id: String,
    /// Target tool ID (wildcard "*" matches all)
    pub tool_id: String,
    /// Target method (wildcard "*" matches all)
    pub method: String,
    /// Resource patterns this rule applies to
    pub resource_patterns: Vec<String>,
    /// Action to take when rule matches
    pub action: RuleAction,
    /// Additional conditions
    pub conditions: RuleConditions,
}

/// Action to take when a rule matches
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    /// Allow the action
    Allow,
    /// Deny the action
    Deny,
    /// Escalate to higher approval tier
    Escalate,
}

/// Additional conditions for rule evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleConditions {
    /// Always apply
    Always,
    /// Only during business hours (9-17 local time)
    BusinessHours,
    /// Maximum requests per minute
    RateLimit {
        /// Maximum allowed requests per minute
        max_per_minute: u64,
    },
    /// Requires specific resource pattern match
    ResourceMatches(String),
    /// Compound: all must match
    And(Vec<RuleConditions>),
    /// Compound: any must match
    Or(Vec<RuleConditions>),
}

impl PolicyRule {
    /// Check if this rule matches a proposal
    pub fn matches(&self, proposal: &ActionProposal) -> bool {
        // Tool ID match
        if self.tool_id != "*" && self.tool_id != proposal.tool_id {
            return false;
        }

        // Method match
        if self.method != "*" && self.method != proposal.method {
            return false;
        }

        // Resource pattern match
        let resource = extract_resource(proposal);
        if !self.resource_patterns.iter().any(|p| match_pattern(p, resource)) {
            return false;
        }

        // Conditions match
        self.conditions.evaluate(proposal)
    }
}

impl RuleConditions {
    /// Evaluate conditions against a proposal
    pub fn evaluate(&self, proposal: &ActionProposal) -> bool {
        match self {
            RuleConditions::Always => true,
            RuleConditions::BusinessHours => {
                let now = chrono::Local::now();
                let weekday = now.weekday();
                let hour = now.hour();
                let is_weekday = matches!(weekday, chrono::Weekday::Mon | chrono::Weekday::Tue | chrono::Weekday::Wed | chrono::Weekday::Thu | chrono::Weekday::Fri);
                let is_business_hours = hour >= 9 && hour < 17;
                is_weekday && is_business_hours
            }
            RuleConditions::RateLimit { .. } => {
                // Rate limit is enforced at the PolicyRules level
                true
            }
            RuleConditions::ResourceMatches(pattern) => {
                let resource = extract_resource(proposal);
                match_pattern(pattern, resource)
            }
            RuleConditions::And(conds) => {
                conds.iter().all(|c| c.evaluate(proposal))
            }
            RuleConditions::Or(conds) => {
                conds.iter().any(|c| c.evaluate(proposal))
            }
        }
    }

    /// Extract the rate limit value from this condition, if any
    pub fn rate_limit(&self) -> Option<u64> {
        match self {
            RuleConditions::RateLimit { max_per_minute } => Some(*max_per_minute),
            RuleConditions::And(conds) => conds.iter().find_map(|c| c.rate_limit()),
            RuleConditions::Or(conds) => conds.iter().find_map(|c| c.rate_limit()),
            _ => None,
        }
    }
}

impl RuleAction {
    /// Convert to string for logging
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleAction::Allow => "allow",
            RuleAction::Deny => "deny",
            RuleAction::Escalate => "escalate",
        }
    }
}

/// Extract the resource identifier from a proposal
fn extract_resource(proposal: &ActionProposal) -> &str {
    proposal.params.get("resource")
        .and_then(|v| v.as_str())
        .or_else(|| proposal.params.get("path").and_then(|v| v.as_str()))
        .or_else(|| proposal.params.get("to").and_then(|v| v.as_str()))
        .unwrap_or(proposal.tool_id.as_str())
}

/// Match a glob pattern against a resource string.
/// Supports `*` (any suffix), `?` (single char), and `**` (recursive).
fn match_pattern(pattern: &str, resource: &str) -> bool {
    const MAX_PATTERN_LEN: usize = 4096;
    const MAX_RESOURCE_LEN: usize = 4096;
    if pattern.len() > MAX_PATTERN_LEN || resource.len() > MAX_RESOURCE_LEN {
        return false;
    }
    if pattern == "**" || pattern == resource {
        return true;
    }
    if pattern.ends_with("**") {
        let prefix = &pattern[..pattern.len() - 2];
        return resource.starts_with(prefix);
    }
    if pattern.ends_with('*') && !pattern.ends_with("**") {
        let prefix = &pattern[..pattern.len() - 1];
        return resource.starts_with(prefix);
    }
    // Handle ** in the middle (e.g., inbox/**/sent)
    if pattern.contains("**") {
        let parts: Vec<&str> = pattern.split("**").collect();
        if parts.len() == 2 {
            return resource.starts_with(parts[0]) && resource.ends_with(parts[1]);
        }
    }
    // Simple ? wildcard support
    if pattern.len() == resource.len() {
        return pattern.chars().zip(resource.chars()).all(|(p, r)| p == '?' || p == r);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proposal(tool: &str, method: &str) -> ActionProposal {
        ActionProposal {
            tool_id: tool.to_string(),
            method: method.to_string(),
            params: serde_json::json!({}),
            requester_pubkey: [0u8; 32].to_vec(),
            timestamp: muccheai_types::Timestamp::now(),
            nonce: [0u8; 32].to_vec(),
        }
    }

    #[test]
    fn test_exact_match() {
        let rule = PolicyRule {
            id: "r1".to_string(),
            tool_id: "email".to_string(),
            method: "send".to_string(),
            resource_patterns: vec!["*".to_string()],
            action: RuleAction::Allow,
            conditions: RuleConditions::Always,
        };

        assert!(rule.matches(&make_proposal("email", "send")));
        assert!(!rule.matches(&make_proposal("email", "read")));
        assert!(!rule.matches(&make_proposal("calendar", "send")));
    }

    #[test]
    fn test_wildcard_match() {
        let rule = PolicyRule {
            id: "r1".to_string(),
            tool_id: "*".to_string(),
            method: "*".to_string(),
            resource_patterns: vec!["*".to_string()],
            action: RuleAction::Allow,
            conditions: RuleConditions::Always,
        };

        assert!(rule.matches(&make_proposal("anything", "anything")));
    }

    #[test]
    fn test_default_deny() {
        let mut rules = PolicyRules {
            rules: vec![],
            default_action: RuleAction::Deny,
            ..Default::default()
        };

        assert_eq!(rules.evaluate(&make_proposal("x", "y")), RuleAction::Deny);
    }

    #[test]
    fn test_resource_pattern_matching() {
        let rule = PolicyRule {
            id: "r1".to_string(),
            tool_id: "email".to_string(),
            method: "send".to_string(),
            resource_patterns: vec!["inbox/**".to_string(), "drafts/*".to_string()],
            action: RuleAction::Allow,
            conditions: RuleConditions::Always,
        };

        let mut proposal = make_proposal("email", "send");
        proposal.params = serde_json::json!({"path": "inbox/work"});
        assert!(rule.matches(&proposal));

        proposal.params = serde_json::json!({"path": "drafts/123"});
        assert!(rule.matches(&proposal));

        proposal.params = serde_json::json!({"path": "sent/123"});
        assert!(!rule.matches(&proposal));
    }
}
