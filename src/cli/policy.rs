//! Policy management command implementation.

use muccheai_policy_engine::rules::{PolicyRule, RuleAction, RuleConditions};

/// List active policy rules.
pub fn policy_list() {
    let config = match crate::config::MuccheConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            return;
        }
    };
    if config.policy_rules.rules.is_empty() {
        println!("No policy rules configured.");
        return;
    }
    println!("Active policy rules:");
    for r in &config.policy_rules.rules {
        println!(
            "  {}: {}.{} → {:?}",
            r.id, r.tool_id, r.method, r.action
        );
    }
}

/// Add a new policy rule.
pub fn policy_add(id: &str, tool: &str, method: &str, action: &str) {
    let action_enum = match action.to_lowercase().as_str() {
        "allow" => RuleAction::Allow,
        "deny" => RuleAction::Deny,
        "escalate" => RuleAction::Escalate,
        _ => {
            eprintln!("Invalid action '{}'. Use allow, deny, or escalate.", action);
            return;
        }
    };

    let mut config = match crate::config::MuccheConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            return;
        }
    };

    // Prevent duplicate IDs.
    if config.policy_rules.rules.iter().any(|r| r.id == id) {
        eprintln!("Rule with id '{}' already exists.", id);
        return;
    }

    config.policy_rules.rules.push(PolicyRule {
        id: id.to_string(),
        tool_id: tool.to_string(),
        method: method.to_string(),
        resource_patterns: vec!["*".to_string()],
        action: action_enum,
        conditions: RuleConditions::Always,
    });

    if let Err(e) = config.save() {
        eprintln!("Failed to save config: {}", e);
        return;
    }

    println!("Added rule: {} ({}.{} → {:?})", id, tool, method, action_enum);
}

/// Remove a policy rule.
pub fn policy_remove(id: &str) {
    let mut config = match crate::config::MuccheConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            return;
        }
    };

    let before = config.policy_rules.rules.len();
    config.policy_rules.rules.retain(|r| r.id != id);

    if config.policy_rules.rules.len() == before {
        eprintln!("Rule '{}' not found.", id);
        return;
    }

    if let Err(e) = config.save() {
        eprintln!("Failed to save config: {}", e);
        return;
    }

    println!("Removed rule: {}", id);
}
