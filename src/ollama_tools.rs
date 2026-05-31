//! Ollama native tool calling — OpenAI-compatible tool format.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A tool definition in OpenAI format (used by Ollama `/api/chat`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub r#type: String,
    pub function: ToolFunction,
}

impl ToolDefinition {
    pub fn new(name: &str, description: &str, parameters: serde_json::Value) -> Self {
        Self {
            r#type: "function".to_string(),
            function: ToolFunction {
                name: name.to_string(),
                description: description.to_string(),
                parameters,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolFunction {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// A tool call returned by the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub function: ToolCallFunction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallFunction {
    pub name: String,
    pub arguments: String,
}

/// Convert a simple parameter schema to JSON Schema object.
pub fn simple_params(params: &[(&str, &str, bool)]) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for (name, description, is_required) in params {
        let mut prop = serde_json::Map::new();
        prop.insert("type".to_string(), serde_json::Value::String("string".to_string()));
        prop.insert("description".to_string(), serde_json::Value::String(description.to_string()));
        properties.insert(name.to_string(), serde_json::Value::Object(prop));
        if *is_required {
            required.push(serde_json::Value::String(name.to_string()));
        }
    }
    let mut schema = serde_json::Map::new();
    schema.insert("type".to_string(), serde_json::Value::String("object".to_string()));
    schema.insert("properties".to_string(), serde_json::Value::Object(properties));
    schema.insert("required".to_string(), serde_json::Value::Array(required));
    serde_json::Value::Object(schema)
}

/// Build tool definitions from MCP tools and custom tools.
/// For now this is a stub — real integration would inspect tool schemas.
pub fn build_tool_definitions(
    mcp_tools: &[(String, String)], // (name, description)
    custom_tools: &[(String, String)],
) -> Vec<ToolDefinition> {
    let mut defs = Vec::new();
    for (name, desc) in mcp_tools.iter().chain(custom_tools.iter()) {
        defs.push(ToolDefinition::new(
            name,
            desc,
            simple_params(&[("input", "The input for this tool", true)]),
        ));
    }
    defs
}

/// Parse tool calls from an Ollama response string.
/// If the response contains `tool_calls` in JSON, extract them.
/// Falls back to regex `<mcp_tool>` parsing for backward compatibility.
pub fn parse_tool_calls(response: &str) -> Vec<ToolCall> {
    // Try to parse as Ollama native tool_calls JSON first
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(response) {
        if let Some(calls) = val.get("message").and_then(|m| m.get("tool_calls")).and_then(|t| t.as_array()) {
            let mut result = Vec::new();
            for call in calls {
                if let (Some(name), Some(args)) = (
                    call.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()),
                    call.get("function").and_then(|f| f.get("arguments")),
                ) {
                    result.push(ToolCall {
                        function: ToolCallFunction {
                            name: name.to_string(),
                            arguments: args.to_string(),
                        },
                    });
                }
            }
            if !result.is_empty() {
                return result;
            }
        }
    }

    // Fallback: regex <mcp_tool> parsing
    let re = regex::Regex::new(r"<mcp_tool>(.*?)</mcp_tool>").unwrap();
    let mut result = Vec::new();
    for cap in re.captures_iter(response) {
        let inner = cap[1].trim();
        if let Ok(json) = serde_json::from_str::<HashMap<String, serde_json::Value>>(inner) {
            if let Some(name) = json.get("name").and_then(|v| v.as_str()) {
                result.push(ToolCall {
                    function: ToolCallFunction {
                        name: name.to_string(),
                        arguments: serde_json::to_string(&json).unwrap_or_default(),
                    },
                });
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_params() {
        let p = simple_params(&[("city", "City name", true)]);
        assert!(p.get("properties").is_some());
        assert!(p.get("required").is_some());
    }

    #[test]
    fn test_parse_fallback() {
        let resp = r#"I'll check that for you. <mcp_tool>{"name":"weather","input":"Paris"}</mcp_tool>"#;
        let calls = parse_tool_calls(resp);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "weather");
    }
}
