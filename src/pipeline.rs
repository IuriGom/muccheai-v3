//! Modular processing pipeline — auditável chain of nodes.
//!
//! Each node transforms a `PipelineContext` and appends an audit log entry.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single audit log entry for a pipeline run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub node_name: String,
    pub timestamp_ms: u64,
    pub input_summary: String,
    pub output_summary: String,
    pub duration_ms: u64,
}

/// Context passed through the pipeline.
#[derive(Debug, Clone, Default)]
pub struct PipelineContext {
    pub system_prompt: String,
    pub user_message: String,
    pub memories: Vec<String>,
    pub tools: Vec<String>,
    pub llm_response: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// A pipeline node.
pub trait PipelineNode: Send + Sync {
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &mut PipelineContext) -> anyhow::Result<()>;
}

/// An audit-able pipeline.
pub struct Pipeline {
    nodes: Vec<Box<dyn PipelineNode>>,
    pub audit_log: Vec<AuditLogEntry>,
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Pipeline {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            audit_log: Vec::new(),
        }
    }

    pub fn add(&mut self, node: Box<dyn PipelineNode>) {
        self.nodes.push(node);
    }

    pub fn run(&mut self, ctx: &mut PipelineContext) -> anyhow::Result<()> {
        for node in &self.nodes {
            let start = std::time::Instant::now();
            let input_summary = format!(
                "sys={}B user={}B mems={} tools={}",
                ctx.system_prompt.len(),
                ctx.user_message.len(),
                ctx.memories.len(),
                ctx.tools.len()
            );
            node.run(ctx)?;
            let duration_ms = start.elapsed().as_millis() as u64;
            let output_summary = format!(
                "sys={}B user={}B mems={} tools={} resp={}",
                ctx.system_prompt.len(),
                ctx.user_message.len(),
                ctx.memories.len(),
                ctx.tools.len(),
                ctx.llm_response.as_ref().map(|s| s.len()).unwrap_or(0)
            );
            self.audit_log.push(AuditLogEntry {
                node_name: node.name().to_string(),
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                input_summary,
                output_summary,
                duration_ms,
            });
        }
        Ok(())
    }
}

// ─── Built-in nodes ─────────────────────────────────────────────────────────

pub struct InjectSystemPrompt {
    pub prompt: String,
}

impl PipelineNode for InjectSystemPrompt {
    fn name(&self) -> &'static str {
        "InjectSystemPrompt"
    }
    fn run(&self, ctx: &mut PipelineContext) -> anyhow::Result<()> {
        ctx.system_prompt = self.prompt.clone();
        Ok(())
    }
}

pub struct InjectMemories {
    pub memories: Vec<String>,
}

impl PipelineNode for InjectMemories {
    fn name(&self) -> &'static str {
        "InjectMemories"
    }
    fn run(&self, ctx: &mut PipelineContext) -> anyhow::Result<()> {
        ctx.memories = self.memories.clone();
        if !ctx.memories.is_empty() {
            ctx.system_prompt.push_str("\n\nRelevant memories:\n");
            for m in &ctx.memories {
                ctx.system_prompt.push_str(&format!("- {}\n", m));
            }
        }
        Ok(())
    }
}

pub struct DiscoverTools {
    pub tools: Vec<String>,
}

impl PipelineNode for DiscoverTools {
    fn name(&self) -> &'static str {
        "DiscoverTools"
    }
    fn run(&self, ctx: &mut PipelineContext) -> anyhow::Result<()> {
        ctx.tools = self.tools.clone();
        Ok(())
    }
}

pub struct FormatResponse;

impl PipelineNode for FormatResponse {
    fn name(&self) -> &'static str {
        "FormatResponse"
    }
    fn run(&self, ctx: &mut PipelineContext) -> anyhow::Result<()> {
        if let Some(ref mut resp) = ctx.llm_response {
            *resp = resp.trim().to_string();
        }
        Ok(())
    }
}
