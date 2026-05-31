//! Memory tier management — STM → MTM → LTM promotion/demotion.

use muccheai_types::memory::{MemoryEntry, MemoryTier, MemoryType};
use muccheai_types::Timestamp;

/// Thresholds for tier promotion (in milliseconds).
const STM_AGE_MS: u64 = 24 * 60 * 60 * 1000;      // 1 day
const MTM_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;  // 7 days
const STM_CONFIDENCE: f32 = 0.3;
const MTM_CONFIDENCE: f32 = 0.6;

/// Promote or demote a memory entry based on age and confidence.
pub fn evaluate_tier(entry: &mut MemoryEntry, now: Timestamp) {
    let age_ms = now.0.saturating_sub(entry.created_at.0);
    let conf = entry.confidence;

    match entry.tier {
        MemoryTier::ShortTerm => {
            if age_ms > STM_AGE_MS && conf >= STM_CONFIDENCE {
                entry.tier = MemoryTier::MediumTerm;
            }
        }
        MemoryTier::MediumTerm => {
            if age_ms > MTM_AGE_MS && conf >= MTM_CONFIDENCE {
                entry.tier = MemoryTier::LongTerm;
            } else if conf < STM_CONFIDENCE {
                entry.tier = MemoryTier::ShortTerm;
            }
        }
        MemoryTier::LongTerm => {
            if conf < MTM_CONFIDENCE {
                entry.tier = MemoryTier::MediumTerm;
            }
        }
    }
}

/// Filter memories by tier.
pub fn filter_by_tier(entries: &[MemoryEntry], tier: MemoryTier) -> Vec<MemoryEntry> {
    entries.iter().filter(|e| e.tier == tier).cloned().collect()
}

/// Get all STM entries (active session context).
pub fn short_term_memories(entries: &[MemoryEntry]) -> Vec<MemoryEntry> {
    filter_by_tier(entries, MemoryTier::ShortTerm)
}

/// Get all MTM entries (recent summaries, session context).
pub fn medium_term_memories(entries: &[MemoryEntry]) -> Vec<MemoryEntry> {
    filter_by_tier(entries, MemoryTier::MediumTerm)
}

/// Get all LTM entries (durable facts, preferences).
pub fn long_term_memories(entries: &[MemoryEntry]) -> Vec<MemoryEntry> {
    filter_by_tier(entries, MemoryTier::LongTerm)
}

/// Run tier evaluation on all entries and return how many changed.
pub fn recompute_tiers(entries: &mut [MemoryEntry], now: Timestamp) -> usize {
    let mut changed = 0;
    for entry in entries.iter_mut() {
        let before = entry.tier.clone();
        evaluate_tier(entry, now);
        if entry.tier != before {
            changed += 1;
        }
    }
    changed
}

/// Default tier for a new memory based on its type.
pub fn default_tier_for_type(memory_type: &MemoryType) -> MemoryTier {
    match memory_type {
        MemoryType::Fact => MemoryTier::LongTerm,
        MemoryType::Preference => MemoryTier::LongTerm,
        MemoryType::TaskHistory => MemoryTier::MediumTerm,
        MemoryType::Draft => MemoryTier::ShortTerm,
        MemoryType::Context => MemoryTier::ShortTerm,
    }
}
