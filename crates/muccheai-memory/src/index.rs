//! Hybrid search index (SQLite + FTS5 + vector cosine similarity)

use std::path::Path;

use anyhow::Result;
use rusqlite::{Connection, params};
use sha3::{Digest, Sha3_512};

/// A memory hit from hybrid search.
#[derive(Debug, Clone)]
pub struct MemoryHit {
    /// Memory ID
    pub id: String,
    /// Memory content
    pub content: String,
    /// Source category
    pub source: String,
    /// Creation timestamp (unix seconds)
    pub created_at: u64,
    /// Combined relevance score
    pub score: f32,
}

/// Hybrid search index: SQLite + FTS5 + vector cosine similarity.
pub struct HybridIndex {
    conn: Connection,
}

// NOTE: rusqlite's `Connection` is `Send` when compiled with the `bundled`
// feature (SQLITE_THREADSAFE=1/2). `HybridIndex` must ONLY be accessed
// through `tokio::sync::Mutex<MemoryEngine>` or equivalent synchronization.

impl HybridIndex {
    /// Open or create the hybrid index at the given path.
    ///
    /// **Security Note:** This SQLite database is NOT encrypted by default.
    /// For production deployments, compile rusqlite with SQLCipher support
    /// (replace `bundled` with `bundled-sqlcipher` in Cargo.toml) and call:
    /// `conn.execute_batch("PRAGMA key = 'your-password';")` after opening.
    pub fn new(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path.parent().unwrap_or(Path::new("")))?;
        let conn = Connection::open(path)?;

        // Main memories table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS memories (
                id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                source TEXT,
                created_at INTEGER,
                embedding BLOB
            )",
            [],
        )?;

        // FTS5 virtual table for text search
        conn.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(content, content='memories', content_rowid='rowid')",
            [],
        )?;

        // Triggers to keep FTS5 in sync
        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
                INSERT INTO memories_fts(rowid, content) VALUES (new.rowid, new.content);
            END",
            [],
        )?;

        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
            END",
            [],
        )?;

        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
                INSERT INTO memories_fts(rowid, content) VALUES (new.rowid, new.content);
            END",
            [],
        )?;

        Ok(Self { conn })
    }

    /// Insert or replace a memory entry.
    pub fn insert(&self, id: &str, content: &str, source: &str, created_at: u64) -> Result<()> {
        let embedding = embed(content);
        let embedding_bytes = embedding_to_bytes(&embedding);

        self.conn.execute(
            "INSERT OR REPLACE INTO memories (id, content, source, created_at, embedding)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, content, source, created_at as i64, embedding_bytes],
        )?;
        Ok(())
    }

    /// Hybrid search: 70% vector + 30% BM25, with temporal decay.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<MemoryHit>> {
        let query_embedding = embed(query);

        // Get candidates from FTS5
        let mut stmt = self.conn.prepare(
            "SELECT m.rowid, m.id, m.content, m.source, m.created_at, m.embedding,
                    rank as bm25_rank
             FROM memories_fts
             JOIN memories m ON m.rowid = memories_fts.rowid
             WHERE memories_fts MATCH ?1
             ORDER BY rank
             LIMIT ?2"
        )?;

        let rows = stmt.query_map(params![query, limit as i64], |row| {
            let _rowid: i64 = row.get(0)?;
            let id: String = row.get(1)?;
            let content: String = row.get(2)?;
            let source: String = row.get(3)?;
            let created_at: i64 = row.get(4)?;
            let embedding_bytes: Vec<u8> = row.get(5)?;
            let bm25_rank: f64 = row.get(6)?;

            let embedding = bytes_to_embedding(&embedding_bytes);
            let vector_score = cosine_similarity(&query_embedding, &embedding);
            let temporal_score = temporal_decay(created_at as u64);

            // Normalize bm25_rank: FTS5 rank is lower=better (typically negative)
            let bm25_score = (1.0 / (1.0 + bm25_rank.abs())).min(1.0) as f32;

            let score = 0.7 * vector_score + 0.3 * bm25_score;
            let score = score * temporal_score;

            Ok(MemoryHit {
                id,
                content,
                source,
                created_at: created_at as u64,
                score,
            })
        })?;

        let mut hits = Vec::new();
        let mut existing_ids = std::collections::HashSet::new();
        for row in rows {
            let hit = row?;
            existing_ids.insert(hit.id.clone());
            hits.push(hit);
        }

        // Brute-force vector search over recent memories to catch semantic
        // matches even when text overlap is poor.
        let mut stmt = self.conn.prepare(
            "SELECT id, content, source, created_at, embedding FROM memories ORDER BY created_at DESC LIMIT ?1"
        )?;
        let recent_rows = stmt.query_map(params![limit as i64 * 3], |row| {
            let id: String = row.get(0)?;
            let content: String = row.get(1)?;
            let source: String = row.get(2)?;
            let created_at: i64 = row.get(3)?;
            let embedding_bytes: Vec<u8> = row.get(4)?;

            let embedding = bytes_to_embedding(&embedding_bytes);
            let vector_score = cosine_similarity(&query_embedding, &embedding);
            let temporal_score = temporal_decay(created_at as u64);

            let score = 0.7 * vector_score * temporal_score;

            Ok(MemoryHit {
                id,
                content,
                source,
                created_at: created_at as u64,
                score,
            })
        })?;

        for row in recent_rows {
            let hit = row?;
            if !existing_ids.contains(&hit.id) && hit.score > 0.3 {
                existing_ids.insert(hit.id.clone());
                hits.push(hit);
            }
        }

        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        hits.truncate(limit);
        Ok(hits)
    }

    /// List all memories.
    pub fn list_all(&self) -> Result<Vec<MemoryHit>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content, source, created_at FROM memories ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MemoryHit {
                id: row.get(0)?,
                content: row.get(1)?,
                source: row.get(2)?,
                created_at: row.get::<_, i64>(3)? as u64,
                score: 0.0,
            })
        })?;
        let mut hits = Vec::new();
        for row in rows {
            hits.push(row?);
        }
        Ok(hits)
    }
}

/// Simple deterministic embedding using SHA3-512 hashing.
///
/// In production, this would be replaced with a real embedding model
/// (e.g. sentence-transformers, Ollama embeddings API).
fn embed(text: &str) -> Vec<f32> {
    const DIM: usize = 384;
    let mut vec = vec![0.0f32; DIM];
    let words: Vec<_> = text
        .to_lowercase()
        .split_whitespace()
        .map(|w| w.chars().filter(|c| c.is_alphanumeric()).collect::<String>())
        .filter(|w| !w.is_empty())
        .collect();

    if words.is_empty() {
        return vec;
    }

    for (i, word) in words.iter().enumerate() {
        let hash = Sha3_512::digest(word.as_bytes());
        for j in 0..DIM {
            let byte_idx = j % hash.len();
            // Map byte to [-1, 1]
            let val = (hash[byte_idx] as f32 / 127.5) - 1.0;
            // Slight position decay
            let weight = 1.0 / (1.0 + (i as f32) * 0.1);
            vec[j] += val * weight;
        }
    }

    // Average
    for v in &mut vec {
        *v /= words.len() as f32;
    }

    // Normalize to unit length
    let norm: f32 = vec.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 1e-6 {
        for v in &mut vec {
            *v /= norm;
        }
    }

    vec
}

fn embedding_to_bytes(embedding: &[f32]) -> Vec<u8> {
    embedding.iter().flat_map(|f| f.to_le_bytes()).collect()
}

fn bytes_to_embedding(bytes: &[u8]) -> Vec<f32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    let denom = (norm_a.sqrt() * norm_b.sqrt()).max(1e-6);
    (dot / denom).max(0.0)
}

fn temporal_decay(created_at: u64) -> f32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let age_days = (now.saturating_sub(created_at)) as f32 / 86400.0;
    // Exponential decay with 30-day half-life
    (-0.0231 * age_days).exp().max(0.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_insert_and_search() {
        let tmp = TempDir::new().unwrap();
        let idx = HybridIndex::new(&tmp.path().join("test.db")).unwrap();

        idx.insert("id1", "Rust is a systems programming language", "test", now_secs()).unwrap();
        idx.insert("id2", "Python is great for scripting", "test", now_secs()).unwrap();
        idx.insert("id3", "I love writing Rust code", "test", now_secs()).unwrap();

        let hits = idx.search("Rust programming", 5).unwrap();
        assert!(!hits.is_empty());
        // The Rust-related entries should score higher
        assert!(hits[0].content.to_lowercase().contains("rust"));
    }

    #[test]
    fn test_temporal_decay() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(temporal_decay(now), 1.0);
        assert!(temporal_decay(now - 86400 * 30) < 1.0);
        assert!(temporal_decay(now - 86400 * 30) >= 0.1);
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}
