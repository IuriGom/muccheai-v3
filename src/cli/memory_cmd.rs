//! Memory management commands for MuccheAI.

use crate::memory_store::MemoryStore;

/// Run memory subcommand.
pub async fn run(search: Option<String>, compact: bool) -> anyhow::Result<()> {
    let store = MemoryStore::new()?;

    if compact {
        let entries = store.list(); // newest first
        let mut seen = std::collections::HashSet::new();
        let mut unique = Vec::new();
        for entry in entries {
            if seen.insert(entry.key.clone()) {
                unique.push(entry);
            }
        }
        let path = store.path.clone();
        let mut file = std::fs::File::create(&path)?;
        for entry in unique.into_iter().rev() {
            let line = serde_json::to_string(&entry)?;
            writeln!(file, "{line}")?;
        }
        println!("✓ Memory compacted (duplicates removed, latest kept)");
        return Ok(());
    }

    if let Some(query) = search {
        let results = store.search(&query);
        if results.is_empty() {
            println!("No memories found for '{query}'");
        } else {
            println!("Found {} memories:", results.len());
            for e in results {
                println!("  • {} = {:?}", e.key, e.value);
            }
        }
        return Ok(());
    }

    // Show status
    let entries = store.list();
    let total = entries.len();

    let now = muccheai_types::Timestamp::now();
    let today_start = now.0 - (now.0 % 86_400_000);
    let today_count = entries.iter().filter(|e| e.created_at.0 >= today_start).count();

    println!("🧠 Memory Status");
    println!("  Total memories:  {total}");
    println!("  Today's entries: {today_count}");
    if let Some(last) = entries.first() {
        println!("  Last session:    {}", last.created_at.0);
    } else {
        println!("  Last session:    never");
    }

    Ok(())
}
