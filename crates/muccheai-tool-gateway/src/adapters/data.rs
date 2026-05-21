//! Data tool adapters
//!
//! Includes: sqlite, csv, json

use muccheai_types::{ToolError, ToolResult, ToolResultMetadata};
use serde_json::json;
use std::path::Path;

/// Validate a path by canonicalizing it and ensuring it stays within
/// the current working directory (prevents symlink traversal).
///
/// SECURITY NOTE: This function mitigates but cannot fully eliminate TOCTOU
/// race conditions without `O_NOFOLLOW` / `openat()` on the caller side.
/// For read operations, callers should open the returned path and verify
/// the opened file's path matches via `/proc/self/fd` on Linux.
pub(crate) fn validate_path(path_str: &str) -> Result<std::path::PathBuf, ToolError> {
    let path = Path::new(path_str);

    // Reject absolute paths and explicit traversal attempts immediately.
    if path.is_absolute() || path_str.contains("..") {
        return Err(ToolError::CapabilityDenied(
            "Absolute paths and directory traversal are not allowed".to_string(),
        ));
    }

    let cwd = std::env::current_dir()
        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get current directory: {}", e)))?
        .canonicalize()
        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to canonicalize cwd: {}", e)))?;

    let parent = path.parent().unwrap_or(Path::new("."));
    let canonical_parent = parent.canonicalize().map_err(|e| {
        ToolError::CapabilityDenied(format!("Invalid path: {}", e))
    })?;

    // Ensure the resolved parent directory is still within the cwd.
    if !canonical_parent.starts_with(&cwd) {
        return Err(ToolError::CapabilityDenied(
            "Path escapes allowed directory".to_string(),
        ));
    }

    // Validate basename: must be a simple filename without path separators.
    let basename = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ToolError::CapabilityDenied("Invalid filename".to_string()))?;

    if basename.contains('/') || basename.contains('\\') || basename == "." || basename == ".." {
        return Err(ToolError::CapabilityDenied("Invalid filename".to_string()));
    }

    let canonical = canonical_parent.join(basename);

    // If the target already exists, reject symlinks to prevent traversal.
    if let Ok(meta) = std::fs::symlink_metadata(&canonical) {
        if meta.file_type().is_symlink() {
            return Err(ToolError::CapabilityDenied(
                "Symlinks are not allowed".to_string(),
            ));
        }
    }

    // Final verification: if the path exists, canonicalize the full path
    // and ensure it matches our constructed path and still stays within cwd.
    if canonical.exists() {
        let fully_canonical = canonical.canonicalize().map_err(|e| {
            ToolError::CapabilityDenied(format!("Path resolution failed: {}", e))
        })?;
        if !fully_canonical.starts_with(&cwd) {
            return Err(ToolError::CapabilityDenied(
                "Resolved path escapes allowed directory".to_string(),
            ));
        }
        return Ok(fully_canonical);
    }

    Ok(canonical)
}

/// SQLite adapter — query local SQLite databases
pub fn sqlite_query(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let db_path = params
        .get("db_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'db_path'".to_string()))?;
    let query = params
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'query'".to_string()))?;

    // Strict path validation: no traversal, no absolute paths, must end in .db/.sqlite/.sqlite3
    let db_lower = db_path.to_lowercase();
    if db_path.contains("..")
        || db_path.starts_with('/')
        || !(db_lower.ends_with(".db")
            || db_lower.ends_with(".sqlite")
            || db_lower.ends_with(".sqlite3"))
    {
        return Err(ToolError::CapabilityDenied(
            "Invalid database path".to_string(),
        ));
    }
    let canonical_db = validate_path(db_path)?;

    // Reject any query that is not a plain SELECT.
    let trimmed = query.trim();

    // Strip ALL comment styles before checking keywords:
    //   /* ... */  (C-style)
    //   -- ...     (line-style, including variations like `---`)
    //   # ...      (shell-style)
    let mut stripped = String::with_capacity(trimmed.len());
    let mut chars = trimmed.char_indices().peekable();
    while let Some((_, c)) = chars.next() {
        if c == '/' && chars.peek().map(|(_, next)| *next) == Some('*') {
            chars.next(); // consume '*'
            while let Some((_, inner)) = chars.next() {
                if inner == '*' && chars.peek().map(|(_, next)| *next) == Some('/') {
                    chars.next(); // consume '/'
                    break;
                }
            }
        } else if c == '-' && chars.peek().map(|(_, next)| *next) == Some('-') {
            chars.next(); // consume second '-'
            // Skip until newline or end of string
            while let Some((_, inner)) = chars.next() {
                if inner == '\n' {
                    break;
                }
            }
        } else if c == '#' {
            // Skip until newline or end of string
            while let Some((_, inner)) = chars.next() {
                if inner == '\n' {
                    break;
                }
            }
        } else {
            stripped.push(c);
        }
    }
    let upper = stripped.to_uppercase();

    // Must start with SELECT
    if !upper.starts_with("SELECT ") {
        return Err(ToolError::CapabilityDenied(
            "Only SELECT queries are allowed".to_string()
        ));
    }

    // Reject multi-statement queries
    if stripped.contains(';') {
        return Err(ToolError::CapabilityDenied(
            "Multiple statements are not allowed".to_string()
        ));
    }

    // Reject dangerous keywords and functions
    let forbidden = [
        "DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "PRAGMA",
        "ATTACH", "CREATE", "WITH", "REINDEX", "ANALYZE", "VACUUM",
        "LOAD_EXTENSION", "LOAD_", "UNION", "INTERSECT", "EXCEPT",
        "EXEC", "EXECUTE", "CALL", "COPY", "DETACH", "SQLITE_MASTER", "SQLITE_SCHEMA",
    ];
    for f in &forbidden {
        if upper.contains(f) {
            return Err(ToolError::CapabilityDenied(format!(
                "Query contains forbidden keyword: '{}'",
                f
            )));
        }
    }

    // Reject function calls that can execute code or access filesystem.
    // Also block CHAR() which can be used to construct arbitrary strings
    // (e.g. CHAR(47,116,109,112) → '/tmp') to bypass keyword filters.
    let forbidden_funcs = [
        "LOAD_EXTENSION", "READFILE", "WRITEFILE", "ZIPFILE", "SOUNDEX",
        "JSON_EACH", "JSON_TREE", "FTS5", "CHAR(",
    ];
    for f in &forbidden_funcs {
        if upper.contains(f) {
            return Err(ToolError::CapabilityDenied(format!(
                "Query contains forbidden function: '{}'",
                f
            )));
        }
    }

    // This blocks SELECT * FROM (SELECT * FROM secret_table) style attacks.
    let paren_depth = upper.chars().fold(0i32, |depth, c| {
        match c {
            '(' => depth + 1,
            ')' => depth - 1,
            _ => depth,
        }
    });
    if paren_depth != 0 || upper.contains('(') {
        return Err(ToolError::CapabilityDenied(
            "Subqueries and function calls are not allowed".to_string()
        ));
    }

    let conn = rusqlite::Connection::open_with_flags(
        &canonical_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| ToolError::ExecutionFailed(format!("SQLite open error: {}", e)))?;

    conn.execute_batch("PRAGMA load_extension = OFF;")
        .map_err(|e| ToolError::ExecutionFailed(format!("SQLite pragma error: {}", e)))?;

    let mut stmt = conn
        .prepare(query)
        .map_err(|e| ToolError::ExecutionFailed(format!("SQLite prepare error: {}", e)))?;

    let column_names: Vec<String> = stmt
        .column_names()
        .iter()
        .map(|s| s.to_string())
        .collect();

    let rows = stmt
        .query_map([], |row| {
            let mut obj = serde_json::Map::new();
            for (i, name) in column_names.iter().enumerate() {
                let value: serde_json::Value = match row.get_ref(i)? {
                    rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                    rusqlite::types::ValueRef::Integer(v) => json!(v),
                    rusqlite::types::ValueRef::Real(v) => json!(v),
                    rusqlite::types::ValueRef::Text(v) => json!(std::str::from_utf8(v).unwrap_or("")),
                    rusqlite::types::ValueRef::Blob(v) => json!(format!("<blob:{} bytes>", v.len())),
                };
                obj.insert(name.clone(), value);
            }
            Ok(serde_json::Value::Object(obj))
        })
        .map_err(|e| ToolError::ExecutionFailed(format!("SQLite query error: {}", e)))?;

    let mut results = Vec::new();
    const MAX_ROWS: usize = 10_000;
    for row in rows {
        if results.len() >= MAX_ROWS {
            return Err(ToolError::ExecutionFailed(
                "Query returned too many rows".to_string(),
            ));
        }
        results.push(row.map_err(|e| ToolError::ExecutionFailed(format!("SQLite row error: {}", e)))?);
    }

    Ok(ToolResult {
        success: true,
        data: json!({
            "columns": column_names,
            "rows": results,
            "row_count": results.len()
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "sqlite".to_string(),
            method: "query".to_string(),
        },
    })
}

/// CSV adapter — read/write CSV files
pub fn csv_read(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'path'".to_string()))?;

    if path.contains("..") || path.starts_with('/') {
        return Err(ToolError::CapabilityDenied(
            "Invalid path".to_string(),
        ));
    }
    let canonical = validate_path(path)?;

    let mut rdr = csv::Reader::from_path(&canonical)
        .map_err(|e| ToolError::ExecutionFailed(format!("CSV read error: {}", e)))?;

    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| ToolError::ExecutionFailed(format!("CSV header error: {}", e)))?
        .iter()
        .map(|s| s.to_string())
        .collect();

    const MAX_CSV_ROWS: usize = 10_000;
    let mut rows = Vec::new();
    for result in rdr.records() {
        if rows.len() >= MAX_CSV_ROWS {
            return Err(ToolError::ExecutionFailed("CSV exceeds maximum row count".to_string()));
        }
        let record = result.map_err(|e| ToolError::ExecutionFailed(format!("CSV record error: {}", e)))?;
        let mut obj = serde_json::Map::new();
        for (i, header) in headers.iter().enumerate() {
            obj.insert(header.clone(), json!(record.get(i).unwrap_or("")));
        }
        rows.push(serde_json::Value::Object(obj));
    }

    Ok(ToolResult {
        success: true,
        data: json!({
            "headers": headers,
            "rows": rows,
            "row_count": rows.len()
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "csv".to_string(),
            method: "read".to_string(),
        },
    })
}

/// CSV write adapter
pub fn csv_write(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'path'".to_string()))?;
    let rows = params
        .get("rows")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'rows'".to_string()))?;

    if path.contains("..") || path.starts_with('/') {
        return Err(ToolError::CapabilityDenied(
            "Invalid path".to_string(),
        ));
    }
    let canonical = validate_path(path)?;

    let mut wtr = csv::Writer::from_path(&canonical)
        .map_err(|e| ToolError::ExecutionFailed(format!("CSV write error: {}", e)))?;

    if let Some(first) = rows.first() {
        if let Some(obj) = first.as_object() {
            let headers: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
            wtr.write_record(&headers)
                .map_err(|e| ToolError::ExecutionFailed(format!("CSV header write error: {}", e)))?;
            for row in rows {
                if let Some(obj) = row.as_object() {
                    let values: Vec<String> = headers
                        .iter()
                        .map(|h| {
                            let mut val = obj.get(*h).and_then(|v| v.as_str()).unwrap_or("").to_string();
                            if val.starts_with('=') || val.starts_with('+') || val.starts_with('-') || val.starts_with('@') {
                                val.insert(0, '\'');
                            }
                            val
                        })
                        .collect();
                    wtr.write_record(&values)
                        .map_err(|e| ToolError::ExecutionFailed(format!("CSV row write error: {}", e)))?;
                }
            }
        }
    }

    wtr.flush()
        .map_err(|e| ToolError::ExecutionFailed(format!("CSV flush error: {}", e)))?;

    Ok(ToolResult {
        success: true,
        data: json!({
            "path": path,
            "rows_written": rows.len()
        }),
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "csv".to_string(),
            method: "write".to_string(),
        },
    })
}

/// JSON adapter — transform, validate, query JSON
pub fn json_transform(params: &serde_json::Value) -> Result<ToolResult, ToolError> {
    let input = params
        .get("input")
        .cloned()
        .ok_or_else(|| ToolError::InvalidParams("Missing 'input'".to_string()))?;
    let operation = params
        .get("operation")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("Missing 'operation'".to_string()))?;

    let result = match operation {
        "pretty" => serde_json::to_string_pretty(&input)
            .map(|s| json!({ "output": s }))
            .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?,
        "minify" => serde_json::to_string(&input)
            .map(|s| json!({ "output": s }))
            .map_err(|e| ToolError::ExecutionFailed(e.to_string()))?,
        "keys" => {
            if let Some(obj) = input.as_object() {
                json!({ "keys": obj.keys().collect::<Vec<&String>>() })
            } else {
                json!({ "keys": [] })
            }
        }
        "get" => {
            let key = params
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ToolError::InvalidParams("Missing 'key' for get".to_string()))?;
            if let Some(obj) = input.as_object() {
                json!({ "value": obj.get(key).cloned().unwrap_or(serde_json::Value::Null) })
            } else {
                json!({ "value": serde_json::Value::Null })
            }
        }
        "length" => {
            let len = if let Some(arr) = input.as_array() {
                arr.len()
            } else if let Some(obj) = input.as_object() {
                obj.len()
            } else {
                0
            };
            json!({ "length": len })
        }
        _ => return Err(ToolError::InvalidParams(format!("Unknown operation: {}", operation))),
    };

    Ok(ToolResult {
        success: true,
        data: result,
        metadata: ToolResultMetadata {
            execution_time_ms: 0,
            tool_id: "json".to_string(),
            method: "transform".to_string(),
        },
    })
}
