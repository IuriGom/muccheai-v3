//! Web search via DuckDuckGo Lite.

use serde::{Deserialize, Serialize};

/// A single search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

/// Search DuckDuckGo Lite and return top results.
/// No API key needed; parses the HTML lite interface.
pub async fn search_duckduckgo(query: &str, max_results: usize) -> anyhow::Result<Vec<SearchResult>> {
    let max_results = max_results.min(20);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("MuccheAI/3.0")
        .build()?;

    // Domain is hardcoded; query is URL-encoded and appended as a query parameter only.
    // No user input reaches the host portion of the URL.
    let url = format!("https://lite.duckduckgo.com/lite/?q={}", urlencoding::encode(query));
    let resp = client.get(&url).send().await?;
    let html = resp.text().await?;

    Ok(parse_ddg_lite(&html, max_results))
}

fn parse_ddg_lite(html: &str, max_results: usize) -> Vec<SearchResult> {
    let mut results = Vec::new();
    static LINK_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"<a[^>]*class="result-link"[^>]*href="([^"]+)"[^>]*>(.*?)</a>"#).expect("static regex")
    });
    static SNIPPET_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"<td[^>]*class="result-snippet"[^>]*>(.*?)</td>"#).expect("static regex")
    });

    let links: Vec<_> = LINK_RE.captures_iter(html).collect();
    let snippets: Vec<_> = SNIPPET_RE.captures_iter(html).collect();

    for i in 0..links.len().min(snippets.len()).min(max_results) {
        let url = html_unescape(&links[i][1]);
        let title = strip_tags(&links[i][2]);
        let snippet = strip_tags(&snippets[i][1]);
        results.push(SearchResult { title, url, snippet });
    }

    results
}

fn strip_tags(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        if c == '<' {
            in_tag = true;
        } else if c == '>' {
            in_tag = false;
        } else if !in_tag {
            out.push(c);
        }
    }
    out.trim().to_string()
}

fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ddg_lite() {
        let html = r#"
        <a class="result-link" href="https://example.com">Example Site</a>
        <td class="result-snippet">This is a test snippet.</td>
        <a class="result-link" href="https://foo.com">Foo Bar</a>
        <td class="result-snippet">Another snippet here.</td>
        "#;
        let results = parse_ddg_lite(html, 5);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].title, "Example Site");
        assert_eq!(results[0].url, "https://example.com");
        assert_eq!(results[0].snippet, "This is a test snippet.");
    }
}
