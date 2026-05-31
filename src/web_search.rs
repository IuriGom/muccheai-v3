//! Web search integration — DuckDuckGo Lite scraping with no API key required.

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
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("MuccheAI/3.0")
        .build()?;

    let url = format!("https://lite.duckduckgo.com/lite/?q={}", urlencoding::encode(query));
    let resp = client.get(&url).send().await?;
    let html = resp.text().await?;

    Ok(parse_ddg_lite(&html, max_results))
}

fn parse_ddg_lite(html: &str, max_results: usize) -> Vec<SearchResult> {
    let mut results = Vec::new();
    // DuckDuckGo Lite uses a simple table layout.
    // Each result row contains a link <a class="result-link"> and a snippet <td class="result-snippet">.
    let link_re = regex::Regex::new(r#"<a[^>]*class="result-link"[^>]*href="([^"]+)"[^>]*>(.*?)</a>"#).unwrap();
    let snippet_re = regex::Regex::new(r#"<td[^>]*class="result-snippet"[^>]*>(.*?)</td>"#).unwrap();

    let links: Vec<_> = link_re.captures_iter(html).collect();
    let snippets: Vec<_> = snippet_re.captures_iter(html).collect();

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
