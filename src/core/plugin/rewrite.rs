//! Regex URI template rewriting used by redirect and proxy-rewrite plugins.

use std::borrow::Cow;

use once_cell::sync::Lazy;
use regex::Regex;

/// Precompiled placeholder pattern for regex URI templates (e.g., "$1", "$10").
static TEMPLATE_PLACEHOLDER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$(\d+)").expect("Invalid template placeholder regex"));

/// Applies regex-based URI rewriting using precompiled patterns.
///
/// Patterns are applied in order until first match. This enables implementing
/// complex routing rules, redirects, and URL transformations efficiently.
///
/// # Arguments
/// - `uri`: The input URI to be rewritten.
/// - `regex_patterns`: Precompiled regex patterns with replacement templates.
///
/// # Returns
/// The rewritten URI if a pattern matches, otherwise the original URI.
///
/// # Performance Notes
/// Regex patterns are precompiled during plugin initialization to avoid
/// per-request compilation overhead in high-traffic scenarios.
pub fn apply_regex_uri_template<'a>(
    uri: &'a str,
    regex_patterns: &[(Regex, String)],
) -> Cow<'a, str> {
    for (re, redirect_template) in regex_patterns {
        if let Some(captures) = re.captures(uri) {
            // Build new URI by substituting capture groups into template.
            // Use regex replacement to avoid "$10" being treated as "$1" + "0".
            let redirect_uri =
                TEMPLATE_PLACEHOLDER_RE.replace_all(redirect_template, |caps: &regex::Captures| {
                    let idx = caps
                        .get(1)
                        .and_then(|m| m.as_str().parse::<usize>().ok())
                        .unwrap_or(0);
                    if idx == 0 {
                        // Preserve "$0" or malformed placeholders verbatim
                        caps.get(0).map(|m| m.as_str()).unwrap_or("").to_string()
                    } else {
                        captures
                            .get(idx)
                            .map(|m| m.as_str())
                            .unwrap_or("")
                            .to_string()
                    }
                });
            return Cow::Owned(redirect_uri.into_owned());
        }
    }

    Cow::Borrowed(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_with_valid_match() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "/$1-$2-$3".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "/theothers/$1-$2".to_string(),
            ),
        ];
        let uri = "/iresty/a/b/c";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "/a-b-c");
    }

    #[test]
    fn test_second_match_in_multi_patterns() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "/$1-$2-$3".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "/theothers/$1-$2".to_string(),
            ),
        ];
        let uri = "/theothers/x/y";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "/theothers/x-y");
    }

    #[test]
    fn test_no_match_should_return_original_uri() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "/$1-$2-$3".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "/theothers/$1-$2".to_string(),
            ),
        ];
        let uri = "/api/test";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "/api/test");
    }

    #[test]
    fn test_empty_uri() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "/$1-$2-$3".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "/theothers/$1-$2".to_string(),
            ),
        ];
        let uri = "";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "");
    }

    #[test]
    fn test_uri_with_multiple_parts() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "/$1-$2-$3".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "/theothers/$1-$2".to_string(),
            ),
        ];
        let uri = "/iresty/a/b/c/d/e/f";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "/a/b/c/d-e-f");
    }

    #[test]
    fn test_uri_with_special_characters() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "/$1-$2-$3".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "/theothers/$1-$2".to_string(),
            ),
        ];
        let uri = "/iresty/a/!/@";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "/a-!-@");
    }

    #[test]
    fn test_empty_template_should_return_empty_string() {
        let regex_patterns = [
            (
                Regex::new(r"^/iresty/(.*)/(.*)/(.*)").unwrap(),
                "".to_string(),
            ),
            (
                Regex::new(r"^/theothers/(.*)/(.*)").unwrap(),
                "".to_string(),
            ),
        ];
        let uri = "/iresty/a/b/c";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "");
    }

    #[test]
    fn test_template_with_double_digit_group() {
        let regex_patterns = [(
            Regex::new(r"^/a/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)/(\d+)$")
                .unwrap(),
            "/$10-$1".to_string(),
        )];
        let uri = "/a/9/2/3/4/5/6/7/8/9/123";

        let result = apply_regex_uri_template(uri, &regex_patterns);

        assert_eq!(result, "/123-9");
    }
}
