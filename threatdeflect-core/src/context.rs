use crate::types::FileContext;

pub fn classify_file_context(file_path: &str) -> FileContext {
    let normalized = format!("/{}", file_path.to_lowercase());
    let file_name = normalized.rsplit('/').next().unwrap_or(&normalized);

    if normalized.contains("/tests/")
        || normalized.contains("/test/")
        || normalized.contains("/spec/")
        || normalized.contains("/__tests__/")
        || file_name.starts_with("test_")
        || file_name.ends_with("_test.py")
        || file_name.ends_with(".test.js")
        || file_name.ends_with(".test.ts")
        || file_name.ends_with("_spec.rb")
        || file_name.ends_with(".spec.js")
        || file_name.ends_with(".spec.ts")
        || file_name.starts_with("benchmark_")
        || normalized.starts_with("/tests/")
        || normalized.starts_with("/test/")
    {
        return FileContext::Test;
    }

    if normalized.contains("/examples/")
        || normalized.contains("/example/")
        || normalized.contains("/samples/")
        || normalized.contains("/sample/")
        || normalized.contains("/demo/")
        || normalized.contains("/demos/")
        || normalized.starts_with("/examples/")
        || normalized.starts_with("/example/")
    {
        return FileContext::Example;
    }

    if file_name.contains(".example")
        || file_name.contains(".sample")
        || file_name.contains(".template")
        || file_name.contains("skeleton")
    {
        return FileContext::Template;
    }

    if normalized.contains("/docs/")
        || normalized.contains("/doc/")
        || file_name.ends_with(".md")
        || file_name.ends_with(".rst")
        || file_name.ends_with(".txt")
        || file_name == "readme"
        || normalized.starts_with("/docs/")
        || normalized.starts_with("/doc/")
    {
        return FileContext::Documentation;
    }

    FileContext::Production
}

pub fn is_likely_comment(line: &str, extension: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true;
    }
    match extension {
        "py" | "sh" | "yaml" | "yml" | "toml" | "conf" | "dockerfile" | "rb" | "pl" => {
            trimmed.starts_with('#')
        }
        "js" | "ts" | "java" | "c" | "cpp" | "h" | "hpp" | "rs" | "go" | "php" | "swift" => {
            trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*")
        }
        "sql" => trimmed.starts_with("--"),
        _ => false,
    }
}

pub fn is_safe_context_for_suspicious_commands(file_path: &str, extension: &str) -> bool {
    let path_lower = file_path.to_lowercase();

    if [
        "json", "yaml", "yml", "toml", "xml", "html", "css", "scss", "less", "svg", "txt", "md",
        "csv", "sql", "lock",
    ]
    .contains(&extension)
    {
        return true;
    }

    if [
        "c", "cpp", "h", "hpp", "rs", "go", "java", "class", "o", "obj", "a", "lib", "dll", "so",
    ]
    .contains(&extension)
    {
        return true;
    }

    if path_lower.contains("/vendor/")
        || path_lower.contains("_vendored")
        || path_lower.contains("/includes/")
        || path_lower.contains("/debug")
        || path_lower.contains("/deps/")
        || path_lower.contains("/node_modules/")
    {
        return true;
    }

    false
}

pub(crate) enum BlockCommentLang {
    CFamily,
    Python,
    None,
}

pub struct BlockCommentTracker {
    in_block: bool,
    lang_type: BlockCommentLang,
}

impl BlockCommentTracker {
    pub fn new(extension: &str) -> Self {
        let lang_type = match extension {
            "js" | "ts" | "java" | "c" | "cpp" | "h" | "hpp" | "rs" | "go" | "php" | "swift"
            | "css" => BlockCommentLang::CFamily,
            "py" => BlockCommentLang::Python,
            _ => BlockCommentLang::None,
        };
        BlockCommentTracker {
            in_block: false,
            lang_type,
        }
    }

    pub fn update(&mut self, line: &str) -> bool {
        let trimmed = line.trim();
        match self.lang_type {
            BlockCommentLang::CFamily => {
                if self.in_block {
                    if trimmed.contains("*/") {
                        self.in_block = false;
                    }
                    return true;
                }
                if trimmed.contains("/*") && !trimmed.contains("*/") {
                    self.in_block = true;
                    return true;
                }
                false
            }
            BlockCommentLang::Python => {
                if trimmed.starts_with("\"\"\"") || trimmed.starts_with("'''") {
                    let quote = if trimmed.starts_with("\"\"\"") {
                        "\"\"\""
                    } else {
                        "'''"
                    };
                    if self.in_block {
                        self.in_block = false;
                        return true;
                    }
                    let rest = &trimmed[3..];
                    if !rest.contains(quote) {
                        self.in_block = true;
                        return true;
                    }
                    return true;
                }
                self.in_block
            }
            BlockCommentLang::None => false,
        }
    }
}

pub fn is_public_ioc(url_str: &str) -> bool {
    if let Ok(parsed) = url::Url::parse(url_str) {
        return match parsed.host() {
            Some(url::Host::Domain(domain)) => {
                let d = domain.to_lowercase();
                if d == "localhost"
                    || d == "example.com"
                    || d.ends_with(".local")
                    || d.ends_with(".test")
                    || d == "www.w3.org"
                    || d == "schemas.microsoft.com"
                    || d == "json-schema.org"
                    || d == "bugs.python.org"
                    || d == "github.com"
                {
                    return false;
                }
                true
            }
            Some(url::Host::Ipv4(ip)) => {
                if ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                {
                    return false;
                }
                true
            }
            Some(url::Host::Ipv6(ip)) => !ip.is_loopback(),
            None => false,
        };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_context() {
        assert_eq!(classify_file_context("src/main.py"), FileContext::Production);
    }

    #[test]
    fn test_test_context() {
        assert_eq!(classify_file_context("tests/test_auth.py"), FileContext::Test);
        assert_eq!(classify_file_context("src/auth.test.js"), FileContext::Test);
    }

    #[test]
    fn test_example_context() {
        assert_eq!(classify_file_context("examples/demo.py"), FileContext::Example);
    }

    #[test]
    fn test_doc_context() {
        assert_eq!(classify_file_context("docs/setup.md"), FileContext::Documentation);
    }

    #[test]
    fn test_template_context() {
        assert_eq!(classify_file_context("config.example.yaml"), FileContext::Template);
    }

    #[test]
    fn test_public_ioc_private_ip() {
        assert!(!is_public_ioc("http://192.168.1.1/admin"));
        assert!(!is_public_ioc("http://localhost:8080"));
    }

    #[test]
    fn test_public_ioc_real() {
        assert!(is_public_ioc("http://malware.example.org/payload"));
    }

    #[test]
    fn test_comment_detection() {
        assert!(is_likely_comment("# this is a comment", "py"));
        assert!(is_likely_comment("// this is a comment", "js"));
        assert!(!is_likely_comment("api_key = 'abc'", "py"));
    }
}
