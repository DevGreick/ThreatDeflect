use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use base64::{Engine as _, engine::general_purpose};
use url::{Url, Host};

fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut counts = HashMap::new();
    let total = s.len() as f64;
    for c in s.chars() { *counts.entry(c).or_insert(0) += 1; }
    counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / total;
        acc - p * p.log2()
    })
}

fn classify_file_context(file_path: &str) -> (&'static str, f64) {
    let normalized = format!("/{}", file_path.to_lowercase());
    let file_name = normalized.rsplit('/').next().unwrap_or(&normalized);

    if normalized.contains("/tests/") || normalized.contains("/test/")
        || normalized.contains("/spec/") || normalized.contains("/__tests__/")
        || file_name.starts_with("test_") || file_name.ends_with("_test.py")
        || file_name.ends_with(".test.js") || file_name.ends_with(".test.ts")
        || file_name.ends_with("_spec.rb") || file_name.ends_with(".spec.js")
        || file_name.ends_with(".spec.ts") || file_name.starts_with("benchmark_")
        || normalized.starts_with("/tests/") || normalized.starts_with("/test/")
    {
        return ("Test", 0.3);
    }

    if normalized.contains("/examples/") || normalized.contains("/example/")
        || normalized.contains("/samples/") || normalized.contains("/sample/")
        || normalized.contains("/demo/") || normalized.contains("/demos/")
        || normalized.starts_with("/examples/") || normalized.starts_with("/example/")
    {
        return ("Example", 0.2);
    }

    if file_name.contains(".example") || file_name.contains(".sample")
        || file_name.contains(".template") || file_name.contains("skeleton")
    {
        return ("Template", 0.15);
    }

    if normalized.contains("/docs/") || normalized.contains("/doc/")
        || file_name.ends_with(".md") || file_name.ends_with(".rst")
        || file_name.ends_with(".txt") || file_name == "readme"
        || normalized.starts_with("/docs/") || normalized.starts_with("/doc/")
    {
        return ("Documentation", 0.2);
    }

    ("Production", 1.0)
}

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    let placeholders = [
        "your_", "change_me", "changeme", "todo", "example", "test",
        "dummy", "fake", "sample", "placeholder", "insert_", "put_",
        "replace_", "xxx", "aaa", "000", "enter_your", "add_your",
        "my_secret", "my_key", "my_token", "secret_here", "key_here",
        "token_here", "password_here", "api_key_here",
    ];
    placeholders.iter().any(|p| lower.contains(p))
}

fn get_base_confidence(rule_id: &str) -> f64 {
    match rule_id {
        "Private Key" => 0.95,
        "AWS Key" | "AWS Secret Key" => 0.90,
        "GitHub Token" | "GitLab PAT" => 0.90,
        "Slack Token" => 0.85,
        "Stripe API Key" | "Stripe Secret Key" => 0.90,
        "Google Cloud API Key" => 0.85,
        "Firebase Server Key" => 0.85,
        "SendGrid API Key" => 0.90,
        "Discord Bot Token" => 0.80,
        "Telegram Bot Token" => 0.75,
        "NPM Auth Token" | "PyPI Token" => 0.90,
        "DigitalOcean Token" => 0.90,
        "Discord Webhook" | "Slack Incoming Webhook" => 0.90,
        "Database Connection String" => 0.85,
        "Supabase Service Key" => 0.85,
        "Azure Storage Key" => 0.80,
        "GCP Service Account Key" => 0.80,
        "Crypto Mining" => 0.85,
        "JNDI Injection" => 0.90,
        "Docker Socket Mount" => 0.80,
        "Cloud Metadata SSRF" => 0.75,
        "Remote Script Execution" | "Encoded Payload Execution" => 0.80,
        "SSH Key Injection" | "Crontab Injection" => 0.75,
        "Sensitive File Access" => 0.70,
        "PowerShell Encoded" => 0.80,
        "NPM Dangerous Hook" => 0.85,
        "Unsafe Deserialization" => 0.70,
        "Heroku API Key" | "Twilio Auth Token" | "Mailgun API Key" | "Datadog API Key" => 0.75,
        "Twilio SID" => 0.70,
        "Password in URL" => 0.65,
        "Tunnel Service URL" => 0.60,
        "JSON Web Token (JWT)" => 0.45,
        "Google OAuth Client ID" => 0.50,
        "Generic API Key" => 0.40,
        "High Entropy String" => 0.30,
        "Suspicious Command" => 0.50,
        "Suspicious JS Keyword" => 0.25,
        "Invisible Whitespace" => 0.35,
        "Hidden IOC (Base64)" => 0.70,
        _ => 0.50,
    }
}

fn has_assignment_context(line: &str, match_start: usize) -> bool {
    if match_start == 0 { return false; }
    let before = &line[..match_start.min(line.len())];
    let trimmed = before.trim_end();
    trimmed.ends_with('=') || trimmed.ends_with(':') || trimmed.ends_with("=>")
        || trimmed.ends_with("= ") || trimmed.ends_with(": ")
}

fn calculate_pattern_confidence(rule_id: &str, matched_value: &str, line: &str, match_start: usize) -> f64 {
    let mut confidence = get_base_confidence(rule_id);

    if is_placeholder(matched_value) {
        return 0.05;
    }

    let entropy = calculate_entropy(matched_value);
    if matched_value.len() >= 16 {
        if entropy > 5.5 {
            confidence += 0.1;
        } else if entropy < 3.5 {
            confidence -= 0.2;
        }
    }

    if has_assignment_context(line, match_start) {
        confidence += 0.1;
    }

    confidence.clamp(0.0, 1.0)
}

fn is_likely_comment(line: &str, extension: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() { return true; }
    match extension {
        "py" | "sh" | "yaml" | "yml" | "toml" | "conf" | "dockerfile" | "rb" | "pl" => trimmed.starts_with('#'),
        "js" | "ts" | "java" | "c" | "cpp" | "h" | "hpp" | "rs" | "go" | "php" | "swift" => {
            trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*")
        },
        "sql" => trimmed.starts_with("--"),
        _ => false,
    }
}

struct BlockCommentTracker {
    in_block: bool,
    lang_type: BlockCommentLang,
}

enum BlockCommentLang {
    CFamily,
    Python,
    None,
}

impl BlockCommentTracker {
    fn new(extension: &str) -> Self {
        let lang_type = match extension {
            "js" | "ts" | "java" | "c" | "cpp" | "h" | "hpp" | "rs" | "go" | "php" | "swift" | "css" => BlockCommentLang::CFamily,
            "py" => BlockCommentLang::Python,
            _ => BlockCommentLang::None,
        };
        BlockCommentTracker { in_block: false, lang_type }
    }

    fn update(&mut self, line: &str) -> bool {
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
                    let quote = if trimmed.starts_with("\"\"\"") { "\"\"\"" } else { "'''" };
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

fn is_public_ioc(url_str: &str) -> bool {
    if let Ok(parsed) = Url::parse(url_str) {
        return match parsed.host() {
            Some(Host::Domain(domain)) => {
                let d = domain.to_lowercase();
                if d == "localhost" || d == "example.com" || d.ends_with(".local") || d.ends_with(".test")
                   || d == "www.w3.org" || d == "schemas.microsoft.com" || d == "json-schema.org"
                   || d == "bugs.python.org" || d == "github.com" {
                    return false;
                }
                true
            },
            Some(Host::Ipv4(ip)) => {
                if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_documentation() {
                    return false;
                }
                true
            },
            Some(Host::Ipv6(ip)) => !ip.is_loopback(),
            None => false,
        };
    }
    false
}

fn is_safe_context_for_suspicious_commands(file_path: &str, extension: &str) -> bool {
    let path_lower = file_path.to_lowercase();

    if ["json", "yaml", "yml", "toml", "xml", "html", "css", "scss", "less", "svg", "txt", "md", "csv", "sql", "lock"].contains(&extension) {
        return true;
    }

    if ["c", "cpp", "h", "hpp", "rs", "go", "java", "class", "o", "obj", "a", "lib", "dll", "so"].contains(&extension) {
        return true;
    }

    if path_lower.contains("/vendor/") || path_lower.contains("_vendored") ||
       path_lower.contains("/includes/") || path_lower.contains("/debug") ||
       path_lower.contains("/deps/") || path_lower.contains("/node_modules/") {
        return true;
    }

    false
}

#[pyclass]
struct RustAnalyzer {
    secret_patterns: Vec<(String, Regex)>,
    suspicious_patterns: Vec<(String, Regex)>,
    long_string_regex: Regex,
    base64_regex: Regex,
    url_regex: Regex,
    js_keywords: Vec<String>,
}

#[pymethods]
impl RustAnalyzer {
    #[new]
    fn new(rules: HashMap<String, String>, suspicious_rules: HashMap<String, String>) -> PyResult<Self> {
        let mut secret_compiled = Vec::new();
        for (id, pattern) in rules {
            if let Ok(re) = Regex::new(&pattern) {
                secret_compiled.push((id, re));
            }
        }

        let mut suspicious_compiled = Vec::new();
        for (id, pattern) in suspicious_rules {
            if let Ok(re) = Regex::new(&pattern) {
                suspicious_compiled.push((id, re));
            }
        }

        Ok(RustAnalyzer {
            secret_patterns: secret_compiled,
            suspicious_patterns: suspicious_compiled,
            long_string_regex: Regex::new(r#"["']([a-zA-Z0-9+/=,.\-_]{50,})["']"#).unwrap(),
            base64_regex: Regex::new(r"\b([A-Za-z0-9+/=_-]{20,})\b").unwrap(),
            url_regex: Regex::new(r"https?://[a-zA-Z0-9.\-_]+(?:/[^\s<>\x22\x27]*)?").unwrap(),
            js_keywords: vec![
                "eval".to_string(), "document.write".to_string(),
                "innerHTML".to_string(), "unescape".to_string(),
                "crypto.subtle".to_string()
            ],
        })
    }

    fn process_file_content<'py>(&self, py: Python<'py>, content: &str, file_path: &str, file_name: &str) -> PyResult<(Bound<'py, PyList>, Bound<'py, PyList>)> {
        let findings = PyList::empty(py);
        let iocs = PyList::empty(py);
        let mut existing_findings = HashSet::new();
        let mut existing_iocs = HashSet::new();

        let extension = file_name.split('.').last().unwrap_or("").to_lowercase();
        let is_js_ts = extension == "js" || extension == "ts";
        let is_safe_context = is_safe_context_for_suspicious_commands(file_path, &extension);
        let (file_context, context_multiplier) = classify_file_context(file_path);
        let mut block_tracker = BlockCommentTracker::new(&extension);

        for line in content.lines() {
            let in_block_comment = block_tracker.update(line);

            if is_likely_comment(line, &extension) && !in_block_comment { continue; }

            let comment_multiplier = if in_block_comment { 0.1 } else { 1.0 };

            if is_js_ts {
                for keyword in &self.js_keywords {
                    if line.contains(keyword) {
                        let desc = format!("Palavra-chave suspeita '{}'", keyword);
                        if existing_findings.insert((desc.clone(), "Suspicious JS Keyword")) {
                            let base_conf = get_base_confidence("Suspicious JS Keyword");
                            let conf = (base_conf * context_multiplier * comment_multiplier).clamp(0.0, 1.0);
                            let finding = PyDict::new(py);
                            finding.set_item("description", &desc)?;
                            finding.set_item("type", "Suspicious JS Keyword")?;
                            finding.set_item("file", file_path)?;
                            finding.set_item("match_content", line.trim())?;
                            finding.set_item("confidence", conf)?;
                            finding.set_item("file_context", file_context)?;
                            findings.append(finding)?;
                        }
                    }
                }
            }

            for (id, re) in &self.secret_patterns {
                for caps in re.captures_iter(line) {
                    if let Some(m) = caps.get(0) {
                        let matched_str = m.as_str();
                        let match_start = m.start();
                        let raw_conf = calculate_pattern_confidence(id, matched_str, line, match_start);
                        let conf = (raw_conf * context_multiplier * comment_multiplier).clamp(0.0, 1.0);

                        if id == "Generic API Key" {
                            let finding = PyDict::new(py);
                            finding.set_item("description", "Possível chave de API.")?;
                            finding.set_item("type", id)?;
                            finding.set_item("file", file_path)?;
                            finding.set_item("match_content", matched_str)?;
                            finding.set_item("confidence", conf)?;
                            finding.set_item("file_context", file_context)?;
                            findings.append(finding)?;
                        } else {
                            let desc = format!("Possível segredo '{}' exposto", id);
                            if existing_findings.insert((desc.clone(), id.as_str())) {
                                let finding = PyDict::new(py);
                                finding.set_item("description", &desc)?;
                                finding.set_item("type", id)?;
                                finding.set_item("file", file_path)?;
                                finding.set_item("match_content", matched_str)?;
                                finding.set_item("confidence", conf)?;
                                finding.set_item("file_context", file_context)?;
                                findings.append(finding)?;
                            }
                        }
                    }
                }
            }

            if !is_safe_context {
                for (id, re) in &self.suspicious_patterns {
                    if re.is_match(line) {
                        let line_trim = line.trim();
                        if line_trim.starts_with("import ") || line_trim.starts_with("from ") || line_trim.contains("console.log") {
                            continue;
                        }
                        for caps in re.captures_iter(line) {
                            if let Some(m) = caps.get(0) {
                                let raw_conf = calculate_pattern_confidence(id, m.as_str(), line, m.start());
                                let conf = (raw_conf * context_multiplier * comment_multiplier).clamp(0.0, 1.0);
                                let finding = PyDict::new(py);
                                let desc = format!("Comando suspeito: '{}'", id);
                                finding.set_item("description", &desc)?;
                                finding.set_item("type", "Suspicious Command")?;
                                finding.set_item("file", file_path)?;
                                finding.set_item("match_content", m.as_str())?;
                                finding.set_item("confidence", conf)?;
                                finding.set_item("file_context", file_context)?;
                                findings.append(finding)?;
                            }
                        }
                    }
                }
            }
        }

        if is_js_ts || extension == "py" || extension == "env" || extension == "json" || extension == "xml" || extension == "yaml" {
             for caps in self.long_string_regex.captures_iter(content) {
                if let Some(matched) = caps.get(1) {
                    let s = matched.as_str();
                    let entropy = calculate_entropy(s);
                    if entropy > 5.2 {
                        let desc = format!("String de alta entropia ({:.2})", entropy);
                        if existing_findings.insert((desc.clone(), "High Entropy String")) {
                            let raw_conf = (entropy - 5.2) / 2.0 + 0.3;
                            let conf = (raw_conf.min(0.85) * context_multiplier).clamp(0.0, 1.0);
                            let finding = PyDict::new(py);
                            finding.set_item("description", &desc)?;
                            finding.set_item("type", "High Entropy String")?;
                            finding.set_item("file", file_path)?;
                            finding.set_item("match_content", s)?;
                            finding.set_item("confidence", conf)?;
                            finding.set_item("file_context", file_context)?;
                            findings.append(finding)?;
                        }
                    }
                }
            }
        }

        for caps in self.base64_regex.captures_iter(content) {
            if let Some(m) = caps.get(1) {
                let s = m.as_str();
                let decoded = general_purpose::STANDARD.decode(s).or_else(|_| general_purpose::STANDARD_NO_PAD.decode(s));
                if let Ok(bytes) = decoded {
                    if let Ok(decoded_str) = String::from_utf8(bytes) {
                        for url_match in self.url_regex.find_iter(&decoded_str) {
                            let url = url_match.as_str();
                            if is_public_ioc(url) {
                                if existing_iocs.insert(url.to_string()) {
                                    let desc = format!("URL ofuscada em Base64: {}...", &url[..std::cmp::min(50, url.len())]);
                                    let conf = (0.70 * context_multiplier).clamp(0.0, 1.0);
                                    let finding = PyDict::new(py);
                                    finding.set_item("description", desc)?;
                                    finding.set_item("type", "Hidden IOC (Base64)")?;
                                    finding.set_item("file", file_path)?;
                                    finding.set_item("confidence", conf)?;
                                    finding.set_item("file_context", file_context)?;
                                    findings.append(finding)?;
                                    let ioc = PyDict::new(py);
                                    ioc.set_item("ioc", url)?;
                                    ioc.set_item("source_file", file_path)?;
                                    iocs.append(ioc)?;
                                }
                            }
                        }
                    }
                }
            }
        }

        for url_match in self.url_regex.find_iter(content) {
            let url = url_match.as_str();
            if is_public_ioc(url) {
                if existing_iocs.insert(url.to_string()) {
                    let ioc = PyDict::new(py);
                    ioc.set_item("ioc", url)?;
                    ioc.set_item("source_file", file_path)?;
                    iocs.append(ioc)?;
                }
            }
        }

        Ok((findings, iocs))
    }
}

#[pymodule]
fn threatdeflect_rs(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RustAnalyzer>()?;
    Ok(())
}
