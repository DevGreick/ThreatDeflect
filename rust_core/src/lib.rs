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

        for line in content.lines() {
            if is_likely_comment(line, &extension) { continue; }

            if is_js_ts {
                for keyword in &self.js_keywords {
                    if line.contains(keyword) {
                        let desc = format!("Palavra-chave suspeita '{}'", keyword);
                        if existing_findings.insert((desc.clone(), "Suspicious JS Keyword")) {
                            let finding = PyDict::new(py);
                            finding.set_item("description", &desc)?;
                            finding.set_item("type", "Suspicious JS Keyword")?;
                            finding.set_item("file", file_path)?;
                            finding.set_item("match_content", line.trim())?; 
                            findings.append(finding)?;
                        }
                    }
                }
            }

            for (id, re) in &self.secret_patterns {
                if re.is_match(line) {
                    if id == "Generic API Key" {
                       for caps in re.captures_iter(line) {
                           if let Some(m) = caps.get(0) {
                               let finding = PyDict::new(py);
                               finding.set_item("description", "Possível chave de API.")?;
                               finding.set_item("type", id)?;
                               finding.set_item("file", file_path)?;
                               finding.set_item("match_content", m.as_str())?;
                               findings.append(finding)?;
                           }
                       }
                    } else {
                        let desc = format!("Possível segredo '{}' exposto", id);
                        if existing_findings.insert((desc.clone(), id.as_str())) {
                            let finding = PyDict::new(py);
                            finding.set_item("description", &desc)?;
                            finding.set_item("type", id)?;
                            finding.set_item("file", file_path)?;
                            findings.append(finding)?;
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
                                let finding = PyDict::new(py);
                                let desc = format!("Comando suspeito: '{}'", id);
                                finding.set_item("description", &desc)?;
                                finding.set_item("type", "Suspicious Command")?;
                                finding.set_item("file", file_path)?;
                                finding.set_item("match_content", m.as_str())?;
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
                    if entropy > 4.8 {
                        let desc = format!("String de alta entropia ({:.2})", entropy);
                        if existing_findings.insert((desc.clone(), "High Entropy String")) {
                            let finding = PyDict::new(py);
                            finding.set_item("description", &desc)?;
                            finding.set_item("type", "High Entropy String")?;
                            finding.set_item("file", file_path)?;
                            finding.set_item("match_content", s)?; 
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
                                    let finding = PyDict::new(py);
                                    finding.set_item("description", desc)?;
                                    finding.set_item("type", "Hidden IOC (Base64)")?;
                                    finding.set_item("file", file_path)?;
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