# threatdeflect-core

High-performance secret detection, confidence scoring, and IOC extraction engine written in Rust.

[![Crates.io](https://img.shields.io/crates/v/threatdeflect-core.svg)](https://crates.io/crates/threatdeflect-core)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

## What it does

`threatdeflect-core` scans source code and text files looking for:

- **Leaked secrets** — AWS keys, GitHub tokens, API keys, database connection strings, private keys, and 30+ other credential patterns
- **Suspicious commands** — reverse shells, crypto miners, encoded payload execution, unsafe deserialization
- **Indicators of Compromise (IOCs)** — URLs, IPs, and domains extracted from code, including base64-encoded hidden IOCs
- **Paste service C2** — URLs pointing to npoint.io, pastebin.com, and other paste services commonly used as C2 staging

Unlike simple regex scanners, it uses **confidence scoring** to reduce false positives:

| Signal | Effect |
|---|---|
| Shannon entropy > 5.5 | Confidence +10% (likely real secret) |
| Shannon entropy < 3.5 | Confidence -20% (likely placeholder) |
| Placeholder detected (`changeme`, `xxx`, `TODO`) | Confidence forced to 5% |
| Assignment context (`key = "..."`) | Confidence +10% |
| Test file (`test_*.py`, `*_test.go`) | Confidence x0.3 |
| Example/template file | Confidence x0.15-0.2 |
| Production file | Confidence x1.0 (no penalty) |

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
threatdeflect-core = "0.1"
```

### Minimal example

```rust
use threatdeflect_core::SecretAnalyzer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define detection rules: (rule_id, regex_pattern)
    let secret_rules = vec![
        ("AWS Key".to_string(), r"AKIA[0-9A-Z]{16}".to_string()),
        ("GitHub Token".to_string(), r"ghp_[a-zA-Z0-9]{36}".to_string()),
    ];

    // Suspicious command rules (excluded from safe contexts like imports)
    let suspicious_rules = vec![
        ("Reverse Shell".to_string(), r"bash\s+-i\s+>&\s+/dev/tcp".to_string()),
    ];

    let analyzer = SecretAnalyzer::new(secret_rules, suspicious_rules)?;

    let source_code = r#"
        aws_key = "AKIAIOSFODNN7EXAMPLE1"
        callback = "http://evil.com/steal"
    "#;

    let result = analyzer.analyze_content(source_code, "src/config.py", "config.py");

    for finding in &result.findings {
        println!(
            "[{:.0}%] {} in {} ({})",
            finding.confidence * 100.0,
            finding.finding_type,
            finding.file,
            finding.file_context.as_str(),
        );
    }

    for ioc in &result.iocs {
        println!("IOC: {} (from {})", ioc.ioc, ioc.source_file);
    }

    Ok(())
}
```

Output:

```
[85%] AWS Key in src/config.py (Production)
IOC: http://evil.com/steal (from src/config.py)
```

### Scanning multiple files

```rust
use threatdeflect_core::{SecretAnalyzer, AnalysisResult};

fn scan_directory(
    analyzer: &SecretAnalyzer,
    root: &std::path::Path,
) -> AnalysisResult {
    let mut combined = AnalysisResult::new();

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let rel_path = path.strip_prefix(root).unwrap_or(path);

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let result = analyzer.analyze_content(
            &content,
            &rel_path.to_string_lossy(),
            file_name,
        );

        combined.merge(result);
    }

    combined
}
```

### Filtering by confidence

```rust
// High confidence findings only (likely real secrets)
let real_secrets: Vec<_> = result.findings.iter()
    .filter(|f| f.confidence >= 0.70)
    .collect();

// Low confidence findings (send to manual review or AI validation)
let needs_review: Vec<_> = result.findings.iter()
    .filter(|f| f.confidence >= 0.15 && f.confidence < 0.70)
    .collect();

// Auto-discarded (almost certainly false positives)
let discarded: Vec<_> = result.findings.iter()
    .filter(|f| f.confidence < 0.15)
    .collect();
```

### Serialization with serde

All types implement `Serialize` and `Deserialize`:

```rust
let result = analyzer.analyze_content(code, "app.py", "app.py");

// JSON output
let json = serde_json::to_string_pretty(&result)?;
println!("{}", json);

// Or use with any serde-compatible format (YAML, TOML, MessagePack, etc.)
```

### File context classification

The engine automatically classifies files to adjust confidence:

```rust
use threatdeflect_core::context::classify_file_context;
use threatdeflect_core::FileContext;

assert_eq!(classify_file_context("src/config.py"), FileContext::Production);
assert_eq!(classify_file_context("tests/test_auth.py"), FileContext::Test);
assert_eq!(classify_file_context("examples/demo.rs"), FileContext::Example);
assert_eq!(classify_file_context("docs/setup.md"), FileContext::Documentation);
assert_eq!(classify_file_context("templates/base.html"), FileContext::Template);
```

### Entropy calculation

Use the entropy function directly for custom analysis:

```rust
use threatdeflect_core::confidence::calculate_entropy;

let high = calculate_entropy("a8f2k9x1m3n7p4q6r8s2t5u0v3w1y9z");  // ~4.7
let low = calculate_entropy("aaaaaaaaaa");                           // ~0.0
```

## Architecture

```
threatdeflect-core/
  analyzer.rs     SecretAnalyzer: orchestrates all detection passes
  confidence.rs   Shannon entropy, base confidence, context adjustments
  context.rs      File classification, comment detection, IOC validation
  types.rs        Finding, Ioc, AnalysisResult, FileContext
  error.rs        AnalyzerError with thiserror
  lib.rs          Public re-exports
```

**Detection pipeline** (per file):

```
Input (content, path, filename)
  |
  |-- 1. Secret patterns         regex match + confidence scoring -> Finding
  |-- 2. Suspicious patterns     regex match (skip safe contexts) -> Finding
  |-- 3. High entropy strings    entropy > 5.2 in code files -> Finding
  |-- 4. Base64 IOC extraction   decode base64 -> extract hidden URLs -> Ioc
  |-- 5. JS keyword detection    eval, innerHTML, unescape -> Finding
  |
  v
AnalysisResult { findings, iocs }
```

## Detection capabilities

### Secret patterns (30+)

AWS keys, GitHub/GitLab tokens, Slack/Discord tokens, Stripe keys, Google Cloud API keys, Firebase server keys, Azure storage keys, DigitalOcean tokens, Telegram/Discord bot tokens, NPM/PyPI tokens, database connection strings, Supabase keys, SSH private keys, JWTs, and more.

### Suspicious commands

Reverse shells, crypto mining, JNDI injection (Log4Shell), encoded payload execution, Docker socket mounts, SSH key injection, crontab injection, unsafe deserialization, remote code loading, paste service C2 URLs.

### IOC extraction

- Direct URLs from source code (filtered: localhost, internal, CDN, package registries)
- Base64-encoded URLs (decoded and extracted automatically)
- Paste service URLs flagged as potential C2

## Performance

The engine is designed for scanning thousands of files in repositories:

- Zero-copy regex matching with the `regex` crate
- Single-pass line scanning (all detection in one iteration)
- No heap allocation for file context classification
- No I/O: accepts `&str` content, caller controls file reading

Typical throughput: ~50k lines/second on a single core (depends on rule count).

## Python bindings

This crate powers the Python package [ThreatDeflect](https://github.com/DevGreick/ThreatDeflect) via [PyO3](https://pyo3.rs) + [maturin](https://maturin.rs). The Python wrapper adds:

- GitHub/GitLab repository cloning and traversal
- API integrations (VirusTotal, AbuseIPDB, Shodan)
- AI-powered finding validation
- PDF/Excel report generation
- Finding correlation (eval + external URL = severity boost)

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.
