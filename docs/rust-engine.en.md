# Rust Engine

ThreatDeflect has a hybrid Rust engine compiled via **Maturin/PyO3** that provides native performance for the heaviest analysis operations.

The engine is published as an independent crate on crates.io: [**threatdeflect-core**](https://crates.io/crates/threatdeflect-core)

---

## What the Rust engine accelerates

| Function | Description |
|----------|-------------|
| Secret detection | Compiles and executes all regex rules from rules.yaml |
| Entropy calculation | Identifies high-entropy strings (possible secrets) |
| Confidence scoring | Adjusts confidence by entropy, file context, and placeholders |
| Context analysis | Validates whether suspicious commands are in a safe context (comments, docs) |
| Base64 detection | Finds obfuscated IOCs in Base64 |
| URL extraction | Identifies direct URLs in source code |
| Paste Service C2 | Detects paste service URLs used as C2/staging |

---

## Using as a standalone Rust crate (independent from Python)

Add to your `Cargo.toml`:

```toml
[dependencies]
threatdeflect-core = "0.1"
```

```rust
use threatdeflect_core::SecretAnalyzer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rules = vec![
        ("AWS Key".to_string(), r"AKIA[0-9A-Z]{16}".to_string()),
        ("GitHub Token".to_string(), r"ghp_[a-zA-Z0-9]{36}".to_string()),
    ];

    let suspicious = vec![
        ("Reverse Shell".to_string(), r"bash\s+-i\s+>&\s+/dev/tcp".to_string()),
    ];

    let analyzer = SecretAnalyzer::new(rules, suspicious)?;
    let result = analyzer.analyze_content(
        "aws_key = AKIAIOSFODNN7EXAMPLE1",
        "src/config.py",
        "config.py",
    );

    for finding in &result.findings {
        println!(
            "[{:.0}%] {} in {} ({})",
            finding.confidence * 100.0,
            finding.finding_type,
            finding.file,
            finding.file_context.as_str(),
        );
    }

    Ok(())
}
```

Full crate documentation: [docs.rs/threatdeflect-core](https://docs.rs/threatdeflect-core)

---

## Automatic fallback

The Rust engine is **optional** in the Python context. If the `threatdeflect_rs` module is not compiled, ThreatDeflect automatically uses the pure Python implementation. All features remain available, only with lower performance on large analyses.

---

## Compiling for Python

### Requirements

- Rust toolchain (install via [rustup.rs](https://rustup.rs))
- Maturin (`uv tool install maturin`)
- Python 3.11+ in a virtual environment

### Compilation

```bash
source .venv/bin/activate
maturin develop --release
```

The `maturin develop --release` command compiles the Rust module and installs it directly into the active virtual environment.

!!! warning "Virtual environment required"
    `maturin develop` requires an active virtualenv. It does not work with the system Python.

### Verifying the installation

```python
python -c "import threatdeflect_rs; print('Rust engine available')"
```

---

## Architecture

```
threatdeflect-core/          Pure crate (published on crates.io)
  src/
    lib.rs                   Public re-exports
    analyzer.rs              SecretAnalyzer: orchestrates detection
    confidence.rs            Shannon entropy, scoring, adjustments
    context.rs               File classification, comments
    types.rs                 Finding, Ioc, AnalysisResult (with zeroize)
    error.rs                 AnalyzerError (thiserror)

rust_core/                   PyO3 wrapper (~50 lines)
  src/
    lib.rs                   Converts Rust types -> PyDict/PyList
```

The `RustAnalyzer` class is exposed to Python via PyO3 and provides the main method `process_file_content()` which receives a file's content and returns all findings (secrets, suspicious commands, IOCs, etc.).

---

## Memory safety

| Feature | Implementation |
|---------|----------------|
| Secret cleanup | `zeroize` on `Drop` for `Finding` and `Ioc` |
| Safe parsing | `serde(deny_unknown_fields)` on all types |
| Error handling | `thiserror` with `Result`, zero `.unwrap()` at runtime |
| Unsafe | Zero `unsafe` blocks |

---

## Rust dependencies

| Crate | Version | Usage |
|-------|---------|-------|
| `regex` | 1.11 | Pattern compilation and execution |
| `base64` | 0.22 | Base64 payload decoding |
| `url` | 2.5 | URL parsing and validation |
| `serde` | 1.0 | Serialization/deserialization (JSON, YAML, etc.) |
| `thiserror` | 2 | Typed errors |
| `zeroize` | 1.8 | Secure sensitive memory cleanup |
| `pyo3` | 0.28 | Python/Rust bridge (wrapper only) |
