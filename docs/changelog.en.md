# Changelog

## v3.2.0 (2026-03-22)

### Published Rust Crate

- Detection engine extracted to independent crate [`threatdeflect-core`](https://crates.io/crates/threatdeflect-core) on crates.io
- Cargo workspace with two crates: `threatdeflect-core` (pure lib) and `rust_core` (PyO3 wrapper)
- Any Rust project can use the detection engine without depending on Python

### Findings Correlation

- New correlation system that cross-references findings in the same file
- `eval` + external URL in the same file = automatically promoted to HIGH
- Obfuscated payload (high entropy) + external URL = promoted to HIGH

### Obfuscation Detection

- **Hidden IOC (Hex)**: detects URLs and secrets hidden in hexadecimal strings (`0x68747470...` or `\x68\x74\x74\x70...`)
- **Hidden IOC (URL Encoded)**: detects connection strings obfuscated with percent-encoding (`postgres%3A%2F%2F...`)
- **Hidden IOC (Char Array)**: detects URLs and secrets hidden in char code arrays (`[104,116,116,112,...]`)

### New Detection Rules

- **Remote Code Loading**: detects fetch + eval/exec patterns (supply chain attack)
- **Paste Service C2**: detects URLs from npoint.io, pastebin.com and 15+ paste services used as C2/staging
- `Suspicious JS Keyword` promoted from LOW to MEDIUM
- `High Entropy String` promoted from LOW to MEDIUM
- Automatic severity boost for HIGH/CRITICAL findings with low Rust confidence

### Memory Safety

- `zeroize` on `Drop` for `Finding` and `Ioc` (secrets cleared from memory)
- `serde(deny_unknown_fields)` on all deserializable types
- `finding_type` now uses the actual rule ID instead of generic "Suspicious Command"

### Documentation

- README updated with crates.io badge and Rust crate usage section
- `rust-engine.md` rewritten with usage example, workspace architecture and security table

---

## v3.1.0 (2026-03-15)

### Detection Engine Rewritten

The detection rules (`rules.yaml`) were completely rewritten with a focus on precision, reducing false positives by ~99%.

- 46 detection rules (14 new), all compatible with the Rust engine
- New rules: AWS Secret Key, Telegram Bot Token, Discord Bot Token, Stripe, Firebase, Azure Storage, DigitalOcean, Supabase, SendGrid, Mailgun, Datadog, NPM Auth Token, PyPI Token, Database Connection String
- New attack rules: Discord Webhook, Slack Webhook, Cloud Metadata SSRF, Crypto Mining, JNDI Injection, Encoded Payload Execution, Docker Socket Mount, SSH Key Injection, Crontab Injection, Sensitive File Access, GCP Service Account Key, Tunnel Service URL, Unsafe Deserialization
- Rules like JWT, Heroku and suspicious commands now require context
- 93 ignored directories, 148 ignored files, 60 sensitive names

### Complete Bilingual CLI

- Help (`--help`) with detailed descriptions and examples for all commands
- Full translation to Portuguese (pt-br) and English (en-us), including internal Typer/Rich labels
- Language switch via `threatdeflect config set-lang pt_br`

### Cross-platform Build

- Standalone executables for Linux, Windows and macOS
- Automated CI/CD pipeline with GitHub Actions (PyInstaller + Maturin/PyO3)
- Rust engine embedded in executables

### Redesigned Interface

- Redesigned dark visual
- Reorganized layout with improved usability

### Documentation

- README completely rewritten
- Full documentation with MkDocs Material

---

## v3.0.0 (2025-12-28)

- Hybrid Rust + Python engine via PyO3/Maturin
- Redesigned GUI with PySide6
- CLI with Typer and Rich
- Ollama integration for local AI
- SQLite cache to optimize API usage
- Reports in Excel and PDF

---

## v2.0.0

- Complete rewrite of the tool
- Added repository analysis
- Multiple intelligence sources (VirusTotal, AbuseIPDB, Shodan, URLHaus, MalwareBazaar)

---

## v1.0.0

- Initial release
- Basic IOC analysis via VirusTotal
