<div align="center" class="td-hero">
  <img src="https://raw.githubusercontent.com/DevGreick/ThreatDeflect/main/threatdeflect-logo.png" alt="ThreatDeflect Logo" width="150" class="td-logo-main"/>
  <h1 class="td-title-animated">ThreatDeflect</h1>
</div>

<div align="center" markdown>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python"></a>
  <a href="https://github.com/DevGreick/ThreatDeflect/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?logo=gnu" alt="License"></a>
  <img src="https://img.shields.io/badge/status-active-success.svg" alt="Status">
  <a href="https://doc.qt.io/qtforpython/"><img src="https://img.shields.io/badge/GUI-PySide6-purple.svg" alt="GUI"></a>
  <img src="https://img.shields.io/badge/engine-Rust+Python-orange.svg?logo=rust" alt="Engine">
</div>

<p align="center" class="td-tagline"><strong>Threat analysis tool with a hybrid Python + Rust engine that automates IOC, repository, and file lookups across multiple sources, generates reports, and creates summaries with local AI.</strong></p>

<div align="center">
  <img src="https://raw.githubusercontent.com/DevGreick/ThreatDeflect/main/Abertura.png" alt="Screenshot" width="700"/>
</div>

---

## Get Started in 30 Seconds

**1.** Download the executable for your system from the [Releases](https://github.com/DevGreick/ThreatDeflect/releases) page

**2.** Run the file (see [Installation](installation.md) for platform-specific instructions)

**3.** Go to **Settings** and enter your **VirusTotal** key to start analyzing

---

## What Does ThreatDeflect Do?

### Three Analysis Modules

| Module | What it does | Sources queried |
|--------|--------------|-----------------|
| **IOCs** | Bulk lookup of IPs and URLs | VirusTotal, AbuseIPDB, Shodan, URLHaus |
| **Repositories** | Scanning of GitHub/GitLab repos | Secrets, dependencies, IOCs, suspicious patterns |
| **Files** | Reputation by SHA256 hash | VirusTotal, MalwareBazaar |

### Highlights

- **Dual interface**: full GUI (PySide6) and robust CLI (Typer/Rich)
- **Hybrid Rust + Python engine**: secret detection with native performance via PyO3
- **Local AI**: executive summaries with Ollama, no data sent to the cloud
- **Bilingual**: Portuguese (BR) and English, configurable via CLI or GUI
- **Reports**: Excel (.xlsx) and PDF with detailed data
- **Security**: keys stored in the OS keyring, files are never uploaded (only hashes)
- **46 detection rules**: AWS keys, GitHub tokens, Discord webhooks, reverse shells, crypto miners, and more

---

## Navigation

| Page | Description |
|------|-------------|
| [Installation](installation.md) | Executables, pip, uv, source code |
| [GUI Guide](gui-guide.md) | How to use the graphical interface |
| [CLI Reference](cli-reference.md) | All commands with examples |
| [Rules Engine](rules-engine.md) | rules.yaml, calibration, rule list |
| [Rust Engine](rust-engine.md) | Compilation and hybrid engine internals |
| [APIs](api-configuration.md) | How to configure VirusTotal, Shodan, etc. |
| [Local AI](ai-integration.md) | Ollama setup and recommended models |
| [Contributing](contributing.md) | How to contribute to the project |
| [Changelog](changelog.md) | Version history |
