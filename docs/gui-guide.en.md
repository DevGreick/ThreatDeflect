# GUI Guide

## Getting Started

```bash
threatdeflect-gui
# or with uv:
uv run threatdeflect-gui
```

The interface has tabs for each type of analysis and a settings area.

---

## IOC Analysis

Allows you to look up IPs, URLs, and domains across multiple threat intelligence sources.

1. Open the **IOC Analysis** tab
2. Paste the indicators (one per line) or click **Import from File**
3. Click **Analyze Targets**

```
185.172.128.150
https://some-random-domain.net/path
8.8.8.8
```

The app queries the APIs in parallel and generates an Excel report with the results.

### File Reputation Check

In the same tab, click **Check File Reputation** to verify local files. ThreatDeflect calculates the SHA256 hash locally and queries VirusTotal and MalwareBazaar. **No files are uploaded.**

---

## Repository Analysis

Allows you to scan GitHub and GitLab repositories for secrets, vulnerable dependencies, IOCs, and suspicious patterns.

1. Open the **Repository Analysis** tab
2. Paste the repository URLs (one per line)
3. Click **Analyze Repositories**

```
https://github.com/org/repo
```

!!! info "No cloning"
    The analysis is performed via API, without needing to clone the entire repository.

---

## Activity Console

Displays real-time logs during analysis. Useful for tracking progress and identifying errors.

---

## AI Summary

In the **AI-Generated Summary** tab, you can generate executive summaries using local Ollama models.

1. Select the model from the list (e.g., `llama3:8b`, `gpt-oss:20b`, `mistral`)
2. Click **Generate Text Summary** or **Generate PDF Summary**

!!! tip "Privacy"
    All summaries are generated locally. No data is sent to cloud services.

---

## Updates

The **Updates** tab automatically checks for new available versions and displays the release notes.

---

## Settings

Access via the **Settings** button in the top-right corner.

### Available Tabs

| Tab | Contents |
|-----|----------|
| **General** | Log path, language (PT-BR / EN-US) |
| **API Keys** | VirusTotal, AbuseIPDB, URLHaus, Shodan, MalwareBazaar, GitHub, GitLab |
| **Ollama** | Ollama endpoint, connection test |
| **About** | Version, author, license |

### Language

ThreatDeflect supports Portuguese (BR) and English (US). Switch the language in the General tab of the settings. The change is applied immediately.

### Key Storage

API keys are stored in the operating system's keyring:

- **Windows**: Credential Locker
- **macOS**: Keychain
- **Linux**: Secret Service (GNOME Keyring, KWallet)
