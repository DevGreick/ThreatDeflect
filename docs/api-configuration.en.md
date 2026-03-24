# API Configuration

## Overview

| Service | Requirement | What it enables |
|---------|-------------|-----------------|
| **VirusTotal** | Required | IP, URL and file reputation |
| **GitHub** | Recommended | Repository analysis (rate limit 5000 req/hr) |
| **GitLab** | Recommended | GitLab repository analysis |
| **AbuseIPDB** | Optional | IP abuse score |
| **Shodan** | Optional | Open ports and services |
| **URLHaus** | Optional | URLs used to distribute malware |
| **MalwareBazaar** | Optional | Threat identification by hash |
| **Ollama** | Optional | Automated summaries with local AI |

---

## How to obtain the keys

### VirusTotal (required)

1. Create an account at [virustotal.com](https://www.virustotal.com)
2. Go to your profile and copy the API Key
3. Free plan: 500 requests/day

### GitHub

1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. Generate a token with public read permission
3. Increases the rate limit from 60 to 5000 req/hr

### GitLab

1. Go to Settings > Access Tokens on GitLab
2. Create a token with `read_api` scope

### AbuseIPDB

1. Register at [abuseipdb.com](https://www.abuseipdb.com)
2. Go to API > Create Key
3. Free plan: 1000 checks/day

### Shodan

1. Create an account at [shodan.io](https://www.shodan.io)
2. The API Key is on the dashboard
3. Free plan available

### URLHaus

1. Register at [urlhaus.abuse.ch](https://urlhaus.abuse.ch)
2. The API is free and has no rate limit

### MalwareBazaar

1. Free API at [bazaar.abuse.ch](https://bazaar.abuse.ch)
2. No authentication required for hash lookups

---

## Configuring the keys

=== "CLI"

    ```bash
    threatdeflect config set virustotal SUA_CHAVE
    threatdeflect config set github SEU_TOKEN
    threatdeflect config set abuseipdb SUA_CHAVE
    threatdeflect config set shodan SUA_CHAVE
    threatdeflect config show
    ```

=== "GUI"

    1. Click **Settings** in the top right corner
    2. Navigate to the **API Keys** tab
    3. Paste each key in the corresponding field
    4. Keys are saved automatically

---

## Secure storage

Keys are stored in the operating system's keyring:

| System | Backend |
|--------|---------|
| Windows | Credential Locker |
| macOS | Keychain |
| Linux | Secret Service (GNOME Keyring, KWallet) |

Keys are never saved in text files or environment variables.

---

## Cache

ThreatDeflect uses SQLite cache to avoid repeated API queries. The cache is stored in the `.threatdeflect_cache/` subfolder in the executable's directory.

This preserves your request quota and speeds up recurring analyses.

To clear the cache in the GUI, use the **Clear** button in the IOCs tab.
