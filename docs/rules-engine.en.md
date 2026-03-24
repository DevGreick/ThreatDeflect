# Rules Engine

ThreatDeflect uses the `rules.yaml` file to control all detection logic. This file defines what is analyzed, what is ignored, and how each finding is classified.

---

## rules.yaml structure

The file has 4 main sections:

### 1. `ignore_patterns`

Defines directories and files that should not be analyzed.

- **directories**: folders such as `node_modules/`, `.venv/`, `dist/`, `docs/`
- **files**: lock files, configs without secrets, binaries, media, known libraries

### 2. `file_scan_targets`

Defines what the scanner should actively look for.

- **interesting_extensions**: extensions that may contain secrets (`.py`, `.js`, `.yml`, `.env`, `.tf`, etc.)
- **dependency_files**: dependency files (`package.json`, `requirements.txt`, `Cargo.toml`, etc.)
- **sensitive_filenames**: files with high probability of containing secrets (`.env`, `credentials.json`, `id_rsa`, etc.)

### 3. `severity_map`

Maps each detection rule to a severity level:

| Level | Meaning |
|-------|---------|
| **CRITICAL** | Direct credential leak with a validatable format |
| **HIGH** | Probable credentials or remote execution vectors |
| **MEDIUM** | Requires context to confirm |
| **LOW** | Weak indicators, depend on validation |

### 4. `rules`

List of detection rules, each with an `id` and a `pattern` (regex).

---

## Detection Rules

### Credentials and Tokens (CRITICAL)

| ID | What it detects |
|----|-----------------|
| Private Key | RSA, ECDSA, OpenSSH, DSA, PGP private keys |
| AWS Key | Access Key IDs (prefixes AKIA, ASIA, AGPA, etc.) |
| AWS Secret Key | Secret Access Keys with assignment context |
| GitHub Token | Tokens ghp_, gho_, ghu_, ghs_, ghr_ |
| GitLab PAT | Personal Access Tokens glpat- |
| Slack Token | Tokens xoxb-, xoxp-, xoxa-, xoxr-, xoxs- |
| Telegram Bot Token | Bot tokens in numeric:alphanumeric format |
| Discord Bot Token | Tokens with M/N + base64 segments format |
| Stripe API Key | Keys sk_live_ |
| Stripe Secret Key | Keys rk_live_ |
| Google Cloud API Key | Keys AIza... |
| Firebase Server Key | Keys AAAA... with long payload |
| Azure Storage Key | AccountKey with 86-88 char base64 |
| DigitalOcean Token | Tokens dop_v1_ |
| Supabase Service Key | Service role keys with JWT |
| NPM Auth Token | Tokens npm_ with context |
| PyPI Token | Tokens pypi- |
| Database Connection String | URIs mongodb://, postgres://, mysql://, redis://, etc. with password |
| GCP Service Account Key | JSON with "type": "service_account" |

### Webhooks and Exfiltration (CRITICAL)

| ID | What it detects |
|----|-----------------|
| Discord Webhook | Discord webhook URLs |
| Slack Incoming Webhook | URLs hooks.slack.com/services/ |
| Crypto Mining | Stratum protocols, xmrig miners, known pools |
| JNDI Injection | Payloads ${jndi:ldap://...} (Log4Shell and variants) |

### Execution and Backdoors (HIGH)

| ID | What it detects |
|----|-----------------|
| Remote Script Execution | curl/wget piped to bash/sh/python |
| Cloud Metadata SSRF | Access to 169.254.169.254, metadata.google.internal |
| Encoded Payload Execution | Base64 decoded and executed via shell |
| Docker Socket Mount | Mount of /var/run/docker.sock (container escape) |
| SSH Key Injection | Writing to authorized_keys |
| NPM Dangerous Hook | pre/postinstall scripts that download and execute payloads |
| PowerShell Encoded | PowerShell with -EncodedCommand and base64 payload |
| Hidden IOC (Base64) | Obfuscated IOCs in Base64 |
| Sensitive File Access | Reading /etc/shadow, sudoers, gshadow |

### Persistence (MEDIUM)

| ID | What it detects |
|----|-----------------|
| Crontab Injection | Adding cron entries |
| Tunnel Service URL | ngrok, Cloudflare Tunnel, localtunnel URLs |
| Unsafe Deserialization | pickle.load, yaml.unsafe_load, unserialize |
| Suspicious Command | Reverse shells (mkfifo, /dev/tcp/, nc -e, socat exec) |

### Weak Indicators (LOW)

| ID | What it detects |
|----|-----------------|
| Generic API Key | api_key/secret_key patterns with quoted values |
| High Entropy String | Strings with entropy > 4.8 (possible secrets) |
| Suspicious JS Keyword | Suspicious keywords in JavaScript |
| Invisible Whitespace | Invisible Unicode characters used for obfuscation |

---

## Calibration

### Reducing false positives

If the scanner is generating too much noise in your project:

1. Add specific directories to `ignore_patterns.directories`
2. Add files to `ignore_patterns.files`
3. Adjust rule patterns to require more context

### Adding custom rules

To add a new rule:

```yaml
rules:
  - id: Minha Regra Custom
    pattern: '(?i)(meu_padrao)\s*[:=]\s*["''][a-zA-Z0-9]{32}["'']'
```

Then add the severity mapping:

```yaml
severity_map:
  Minha Regra Custom: HIGH
```

!!! warning "Rust Compatibility"
    Patterns must be compatible with the Rust `regex` crate. This means: no lookbehind (`(?<!...)`), no lookahead (`(?!...)`). Use word boundaries (`\b`) as an alternative.
