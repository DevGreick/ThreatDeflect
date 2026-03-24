# CLI Reference

## General usage

```bash
threatdeflect [COMMAND] [OPTIONS]
```

To see help for any command:

```bash
threatdeflect --help
threatdeflect ioc --help
threatdeflect config --help
```

### Language

The CLI supports Portuguese (BR) and English (US). To switch:

```bash
threatdeflect config set-lang pt_br   # Portugues
threatdeflect config set-lang en_us   # Ingles
```

---

## `threatdeflect ioc`

IOC analysis (IPs, URLs, domains).

```bash
threatdeflect ioc [TARGETS...] [OPTIONS]
```

| Argument / Option | Description |
|-------------------|-------------|
| `TARGETS` | One or more IPs, URLs, or domains separated by spaces |
| `--file`, `-f` | Path to a file containing targets (one per line) |
| `--output`, `-o` | Output report path (default: `Analise_IOCs.xlsx`) |
| `--ai` | Ollama model for generating a summary (e.g., `llama3`, `gpt-oss:20b`) |

### Examples

```bash
# Simple analysis
threatdeflect ioc 8.8.8.8

# Multiple targets with AI summary
threatdeflect ioc 8.8.8.8 1.1.1.1 https://evil.com --ai gpt-oss:20b

# From a file
threatdeflect ioc -f targets.txt -o relatorio.xlsx
```

---

## `threatdeflect file`

File analysis by SHA256 hash. The hash is computed locally and looked up on VirusTotal and MalwareBazaar. **No files are uploaded.**

```bash
threatdeflect file FILE [FILE...] [OPTIONS]
```

| Argument / Option | Description |
|-------------------|-------------|
| `FILE` | One or more local file paths |
| `--output`, `-o` | Report path (default: `Analise_Arquivos.xlsx`) |
| `--ai` | Ollama model for generating a summary |

### Examples

```bash
threatdeflect file suspicious.exe
threatdeflect file malware.dll trojan.pdf --ai llama3 -o audit.xlsx
```

---

## `threatdeflect repo`

GitHub and GitLab repository analysis. Detects exposed secrets, vulnerable dependencies, IOCs, and suspicious patterns via API, without cloning.

```bash
threatdeflect repo URL [URL...] [OPTIONS]
```

| Argument / Option | Description |
|-------------------|-------------|
| `URL` | One or more GitHub or GitLab repository URLs |
| `--output`, `-o` | Report path (default: `Analise_Repositorios.xlsx`) |
| `--ai` | Ollama model for generating a summary |

### Examples

```bash
threatdeflect repo https://github.com/org/repo
threatdeflect repo https://github.com/org/repo1 https://gitlab.com/org/repo2 --ai mistral
```

---

## `threatdeflect config`

Configuration management.

| Subcommand | Description | Example |
|------------|-------------|---------|
| `config set SERVICE KEY` | Sets an API key | `config set virustotal YOUR_KEY` |
| `config set-ollama URL` | Sets the Ollama endpoint | `config set-ollama http://localhost:11434/api/generate` |
| `config set-log-path PATH` | Sets the log path | `config set-log-path /var/log/td.log` |
| `config set-lang LANG` | Sets the language | `config set-lang en_us` |
| `config show` | Displays all configurations | `config show` |

### Available services

`virustotal` . `abuseipdb` . `urlhaus` . `shodan` . `malwarebazaar` . `github` . `gitlab`

### Initial configuration example

```bash
threatdeflect config set virustotal SUA_CHAVE_VT
threatdeflect config set abuseipdb SUA_CHAVE_ABUSE
threatdeflect config set github SEU_TOKEN_GH
threatdeflect config set-lang pt_br
threatdeflect config show
```

!!! info "Security"
    Keys are stored in the operating system's keyring, not in text files.

---

## Platform examples

=== "Linux / macOS"

    ```bash
    threatdeflect ioc 8.8.8.8 --ai llama3
    threatdeflect file ~/Downloads/suspicious.bin
    threatdeflect repo https://github.com/org/repo -o audit.xlsx
    ```

=== "Windows (PowerShell)"

    ```powershell
    threatdeflect ioc 8.8.8.8 --ai gpt-oss:20b
    threatdeflect file C:\Users\User\Downloads\suspicious.exe
    threatdeflect repo https://github.com/org/repo -o C:\Users\User\Desktop\report.xlsx
    ```
