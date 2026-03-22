# Rules Engine

O ThreatDeflect usa o arquivo `rules.yaml` para controlar toda a logica de deteccao. Este arquivo define o que e analisado, o que e ignorado e como cada achado e classificado.

---

## Estrutura do rules.yaml

O arquivo possui 4 secoes principais:

### 1. `ignore_patterns`

Define diretorios e arquivos que nao devem ser analisados.

- **directories**: pastas como `node_modules/`, `.venv/`, `dist/`, `docs/`
- **files**: lock files, configs sem segredos, binarios, media, libs conhecidas

### 2. `file_scan_targets`

Define o que o scanner deve procurar ativamente.

- **interesting_extensions**: extensoes que podem conter segredos (`.py`, `.js`, `.yml`, `.env`, `.tf`, etc.)
- **dependency_files**: arquivos de dependencia (`package.json`, `requirements.txt`, `Cargo.toml`, etc.)
- **sensitive_filenames**: arquivos com alta probabilidade de conter segredos (`.env`, `credentials.json`, `id_rsa`, etc.)

### 3. `severity_map`

Mapeia cada regra de deteccao para um nivel de severidade:

| Nivel | Significado |
|-------|-------------|
| **CRITICAL** | Vazamento direto de credenciais com formato validavel |
| **HIGH** | Credenciais provaveis ou vetores de execucao remota |
| **MEDIUM** | Requer contexto para confirmar |
| **LOW** | Indicadores fracos, dependem de validacao |

### 4. `rules`

Lista de regras de deteccao, cada uma com um `id` e um `pattern` (regex).

---

## Regras de Deteccao

### Credenciais e Tokens (CRITICAL)

| ID | O que detecta |
|----|---------------|
| Private Key | Chaves privadas RSA, ECDSA, OpenSSH, DSA, PGP |
| AWS Key | Access Key IDs (prefixos AKIA, ASIA, AGPA, etc.) |
| AWS Secret Key | Secret Access Keys com contexto de atribuicao |
| GitHub Token | Tokens ghp_, gho_, ghu_, ghs_, ghr_ |
| GitLab PAT | Personal Access Tokens glpat- |
| Slack Token | Tokens xoxb-, xoxp-, xoxa-, xoxr-, xoxs- |
| Telegram Bot Token | Tokens de bot no formato numerico:alfanumerico |
| Discord Bot Token | Tokens com formato M/N + base64 segments |
| Stripe API Key | Chaves sk_live_ |
| Stripe Secret Key | Chaves rk_live_ |
| Google Cloud API Key | Chaves AIza... |
| Firebase Server Key | Chaves AAAA... com payload longo |
| Azure Storage Key | AccountKey com base64 de 86-88 chars |
| DigitalOcean Token | Tokens dop_v1_ |
| Supabase Service Key | Service role keys com JWT |
| NPM Auth Token | Tokens npm_ com contexto |
| PyPI Token | Tokens pypi- |
| Database Connection String | URIs mongodb://, postgres://, mysql://, redis://, etc. com senha |
| GCP Service Account Key | JSON com "type": "service_account" |

### Webhooks e Exfiltracao (CRITICAL)

| ID | O que detecta |
|----|---------------|
| Discord Webhook | URLs de webhook do Discord |
| Slack Incoming Webhook | URLs hooks.slack.com/services/ |
| Crypto Mining | Protocolos stratum, mineradores xmrig, pools conhecidos |
| JNDI Injection | Payloads ${jndi:ldap://...} (Log4Shell e variantes) |

### Execucao e Backdoors (HIGH)

| ID | O que detecta |
|----|---------------|
| Remote Script Execution | curl/wget com pipe para bash/sh/python |
| Cloud Metadata SSRF | Acesso a 169.254.169.254, metadata.google.internal |
| Encoded Payload Execution | Base64 decodificado e executado via shell |
| Docker Socket Mount | Mount de /var/run/docker.sock (escape de container) |
| SSH Key Injection | Escrita em authorized_keys |
| NPM Dangerous Hook | Scripts pre/postinstall que baixam e executam payloads |
| PowerShell Encoded | PowerShell com -EncodedCommand e payload base64 |
| Hidden IOC (Base64) | IOCs ofuscados em Base64 |
| Sensitive File Access | Leitura de /etc/shadow, sudoers, gshadow |

### Persistencia (MEDIUM)

| ID | O que detecta |
|----|---------------|
| Crontab Injection | Adicao de entries no cron |
| Tunnel Service URL | URLs ngrok, Cloudflare Tunnel, localtunnel |
| Unsafe Deserialization | pickle.load, yaml.unsafe_load, unserialize |
| Suspicious Command | Reverse shells (mkfifo, /dev/tcp/, nc -e, socat exec) |

### Indicadores Fracos (LOW)

| ID | O que detecta |
|----|---------------|
| Generic API Key | Padroes api_key/secret_key com valor entre aspas |
| High Entropy String | Strings com entropia > 4.8 (possiveis segredos) |
| Suspicious JS Keyword | Palavras-chave suspeitas em JavaScript |
| Invisible Whitespace | Caracteres Unicode invisiveis usados para ofuscacao |

---

## Calibragem

### Reduzindo falsos positivos

Se o scanner esta gerando muito ruido no seu projeto:

1. Adicione diretorios especificos em `ignore_patterns.directories`
2. Adicione arquivos em `ignore_patterns.files`
3. Ajuste os patterns das regras para exigir mais contexto

### Adicionando regras customizadas

Para adicionar uma nova regra:

```yaml
rules:
  - id: Minha Regra Custom
    pattern: '(?i)(meu_padrao)\s*[:=]\s*["''][a-zA-Z0-9]{32}["'']'
```

Depois adicione o mapeamento de severidade:

```yaml
severity_map:
  Minha Regra Custom: HIGH
```

!!! warning "Compatibilidade Rust"
    Os patterns devem ser compativeis com o crate `regex` do Rust. Isso significa: sem lookbehind (`(?<!...)`), sem lookahead (`(?!...)`). Use word boundaries (`\b`) como alternativa.
