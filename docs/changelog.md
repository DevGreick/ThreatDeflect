# Changelog

## v3.2.0 (2026-03-22)

### Crate Rust Publicada

- Detection engine extraido para crate independente [`threatdeflect-core`](https://crates.io/crates/threatdeflect-core) no crates.io
- Cargo workspace com dois crates: `threatdeflect-core` (lib pura) e `rust_core` (wrapper PyO3)
- Qualquer projeto Rust pode usar o detection engine sem depender do Python

### Correlacao de Findings

- Novo sistema de correlacao que cruza findings no mesmo arquivo
- `eval` + URL externa no mesmo arquivo = promovido para HIGH automaticamente
- Payload ofuscado (alta entropia) + URL externa = promovido para HIGH

### Deteccao de Ofuscacao

- **Hidden IOC (Hex)**: detecta URLs e secrets escondidos em strings hexadecimais (`0x68747470...` ou `\x68\x74\x74\x70...`)
- **Hidden IOC (URL Encoded)**: detecta connection strings ofuscadas com percent-encoding (`postgres%3A%2F%2F...`)
- **Hidden IOC (Char Array)**: detecta URLs e secrets escondidos em arrays de char codes (`[104,116,116,112,...]`)

### Novas Regras de Deteccao

- **Remote Code Loading**: detecta padroes de fetch + eval/exec (supply chain attack)
- **Paste Service C2**: detecta URLs de npoint.io, pastebin.com e 15+ servicos de paste usados como C2/staging
- `Suspicious JS Keyword` promovido de LOW para MEDIUM
- `High Entropy String` promovido de LOW para MEDIUM
- Severity boost automatico para findings HIGH/CRITICAL com confidence baixa do Rust

### Seguranca de Memoria

- `zeroize` no `Drop` de `Finding` e `Ioc` (secrets limpos da memoria)
- `serde(deny_unknown_fields)` em todos os tipos deserializaveis
- `finding_type` agora usa o ID real da regra em vez de "Suspicious Command" generico

### Documentacao

- README atualizado com badge crates.io e secao de uso da crate Rust
- `rust-engine.md` reescrito com exemplo de uso, arquitetura do workspace e tabela de seguranca

---

## v3.1.0 (2026-03-15)

### Detection Engine Reescrito

As regras de deteccao (`rules.yaml`) foram completamente reescritas com foco em precisao, reduzindo falsos positivos em ~99%.

- 46 regras de deteccao (14 novas), todas compativeis com o Rust engine
- Novas regras: AWS Secret Key, Telegram Bot Token, Discord Bot Token, Stripe, Firebase, Azure Storage, DigitalOcean, Supabase, SendGrid, Mailgun, Datadog, NPM Auth Token, PyPI Token, Database Connection String
- Novas regras de ataque: Discord Webhook, Slack Webhook, Cloud Metadata SSRF, Crypto Mining, JNDI Injection, Encoded Payload Execution, Docker Socket Mount, SSH Key Injection, Crontab Injection, Sensitive File Access, GCP Service Account Key, Tunnel Service URL, Unsafe Deserialization
- Regras como JWT, Heroku e comandos suspeitos agora exigem contexto
- 93 diretorios ignorados, 148 arquivos ignorados, 60 nomes sensiveis

### CLI Completo e Bilingue

- Help (`--help`) com descricoes detalhadas e exemplos para todos os comandos
- Traducao completa para Portugues (pt-br) e Ingles (en-us), incluindo labels internos do Typer/Rich
- Troca de idioma via `threatdeflect config set-lang pt_br`

### Build Multiplataforma

- Executaveis standalone para Linux, Windows e macOS
- Pipeline CI/CD automatizado com GitHub Actions (PyInstaller + Maturin/PyO3)
- Rust engine embutido nos executaveis

### Interface Renovada

- Visual dark redesenhado
- Layout reorganizado com melhor usabilidade

### Documentacao

- README completamente reescrito
- Documentacao completa com MkDocs Material

---

## v3.0.0 (2025-12-28)

- Hybrid Rust + Python engine via PyO3/Maturin
- Interface GUI redesenhada com PySide6
- CLI com Typer e Rich
- Integracao com Ollama para IA local
- Cache SQLite para otimizar uso de APIs
- Relatorios em Excel e PDF

---

## v2.0.0

- Reescrita completa da ferramenta
- Adicao de analise de repositorios
- Multiplas fontes de inteligencia (VirusTotal, AbuseIPDB, Shodan, URLHaus, MalwareBazaar)

---

## v1.0.0

- Release inicial
- Analise basica de IOCs via VirusTotal
