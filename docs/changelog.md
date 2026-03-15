# Changelog

## v3.1.0 (2026-03-15)

### Motor de Deteccao Reescrito

As regras de deteccao (`rules.yaml`) foram completamente reescritas com foco em precisao, reduzindo falsos positivos em ~99%.

- 46 regras de deteccao (14 novas), todas compativeis com o motor Rust
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
- Motor Rust embutido nos executaveis

### Interface Renovada

- Visual dark redesenhado
- Layout reorganizado com melhor usabilidade

### Documentacao

- README completamente reescrito
- Documentacao completa com MkDocs Material

---

## v3.0.0 (2025-12-28)

- Motor hibrido Rust + Python via PyO3/Maturin
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
