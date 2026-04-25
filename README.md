<div align="center">
    <img src="https://github.com/DevGreick/ThreatDeflect/blob/main/threatdeflect-logo.png" alt="ThreatDeflect Logo" width="150"/>
    <h1>ThreatDeflect</h1>
</div>

<div align="center">

🔍 Análise de ameaças com engine híbrido Python + Rust. Consulta IOCs, varre repositórios, gera relatórios e cria resumos com IA local.

<br>

<a href="https://github.com/DevGreick/ThreatDeflect/releases"><strong>📥 Baixar »</strong></a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="https://devgreick.github.io/ThreatDeflect/"><strong>📖 Documentação »</strong></a>

<br>
⭐ Dê uma estrela se te ajudou!

<br><br>

<a href="README.md"><img src="https://img.shields.io/badge/lang-Portugu%C3%AAs-009c3b?style=for-the-badge" alt="Português"></a>
<a href="README.en.md"><img src="https://img.shields.io/badge/lang-English-grey?style=for-the-badge" alt="English"></a>

</div>

<div align="center">
<a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python Version"></a>
<a href="https://github.com/DevGreick/ThreatDeflect/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?logo=gnu" alt="License"></a>
<img src="https://img.shields.io/badge/status-active-success.svg" alt="Project Status">
<a href="https://doc.qt.io/qtforpython/"><img src="https://img.shields.io/badge/GUI-PySide6-purple.svg" alt="GUI Framework"></a>
<img src="https://img.shields.io/badge/engine-Rust+Python-orange.svg?logo=rust" alt="Rust Engine">
<a href="https://crates.io/crates/threatdeflect-core"><img src="https://img.shields.io/crates/v/threatdeflect-core.svg?logo=rust&label=crates.io" alt="Crates.io"></a>
</div>

<br>
<div align="center">
<img src="https://github.com/DevGreick/ThreatDeflect/blob/main/Abertura.png" alt="Screenshot" width="700"/>
</div>

---

## O que faz

- **Análise de IOCs** via VirusTotal, AbuseIPDB, Shodan, URLHaus
- **Varredura de repositórios** GitHub/GitLab (segredos, backdoors, dependências maliciosas)
- **Reputação de arquivos** por hash SHA256
- **46 regras de detecção** para segredos, crypto miners, SSRF, reverse shells e mais
- **Rust engine** de alta performance via PyO3
- **IA local** com Ollama (nenhum dado sai da sua máquina)
- **GUI + CLI** bilíngues (PT-BR / EN-US)
- **Relatórios** em Excel e PDF

## Instalação

### Opção 1 — Executável (sem Python)

Baixe o binário da página de [Releases](https://github.com/DevGreick/ThreatDeflect/releases) e execute:

**Windows:** clique duplo em `ThreatDeflect-GUI-Windows.exe`

**Linux:**

```bash
chmod +x ThreatDeflect-GUI-Linux
./ThreatDeflect-GUI-Linux
# opcional: mover para o PATH
sudo mv ThreatDeflect-GUI-Linux /usr/local/bin/threatdeflect
```

**macOS:**

```bash
xattr -cr ThreatDeflect-GUI-macOS
./ThreatDeflect-GUI-macOS
```

### Opção 2 — Código-fonte (Python 3.11+)

**Com uv (recomendado):**

```bash
git clone https://github.com/DevGreick/ThreatDeflect.git
cd ThreatDeflect
uv sync
uv run threatdeflect --help
uv run threatdeflect-gui
```

**Com pip:**

```bash
git clone https://github.com/DevGreick/ThreatDeflect.git
cd ThreatDeflect
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

Para tópicos avançados (Rust engine, regras customizadas, Ollama), consulte a **[documentação completa](https://devgreick.github.io/ThreatDeflect/)**.

## Configuração de APIs

Apenas o **VirusTotal** é obrigatório. As demais ampliam a cobertura de análise.

| Serviço | Obrigatório | Limite gratuito | Onde obter |
|---|---|---|---|
| VirusTotal | **Sim** | 500 req/dia | [virustotal.com](https://www.virustotal.com) → perfil → API Key |
| GitHub | Recomendado | 5.000 req/h | [github.com/settings/tokens](https://github.com/settings/tokens) (public read) |
| GitLab | Recomendado | — | Settings → Access Tokens → `read_api` |
| AbuseIPDB | Opcional | 1.000 checks/dia | [abuseipdb.com](https://www.abuseipdb.com) → API |
| Shodan | Opcional | Limitado | [shodan.io](https://www.shodan.io) → dashboard |
| URLHaus | Opcional | Ilimitado | Gratuito, sem autenticação |
| MalwareBazaar | Opcional | Ilimitado | Gratuito, sem autenticação |

**Configurando via CLI:**

```bash
threatdeflect config set virustotal  SUA_CHAVE
threatdeflect config set abuseipdb   SUA_CHAVE
threatdeflect config set shodan      SUA_CHAVE
threatdeflect config set github      SEU_TOKEN
threatdeflect config set gitlab      SEU_TOKEN
```

**Ou via GUI:** Configurações → aba "API Keys" → cole as chaves nos campos correspondentes.

As chaves ficam armazenadas no keyring do sistema operacional (Windows Credential Locker, macOS Keychain, Linux Secret Service).

## Uso

### Analisar IPs e URLs (IOCs)

```bash
# alvo único
threatdeflect ioc 8.8.8.8

# múltiplos alvos
threatdeflect ioc 8.8.8.8 1.1.1.1 https://dominio-suspeito.com

# a partir de arquivo (um alvo por linha)
threatdeflect ioc -f targets.txt -o relatorio.xlsx

# com resumo por IA local
threatdeflect ioc -f targets.txt --ai llama3
```

### Verificar arquivos por hash

```bash
threatdeflect file suspeito.exe
threatdeflect file malware.dll trojan.pdf --ai llama3 -o auditoria.xlsx
```

> Nenhum arquivo é enviado, a verificação é feita apenas pelo hash SHA256.

### Varrer repositórios

```bash
threatdeflect repo https://github.com/org/repo
threatdeflect repo https://github.com/org/repo https://gitlab.com/org/repo2 --ai mistral
```

### Ver configurações atuais

```bash
threatdeflect config show
```

## IA local (opcional)

Com [Ollama](https://ollama.com) instalado, o ThreatDeflect gera resumos executivos dos relatórios sem enviar dados para a nuvem:

```bash
ollama pull llama3
threatdeflect ioc -f targets.txt --ai llama3
```

## Crate Rust (uso independente)

O detection engine é publicado como crate independente no [crates.io](https://crates.io/crates/threatdeflect-core), permitindo integração direta em projetos Rust sem depender do Python:

```toml
[dependencies]
threatdeflect-core = "0.1"
```

```rust
use threatdeflect_core::SecretAnalyzer;

let rules = vec![("AWS Key".to_string(), r"AKIA[0-9A-Z]{16}".to_string())];
let analyzer = SecretAnalyzer::new(rules, vec![])?;
let result = analyzer.analyze_content("key = AKIAIOSFODNN7EXAMPLE1", "config.py", "config.py");
```

Documentação da crate: [docs.rs/threatdeflect-core](https://docs.rs/threatdeflect-core)

## Licença

GPLv3. Veja [LICENSE](./LICENSE).

<div align="center">
<a href="https://buymeacoffee.com/devgreick" target="_blank">
<img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" width="200">
</a>
</div>
