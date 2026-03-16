<div align="center">
    <img src="https://github.com/DevGreick/ThreatDeflect/blob/main/threatdeflect-logo.png" alt="Logo do ThreatDeflect" width="150"/>
    <h1>ThreatDeflect</h1>
</div>

<div align="center">
<strong>Ferramenta de analise de ameacas com motor hibrido Python + Rust que automatiza a consulta de IOCs, repositorios e arquivos em multiplas fontes, gera relatorios e cria resumos com IA local.</strong>
<br><br>
⭐ De uma estrela se o projeto te ajudou! | <a href="https://github.com/DevGreick/ThreatDeflect/releases"><strong>Baixar »</strong></a> | <a href="https://devgreick.github.io/ThreatDeflect/"><strong>Documentacao completa »</strong></a>
</div>

<br>

<div align="center">
<a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python Version"></a>
<a href="https://github.com/DevGreick/ThreatDeflect/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?logo=gnu" alt="License"></a>
<img src="https://img.shields.io/badge/status-active-success.svg" alt="Project Status">
<a href="https://doc.qt.io/qtforpython/"><img src="https://img.shields.io/badge/GUI-PySide6-purple.svg" alt="GUI Framework"></a>
<img src="https://img.shields.io/badge/engine-Rust+Python-orange.svg?logo=rust" alt="Rust Engine">
</div>

<br>
<div align="center">
<img src="https://github.com/DevGreick/ThreatDeflect/blob/main/Abertura.png" alt="Screenshot" width="700"/>
</div>

---

## O que faz

- **Analise de IOCs** via VirusTotal, AbuseIPDB, Shodan, URLHaus
- **Varredura de repositorios** GitHub/GitLab (segredos, backdoors, dependencias maliciosas)
- **Reputacao de arquivos** por hash SHA256
- **46 regras de deteccao** para segredos, crypto miners, SSRF, reverse shells e mais
- **Motor Rust** de alta performance via PyO3
- **IA local** com Ollama (nenhum dado sai da sua maquina)
- **GUI + CLI** bilingues (PT-BR / EN-US)
- **Relatorios** em Excel e PDF

---

## Instalacao

### Opcao 1 — Executavel (sem Python)

Baixe o binario da pagina de [Releases](https://github.com/DevGreick/ThreatDeflect/releases) e execute:

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

### Opcao 2 — Codigo-fonte (Python 3.11+)

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

Para topicos avancados (motor Rust, regras customizadas, Ollama), consulte a **[Documentacao completa](https://devgreick.github.io/ThreatDeflect/)**.

---

## Configuracao de APIs

Apenas o **VirusTotal** e obrigatorio. As demais ampliam a cobertura de analise.

| Servico | Obrigatorio | Limite gratuito | Onde obter |
|---|---|---|---|
| VirusTotal | **Sim** | 500 req/dia | [virustotal.com](https://www.virustotal.com) → perfil → API Key |
| GitHub | Recomendado | 5.000 req/h | [github.com/settings/tokens](https://github.com/settings/tokens) (public read) |
| GitLab | Recomendado | — | Settings → Access Tokens → `read_api` |
| AbuseIPDB | Opcional | 1.000 checks/dia | [abuseipdb.com](https://www.abuseipdb.com) → API |
| Shodan | Opcional | Limitado | [shodan.io](https://www.shodan.io) → dashboard |
| URLHaus | Opcional | Ilimitado | Gratuito, sem autenticacao |
| MalwareBazaar | Opcional | Ilimitado | Gratuito, sem autenticacao |

**Configurando via CLI:**
```bash
threatdeflect config set virustotal  SUA_CHAVE
threatdeflect config set abuseipdb   SUA_CHAVE
threatdeflect config set shodan      SUA_CHAVE
threatdeflect config set github      SEU_TOKEN
threatdeflect config set gitlab      SEU_TOKEN
```

**Ou via GUI:** Configuracoes → Aba "API Keys" → cole as chaves nos campos correspondentes.

As chaves ficam armazenadas no keyring do sistema operacional (Windows Credential Locker, macOS Keychain, Linux Secret Service).

---

## Uso

### Analisar IPs e URLs (IOCs)

```bash
# alvo unico
threatdeflect ioc 8.8.8.8

# multiplos alvos
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

> Nenhum arquivo e enviado — a verificacao e feita apenas pelo hash SHA256.

### Varrer repositorios

```bash
threatdeflect repo https://github.com/org/repo
threatdeflect repo https://github.com/org/repo https://gitlab.com/org/repo2 --ai mistral
```

### Ver configuracoes atuais

```bash
threatdeflect config show
```

---

## IA local (opcional)

Com [Ollama](https://ollama.com) instalado, o ThreatDeflect gera resumos executivos dos relatorios sem enviar dados para a nuvem:

```bash
ollama pull llama3
threatdeflect ioc -f targets.txt --ai llama3
```

---

## Licenca

GPLv3. Veja [LICENSE](./LICENSE).

<div align="center">
<a href="https://buymeacoffee.com/devgreick" target="_blank">
<img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" width="200">
</a>
</div>
