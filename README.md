<div align="center">
  <h1>🛡️ ThreatDeflect</h1>
  <img src="https://github.com/DevGreick/ThreatDeflect/blob/main/spy2-1.png" alt="Logo do ThreatDeflect" width="150"/>
</div>

<div align="center">
<strong>Ferramenta de análise de ameaças com motor híbrido Python + Rust que automatiza a consulta de IOCs, repositórios e arquivos em múltiplas fontes, gera relatórios e cria resumos com IA local.</strong>
<br><br>
⭐ Dê uma estrela se o projeto te ajudou! | <a href="https://github.com/DevGreick/ThreatDeflect/releases"><strong>Baixar a Última Versão »</strong></a> | <a href="https://devgreick.github.io/ThreatDeflect/"><strong>Documentação Completa »</strong></a>
</div>

<br>

<div align="center">
<a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python Version"></a>
<a href="https://github.com/DevGreick/ThreatDeflect/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?logo=gnu" alt="License"></a>
<img src="https://img.shields.io/badge/status-active-success.svg" alt="Project Status">
<a href="https://doc.qt.io/qtforpython/"><img src="https://img.shields.io/badge/GUI-PySide6-purple.svg" alt="GUI Framework"></a>
<img src="https://img.shields.io/badge/engine-Rust+Python-orange.svg?logo=rust" alt="Rust Engine">
<a href="https://devgreick.github.io/ThreatDeflect/contributing/"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg" alt="Contributions"></a>
</div>

<br>
<div align="center">
<img src="https://github.com/DevGreick/ThreatDeflect/blob/main/Abertura.png" alt="Screenshot da interface do ThreatDeflect" width="700"/>
</div>

---

## ⚡ Instale em 30 Segundos

Baixe o executável na página de [Releases](https://github.com/DevGreick/ThreatDeflect/releases). Não precisa de Python.

| Sistema | Arquivo | Execução |
|---------|---------|----------|
| Windows | `ThreatDeflect-GUI-Windows.exe` | Duplo clique |
| Linux   | `ThreatDeflect-CLI-Linux` | `chmod +x` e execute |
| macOS   | `ThreatDeflect-CLI-macOS` | `chmod +x && xattr -cr` no terminal |

> Após abrir, vá em **Configurações** e insira a chave do **VirusTotal** para começar.

---

## 🚀 O que faz

| Módulo | O que faz | Fontes |
|--------|-----------|----|
| **IOCs** | Consulta massiva de IPs e URLs | VirusTotal, AbuseIPDB, Shodan, URLHaus |
| **Repositórios** | Varredura de repos GitHub/GitLab | Segredos, dependências, IOCs, padrões suspeitos |
| **Arquivos** | Reputação por hash SHA256 | VirusTotal, MalwareBazaar |

### Destaques

- **GUI + CLI** completas e bilíngues (PT-BR / EN-US)
- **Motor Rust** para detecção de alta performance via PyO3
- **IA local** com Ollama para resumos executivos (nenhum dado sai da sua máquina)
- **46 regras de detecção** para segredos, backdoors, crypto miners, SSRF e mais
- **Relatórios** em Excel e PDF
- **Chaves seguras** no keyring do sistema operacional

---

## 💻 Uso Rápido

```bash
# CLI
threatdeflect ioc 8.8.8.8 --ai llama3
threatdeflect repo https://github.com/org/repo
threatdeflect file suspicious.exe

# GUI
threatdeflect-gui
```

---

## 📦 Instalação pelo Código-Fonte

```bash
git clone https://github.com/DevGreick/ThreatDeflect.git
cd ThreatDeflect
uv sync
uv run threatdeflect --help
uv run threatdeflect-gui
```

---

## 📖 Documentação

Para guias detalhados, referência completa do CLI, configuração de APIs, motor de regras, integração com IA e mais:

**[devgreick.github.io/ThreatDeflect](https://devgreick.github.io/ThreatDeflect/)**

---

## ⚖️ Segurança e Privacidade

- IPs e URLs são enviados para as APIs configuradas
- Arquivos **nunca são enviados**, apenas hashes SHA256
- Resumos de IA são gerados **localmente** via Ollama
- Chaves armazenadas no keyring do OS

---

## 🤝 Contribuição

1. Fork → Branch → Commit → PR

Detalhes na [documentação de contribuição](https://devgreick.github.io/ThreatDeflect/contributing/).

---

<div align="center">
<a href="https://buymeacoffee.com/devgreick" target="_blank">
<img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" width="200">
</a>
</div>

---

## 📜 Licença

Distribuído sob a licença GPLv3. Consulte o arquivo [LICENSE](./LICENSE) para mais informações.
