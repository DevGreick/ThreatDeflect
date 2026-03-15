<div align="center" class="td-hero">
  <img src="https://raw.githubusercontent.com/DevGreick/ThreatDeflect/main/threatlogo.png" alt="ThreatDeflect Logo" width="150" class="td-logo-main"/>
  <h1 class="td-title-animated">ThreatDeflect</h1>
</div>

<div align="center" markdown>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python"></a>
  <a href="https://github.com/DevGreick/ThreatDeflect/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?logo=gnu" alt="License"></a>
  <img src="https://img.shields.io/badge/status-active-success.svg" alt="Status">
  <a href="https://doc.qt.io/qtforpython/"><img src="https://img.shields.io/badge/GUI-PySide6-purple.svg" alt="GUI"></a>
  <img src="https://img.shields.io/badge/engine-Rust+Python-orange.svg?logo=rust" alt="Engine">
</div>

<p align="center" class="td-tagline"><strong>Ferramenta de analise de ameacas com motor hibrido Python + Rust que automatiza a consulta de IOCs, repositorios e arquivos em multiplas fontes, gera relatorios e cria resumos com IA local.</strong></p>

<div align="center">
  <img src="https://raw.githubusercontent.com/DevGreick/ThreatDeflect/main/Abertura.png" alt="Screenshot" width="700"/>
</div>

---

## Comece em 30 Segundos

**1.** Baixe o executavel para o seu sistema na pagina de [Releases](https://github.com/DevGreick/ThreatDeflect/releases)

**2.** Execute o arquivo (veja [Instalacao](installation.md) para instrucoes por plataforma)

**3.** Va em **Configuracoes** e insira a chave do **VirusTotal** para comecar a analisar

---

## O que o ThreatDeflect faz?

### Tres Modulos de Analise

| Modulo | O que faz | Fontes consultadas |
|--------|-----------|--------------------|
| **IOCs** | Consulta massiva de IPs e URLs | VirusTotal, AbuseIPDB, Shodan, URLHaus |
| **Repositorios** | Varredura de repos GitHub/GitLab | Segredos, dependencias, IOCs, padroes suspeitos |
| **Arquivos** | Reputacao por hash SHA256 | VirusTotal, MalwareBazaar |

### Destaques

- **Interface dupla**: GUI completa (PySide6) e CLI robusta (Typer/Rich)
- **Motor hibrido Rust + Python**: deteccao de segredos com performance nativa via PyO3
- **IA local**: resumos executivos com Ollama, sem enviar dados para nuvem
- **Bilingue**: Portugues (BR) e Ingles, configuravel via CLI ou GUI
- **Relatorios**: Excel (.xlsx) e PDF com dados detalhados
- **Seguranca**: chaves no keyring do OS, arquivos nunca sao enviados (apenas hashes)
- **46 regras de deteccao**: chaves AWS, tokens GitHub, webhooks Discord, reverse shells, crypto miners e mais

---

## Navegacao

| Pagina | Descricao |
|--------|-----------|
| [Instalacao](installation.md) | Executaveis, pip, uv, codigo-fonte |
| [Guia da GUI](gui-guide.md) | Como usar a interface grafica |
| [Referencia CLI](cli-reference.md) | Todos os comandos com exemplos |
| [Motor de Regras](rules-engine.md) | rules.yaml, calibragem, lista de regras |
| [Motor Rust](rust-engine.md) | Compilacao e funcionamento do motor hibrido |
| [APIs](api-configuration.md) | Como configurar VirusTotal, Shodan, etc. |
| [IA Local](ai-integration.md) | Setup do Ollama e modelos recomendados |
| [Contribuicao](contributing.md) | Como contribuir com o projeto |
| [Changelog](changelog.md) | Historico de versoes |
