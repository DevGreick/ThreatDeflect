<div align="center">
  <h1>🛡️ ThreatDeflect</h1>
  <img src="https://github.com/DevGreick/ThreatDeflect/blob/main/threatdeflect-logo.png" alt="Logo do ThreatDeflect" width="150"/>
</div>

<div align="center">
<strong>Ferramenta de análise de ameaças com motor híbrido Python + Rust que automatiza a consulta de IOCs, repositórios e arquivos em múltiplas fontes, gera relatórios e cria resumos com IA local.</strong>
<br><br>
<a href="https://github.com/DevGreick/ThreatDeflect/releases"><strong>Baixar »</strong></a> | <a href="https://devgreick.github.io/ThreatDeflect/"><strong>Documentação »</strong></a>
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

## Inicio Rapido

**Executavel:** Baixe na pagina de [Releases](https://github.com/DevGreick/ThreatDeflect/releases) e execute. Nao precisa de Python.

**Codigo-fonte:**

```bash
git clone https://github.com/DevGreick/ThreatDeflect.git
cd ThreatDeflect
uv sync
uv run threatdeflect --help
uv run threatdeflect-gui
```

Para instrucoes detalhadas de instalacao, configuracao de APIs e uso completo, consulte a **[Documentacao](https://devgreick.github.io/ThreatDeflect/)**.

---

## Licenca

GPLv3. Veja [LICENSE](./LICENSE).

<div align="center">
<a href="https://buymeacoffee.com/devgreick" target="_blank">
<img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" width="200">
</a>
</div>
