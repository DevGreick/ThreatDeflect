<div align="center">
  <h1>🛡️ ThreatDeflect</h1>
  <img src="https://github.com/DevGreick/ThreatDeflect/blob/main/spy2-1.png" alt="Logo do ThreatDeflect" width="150"/>
</div>

<div align="center">
<strong>Ferramenta de análise de ameaças com motor híbrido Python + Rust que automatiza a consulta de IOCs, repositórios e arquivos em múltiplas fontes, gera relatórios e cria resumos com IA local.</strong>
<br><br>
⭐ Dê uma estrela se o projeto te ajudou! | <a href="https://github.com/DevGreick/ThreatDeflect/releases"><strong>Baixar a Última Versão »</strong></a>
</div>

<br>

<div align="center">
<a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python Version"></a>
<a href="https://github.com/DevGreick/ThreatDeflect/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?logo=gnu" alt="License"></a>
<img src="https://img.shields.io/badge/status-active-success.svg" alt="Project Status">
<a href="https://doc.qt.io/qtforpython/"><img src="https://img.shields.io/badge/GUI-PySide6-purple.svg" alt="GUI Framework"></a>
<img src="https://img.shields.io/badge/engine-Rust+Python-orange.svg?logo=rust" alt="Rust Engine">
<a href="#contribuicao"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg" alt="Contributions"></a>
</div>

<br>
<div align="center">
<img src="https://github.com/DevGreick/ThreatDeflect/blob/main/Abertura.png" alt="Screenshot da interface do ThreatDeflect" width="700"/>
</div>

---

<a id="sumario"></a>

## 📑 Sumário

- [⚡ Instale em 30 Segundos](#instalacao-rapida)
- [🖥️ Como Usar — GUI](#uso-gui)
- [💻 Como Usar — CLI](#uso-cli)
- [📖 Referência Completa do CLI](#referencia-cli)
- [🚀 Funcionalidades Principais](#features)
- [⚙️ Configuração de APIs](#configuracao)
- [✅ Requisitos](#requisitos)
- [📦 Instalação pelo Código-Fonte](#instalacao-fonte)
- [🦀 Motor Rust (Opcional)](#motor-rust)
- [🎛️ Calibrando a Precisão da Análise](#calibragem)
- [⚖️ Aviso de Segurança e Privacidade](#aviso)
- [🛠️ Tecnologias](#tech)
- [🤝 Contribuição](#contribuicao)
- [☕ Apoie o Projeto](#apoie)
- [📜 Licença](#licenca)

---

<a id="instalacao-rapida"></a>

## ⚡ Instale em 30 Segundos

Baixe o executável para o seu sistema operacional na página de [Releases](https://github.com/DevGreick/ThreatDeflect/releases). Não precisa de Python instalado.

| Sistema | Arquivo | Execução |
|---------|---------|----------|
| Windows | `ThreatDeflect-GUI-Windows.exe` | Duplo clique |
| Linux   | `ThreatDeflect-CLI-Linux` | `chmod +x` e execute |
| macOS   | `ThreatDeflect-CLI-macOS` | `chmod +x` e execute |

> Após abrir, vá em **Configurações** e insira pelo menos a chave do **VirusTotal** para começar a analisar.

---

<a id="uso-gui"></a>

## 🖥️ Como Usar — GUI

```bash
threatdeflect-gui
```

### Exemplo 1: Analisando IOCs

Abra **Análise de IOCs** e cole indicadores (um por linha), ou clique em **Importar Alvos de Arquivo** para enviar IPs/domínios em lote:

```
185.172.128.150
https://some-random-domain.net/path
8.8.8.8
```

Clique em **Analisar Alvos**. O app consulta APIs em paralelo e gera um Excel com os resultados.

---

### Exemplo 2: Analisando um Repositório Suspeito

Abra **Análise de Repositórios** e cole repositórios (um por linha), ou clique em **Importar Alvos de Arquivo** para enviar repositórios em lote (*não recomendado sem token de API; para volumes corporativos, pode ser necessário GitHub Enterprise*).

```
https://github.com/DevGreick/threatspy-test-env
```

Clique em **Analisar Repositórios**. A ferramenta detecta segredos e IOCs, gerando um relatório sem precisar clonar o repositório inteiro.

---

### Exemplo 3: Analisando Arquivos Locais

1. Na aba **Análise de IOCs**, clique em **Verificar Reputação de Arquivos**.
2. Selecione um ou mais arquivos (PDFs, executáveis, etc.).
3. O ThreatDeflect **não envia seus arquivos**: ele calcula o hash SHA256 localmente e consulta no VirusTotal e no MalwareBazaar.

---

<a id="uso-cli"></a>

## 💻 Como Usar — CLI

### Windows (PowerShell ou CMD)
```powershell
# Ver ajuda geral
threatdeflect --help

# Analisa múltiplos alvos com resumo por IA
threatdeflect ioc 8.8.8.8 https://malware.com/payload.php --ai gpt-oss:20b

# Analisa alvos de um arquivo e salva em Excel
threatdeflect ioc --file C:\Users\SeuUsuario\Desktop\targets.txt -o C:\Users\SeuUsuario\Desktop\report.xlsx

# Verifica reputação de arquivos pelo hash
threatdeflect file C:\Users\SeuUsuario\Downloads\suspicious.exe

# Analisa repositórios
threatdeflect repo https://github.com/org/repo --ai llama3
```

<img src="https://github.com/DevGreick/ThreatDeflect/blob/main/CLI.png" alt="ThreatDeflect CLI" width="800">

---

### macOS / Linux (Terminal)
```bash
# Ver ajuda geral
threatdeflect --help

# Analisa múltiplos alvos
threatdeflect ioc 8.8.8.8 1.1.1.1 https://malware.com/payload.php --ai gpt-oss:20b

# Analisa via arquivo e exporta
threatdeflect ioc --file ~/targets.txt -o ~/report_iocs.xlsx

# Verifica reputação de arquivos
threatdeflect file ~/Downloads/suspicious.bin --ai llama3

# Analisa repositórios em lote
threatdeflect repo https://github.com/org/repo1 https://github.com/org/repo2 -o audit.xlsx
```

> **Linux (release):** Após descompactar, torne executável com `chmod +x ThreatDeflect-CLI-Linux` e use `./ThreatDeflect-CLI-Linux` no lugar de `threatdeflect`.

---

<a id="referencia-cli"></a>

## 📖 Referência Completa do CLI

### `threatdeflect ioc` — Análise de IOCs (IPs, URLs, domínios)

```
threatdeflect ioc [ALVOS...] [OPÇÕES]
```

| Argumento / Opção | Descrição |
|-------------------|-----------|
| `ALVOS` | Um ou mais IPs, URLs ou domínios separados por espaço |
| `--file`, `-f` | Caminho para arquivo com alvos (um por linha) |
| `--output`, `-o` | Caminho do relatório de saída (padrão: `Analise_IOCs.xlsx`) |
| `--ai` | Modelo Ollama para gerar resumo (ex: `llama3`, `gpt-oss:20b`, `mistral`) |

```bash
# Exemplos
threatdeflect ioc 8.8.8.8
threatdeflect ioc 8.8.8.8 1.1.1.1 https://evil.com --ai gpt-oss:20b
threatdeflect ioc -f targets.txt -o relatorio.xlsx
```

---

### `threatdeflect file` — Análise de Arquivos (hash SHA256)

```
threatdeflect file ARQUIVO [ARQUIVO...] [OPÇÕES]
```

| Argumento / Opção | Descrição |
|-------------------|-----------|
| `ARQUIVO` | Um ou mais caminhos de arquivos locais |
| `--output`, `-o` | Caminho do relatório de saída (padrão: `Analise_Arquivos.xlsx`) |
| `--ai` | Modelo Ollama para gerar resumo |

```bash
# Exemplos
threatdeflect file suspicious.exe
threatdeflect file malware.dll trojan.pdf --ai llama3 -o audit_files.xlsx
```

> O ThreatDeflect calcula o hash SHA256 localmente e consulta no VirusTotal e MalwareBazaar. **Nenhum arquivo é enviado.**

---

### `threatdeflect repo` — Análise de Repositórios

```
threatdeflect repo URL [URL...] [OPÇÕES]
```

| Argumento / Opção | Descrição |
|-------------------|-----------|
| `URL` | Uma ou mais URLs de repositórios GitHub ou GitLab |
| `--output`, `-o` | Caminho do relatório de saída (padrão: `Analise_Repositorios.xlsx`) |
| `--ai` | Modelo Ollama para gerar resumo |

```bash
# Exemplos
threatdeflect repo https://github.com/org/repo
threatdeflect repo https://github.com/org/repo1 https://gitlab.com/org/repo2 --ai mistral
```

> A análise detecta segredos expostos, dependências vulneráveis, IOCs e padrões suspeitos sem clonar o repositório.

---

### `threatdeflect config` — Configuração

| Subcomando | Descrição | Exemplo |
|------------|-----------|---------|
| `config set SERVICE KEY` | Define chave de API | `config set virustotal SUA_CHAVE` |
| `config set-ollama URL` | Define endpoint do Ollama | `config set-ollama http://localhost:11434/api/generate` |
| `config set-log-path PATH` | Define caminho dos logs | `config set-log-path /var/log/td.log` |
| `config set-lang LANG` | Define idioma (`pt_br` ou `en_us`) | `config set-lang en_us` |
| `config show` | Exibe todas as configurações | `config show` |

**Serviços disponíveis para `config set`:**

`virustotal` · `abuseipdb` · `urlhaus` · `shodan` · `malwarebazaar` · `github` · `gitlab`

```bash
# Configuração inicial rápida
threatdeflect config set virustotal SUA_CHAVE_VT
threatdeflect config set abuseipdb SUA_CHAVE_ABUSE
threatdeflect config set-lang pt_br
threatdeflect config show
```

> As chaves são armazenadas de forma segura no **keyring** do sistema operacional (Windows Credential Locker, macOS Keychain, Linux Secret Service).

---

<a id="features"></a>

## 🚀 Funcionalidades Principais

### Três Módulos de Análise
| Módulo | O que faz | Fontes consultadas |
|--------|-----------|--------------------|
| **IOCs** | Consulta massiva de IPs e URLs | VirusTotal, AbuseIPDB, Shodan, URLHaus |
| **Repositórios** | Varredura de repos GitHub/GitLab | Segredos, dependências, IOCs, padrões suspeitos |
| **Arquivos** | Reputação por hash SHA256 | VirusTotal, MalwareBazaar |

### Interface Dupla
- **GUI Completa** — Interface gráfica PySide6, com abas, progresso em tempo real e geração de relatórios Excel/PDF.
- **CLI Robusta** — Linha de comando com Typer e Rich, ideal para automação, scripts e pipelines.

### Integração com IA Local (Ollama)
- Gera dossiês completos e resumos executivos usando modelos locais (llama3, mistral, gpt-oss:20b, etc.).
- **Nenhum dado é enviado para APIs de nuvem** — tudo roda na sua máquina.

### Motor Híbrido Rust + Python
- Detecção de segredos, cálculo de entropia e análise de padrões com performance nativa via PyO3/Maturin.

### Segurança
- Chaves de API armazenadas no keyring do sistema operacional.
- Arquivos locais **nunca são enviados** — apenas hashes SHA256.
- Sanitização de dados contra prompt injection nas consultas de IA.
- Guardrails de alucinação para validar resumos gerados por IA.

### Outros
- Bilíngue: Português (BR) e Inglês, configurável via CLI ou GUI.
- Sistema de atualização automática (GUI).
- Cache SQLite para evitar consultas repetidas.
- Relatórios em Excel (.xlsx) e PDF.

---

<a id="configuracao"></a>

## ⚙️ Configuração de APIs

| Serviço | Necessidade | O que habilita |
|---------|-------------|----------------|
| **VirusTotal** | Obrigatória | Reputação de IPs, URLs e arquivos |
| **GitHub / GitLab** | Recomendada | Análise de repositórios (evita rate limit) |
| **AbuseIPDB** | Opcional | Score de abuso de IPs |
| **Shodan** | Opcional | Portas abertas e serviços |
| **URLHaus** | Opcional | URLs usadas para distribuir malware |
| **MalwareBazaar** | Opcional | Identificação de ameaças conhecidas |
| **Ollama** | Opcional | Resumos automáticos com IA local |

As chaves são salvas de forma segura com **keyring** no cofre do seu sistema operacional.
Para um guia detalhado sobre como obter e configurar cada chave, consulte o [Guia de Configuração de APIs](./config.md).

**Configuração via CLI:**
```bash
threatdeflect config set virustotal SUA_CHAVE
threatdeflect config set abuseipdb SUA_CHAVE
threatdeflect config show
```

**Configuração via GUI:**
Abra a aba **Configurações** e cole suas chaves nos campos correspondentes.

**Cache de Análise:**
O cache SQLite é armazenado na subpasta `.threatdeflect_cache` no diretório do executável.

---

<a id="requisitos"></a>

## ✅ Requisitos

| Modo | Requisitos |
|------|-----------|
| **Executável (Release)** | Nenhum — basta baixar e executar |
| **Código-fonte** | Python 3.11+, Git |
| **IA local (opcional)** | Ollama instalado e em execução |

### Instalando o Ollama (opcional)

**Windows:** Baixe em <https://ollama.com>

**macOS:**
```bash
brew install --cask ollama
```

**Linux:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Teste rápido:**
```bash
ollama --version
ollama pull llama3
```

> Para melhores resultados, use `gpt-oss:20b`. Sem Ollama, as funcionalidades de IA ficam indisponíveis, mas todas as demais funções seguem ativas.

---

<a id="instalacao-fonte"></a>

## 📦 Instalação pelo Código-Fonte

### Com `uv` (recomendado)
```bash
git clone https://github.com/DevGreick/ThreatDeflect.git
cd ThreatDeflect

# Instala dependências e executa
uv sync
uv run threatdeflect --help       # CLI
uv run threatdeflect-gui          # GUI
```

### Com `pip`
```bash
git clone https://github.com/DevGreick/ThreatDeflect.git
cd ThreatDeflect

# Crie e ative um ambiente virtual
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Instale as dependências
pip install -r requirements.txt

# Instale o pacote em modo editável
pip install -e .

# Execute
threatdeflect --help               # CLI
threatdeflect-gui                  # GUI
```

---

<a id="motor-rust"></a>

## 🦀 Motor Rust (Opcional)

O ThreatDeflect possui um motor híbrido em Rust (`threatdeflect_rs`) compilado via **Maturin/PyO3** que acelera:

- Detecção de segredos e padrões suspeitos
- Cálculo de entropia de strings
- Análise de contexto seguro para comandos
- Detecção de Base64 e URLs em código-fonte

**Para compilar o módulo Rust:**
```bash
pip install maturin
cd rust_core
maturin develop --release
```

> O módulo Rust é opcional. Se não estiver compilado, o ThreatDeflect usa automaticamente a implementação em Python puro.

---

<a id="calibragem"></a>

## 🎛️ Calibrando a Precisão da Análise

Como toda ferramenta de Análise Estática de Segurança, o ThreatDeflect trabalha com detecção de padrões e pode gerar **falsos positivos**.

A precisão é controlada pelo arquivo **`rules.yaml`**. Se você é um analista de segurança, é fortemente encorajado a calibrar:

- **`rules`** — Regras de detecção (regex, severidade, categorias)
- **`ignore_patterns`** — Lista de exclusão para pastas de teste, documentação e outros diretórios irrelevantes

---

<a id="aviso"></a>

## ⚖️ Aviso de Segurança e Privacidade

- Os IPs e URLs fornecidos são enviados para as APIs de terceiros configuradas.
- O ThreatDeflect **não envia seus arquivos**, apenas o hash SHA256 é calculado localmente e enviado para as APIs.
- Resumos de IA são gerados **localmente** via Ollama — nenhum dado sai da sua máquina.
- Não submeta dados sensíveis ou internos. A responsabilidade pela segurança dos dados analisados é **sua**.

---

<a id="tech"></a>

## 🛠️ Tecnologias

| Tecnologia | Propósito |
|------------|-----------|
| Python 3.11+ | Linguagem principal |
| Rust / PyO3 | Motor de análise de alta performance |
| PySide6 (Qt) | Interface gráfica |
| Typer / Rich | CLI moderna |
| SQLite | Cache de análises |
| Requests | Comunicação com APIs |
| Keyring | Armazenamento seguro de credenciais |
| XlsxWriter | Relatórios Excel |
| ReportLab | Relatórios PDF |
| Ollama | IA local para resumos |
| Maturin | Build system para extensões Rust |
| PyInstaller | Executáveis multiplataforma |

---

<a id="contribuicao"></a>

## 🤝 Contribuição

1. Faça um fork.
2. Crie a branch: `git checkout -b feature/nova-feature`.
3. Commit: `git commit -m "Adiciona nova feature"`.
4. Push: `git push origin feature/nova-feature`.
5. Abra um Pull Request.

> Ao submeter um Pull Request, você concorda que suas contribuições serão licenciadas sob a mesma licença GPLv3 do projeto, concedendo ao mantenedor o direito de usar, modificar e distribuir seu código como parte do ThreatDeflect.

---

<a id="apoie"></a>

## ☕ Apoie o Projeto

<div align="center">
<a href="https://buymeacoffee.com/devgreick" target="_blank">
<img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" width="200">
</a>
</div>

---

<a id="licenca"></a>

## 📜 Licença

Distribuído sob a licença GPLv3. Consulte o arquivo [LICENSE](./LICENSE) para mais informações.
