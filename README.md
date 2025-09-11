<div align="center">
  <h1 align="center">🔐 ThreatDeflect</h1>
  <img src="https://github.com/DevGreick/ThreatDeflect/blob/main/spy2-1.png" alt="Logo do ThreatDeflect" width="150"/>
</div>

<div align="center">
<strong>Ferramenta integrada de Análise de Ameaças, Análise de Código e Threat Intelligence com IA Local.</strong>
<br><br>
⭐ Dê uma estrela se o projeto te ajudou! | <a href="https://github.com/DevGreick/ThreatDeflect/releases"><strong>Baixar a Última Versão »</strong></a>
</div>

<br>

<div align="center">
<!-- Badges -->
<a href="https://www.python.org/downloads/release/python-380/"><img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python Version"></a>
<a href="https://github.com/DevGreick/ThreatDeflect/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?logo=gnu" alt="License"></a>
<img src="https://img.shields.io/badge/status-active-success.svg" alt="Project Status">
<a href="https://doc.qt.io/qtforpython/"><img src="https://img.shields.io/badge/GUI-PySide6-purple.svg" alt="GUI Framework"></a>
<a href="#contribuicao"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg" alt="Contributions"></a>
</div>

<br>
<div align="center">
<img src="https://github.com/DevGreick/ThreatDeflect/blob/main/Abertura.png" alt="Screenshot da interface do ThreatDeflect" width="700"/>
</div>

---

<a id="sumario"></a>

## 📑 Sumário

- [⚡ Instale em 30 segundos](#instalacao-rapida)
- [🛠️ Como Usar (GUI)](#uso2)
- [🛠️ Como Usar (CLI)](#uso)
- [🚀 Funcionalidades Principais](#features)
- [⚙️ Configuração](#configuracao)
- [✅ Requisitos](#requisitos)
- [📦 Instalação pelo Código-Fonte](#instalacao-fonte)
- [🎛️ Calibrando a Precisão da Análise](#calibragem)
- [⚖️ Aviso de Segurança e Privacidade](#aviso)
- [🛠️ Tecnologias](#tech)
- [🤝 Contribuição](#contribuicao)
- [☕ Apoie o Projeto](#apoie)
- [📜 Licença](#licenca)

<a id="instalacao-rapida"></a>

## ⚡ Instale em 30 segundos
Baixe o executável para o seu sistema operacional na página de [Releases](https://github.com/DevGreick/ThreatDeflect/releases).

<a id="uso"></a>

<a id="uso2"></a>

## 🛠️ Como Usar (GUI)

**Exemplo 1: Analisando IOCs**

Abra **Análise de IOCs** e cole indicadores (um por linha), ou clique em **Importar Alvos de Arquivo** para enviar IPs/domínios em lote:

```
185.172.128.150
https://some-random-domain.net/path
8.8.8.8
```
Clique em **Analisar Alvos**. O app consulta APIs em paralelo e gera um Excel com os resultados.

<img src="https://raw.githubusercontent.com/DevGreick/ThreatSpy/master/ioc.gif" alt="Demonstração da Análise de IOCs no ThreatSpy" width="800">

---

**Exemplo 2: Analisando um repositório suspeito**

Abra **Análise de Repositórios** e cole repositórios (um por linha), ou clique em **Importar Alvos de Arquivo** para enviar repositórios em lote (*não recomendado sem token de API; para volumes corporativos, pode ser necessário GitHub Enterprise*).  

```
https://github.com/DevGreick/threatspy-test-env
```
Clique em **Analisar Repositórios**. A ferramenta detecta segredos e IOCs, gerando um relatório sem precisar clonar o repositório inteiro.

<img src="https://raw.githubusercontent.com/DevGreick/ThreatSpy/master/rep.gif" alt="Demonstração da Análise de Repositorio no ThreatSpy" width="800">

---

**Exemplo 3: Analisando Arquivos Locais**

- Na aba **Análise de IOCs**, clique em **Verificar Reputação de Arquivos**.  
- Selecione um ou mais arquivos (PDFs, executáveis, etc.).  
- O ThreatSpy **não envia seus arquivos**: ele calcula o hash SHA256 localmente e consulta no VirusTotal e no MalwareBazaar.  

---

## 🛠️ Como Usar  (CLI)

### Windows (PowerShell ou CMD)
```powershell
# Ver ajuda geral
threatdeflect --help

# Analisa múltiplos alvos e gera relatório com resumo por IA
threatdeflect ioc 8.8.8.8 https://malware.com/payload.php --ai llama3

# Analisa alvos de um arquivo e salva em Excel
threatdeflect ioc --file C:\Users\SeuUsuario\Desktop\targets.txt -o C:\Users\SeuUsuario\Desktop\report_iocs.xlsx
```

---

### macOS (Terminal)
```bash
# Ver ajuda
threatdeflect --help

# Analisa múltiplos alvos
threatdeflect ioc 8.8.8.8 https://malware.com/payload.php --ai llama3

# Analisa via arquivo e exporta
threatdeflect ioc --file ~/targets.txt -o ~/report_iocs.xlsx
```

---

### Linux (Terminal)

Após descompactar o release, torne o binário executável com:
```bash
chmod +x ThreatDeflect
```

```bash
# Ver ajuda
./ThreatDeflect --help

# Analisa múltiplos alvos com resumo por IA local
./ThreatDeflect ioc 8.8.8.8 https://malware.com/payload.php --ai llama3

# Analisa via arquivo e salva Excel
./ThreatDeflect ioc --file ~/targets.txt -o ~/report_iocs.xlsx
```

<a id="features"></a>

## 🚀 Funcionalidades Principais
**Três Módulos de Análise:**
- **Análise de IOCs**: Consulta massiva de IPs e URLs contra VirusTotal, AbuseIPDB, Shodan e URLHaus.
- **Análise de Repositórios**: Varredura de repositórios GitHub e GitLab em busca de segredos, vulnerabilidades, dependências maliciosas e IOCs.
- **Análise de Arquivos**: Consulta a reputação de arquivos locais (via hash SHA256) no VirusTotal e MalwareBazaar.

**Interface Dupla:**
- **GUI Completa**: Interface gráfica construída com PySide6, intuitiva e com todas as funcionalidades.
- **CLI Robusta**: Linha de comando moderna com Typer e Rich para automação e uso em scripts.

**Integração com IA Local (Ollama):**
- Geração de dossiês completos e resumos executivos sem enviar dados para APIs de nuvem.

**Sistema de Atualização Automática (GUI):**
- Notifica sobre novas versões disponíveis no GitHub e oferece um processo de atualização simplificado.

**Segurança:**
- Armazena chaves de API de forma segura usando o keyring do sistema operacional.
- Não envia o conteúdo de arquivos locais, apenas seus hashes.

**Modularidade:**
- Dois idiomas disponíveis: inglês e português, pra facilitar o uso em diferentes cenários.

<a id="configuracao"></a>

## ⚙️ Configuração
As chaves de API e outras configurações podem ser gerenciadas via CLI (`threatdeflect config ...`) ou pela janela de "Configurações" na GUI.

**Cache de Análise:**
- O cache do SQLite é armazenado no mesmo diretório, dentro da subpasta `.threatdeflect_cache`.

<a id="requisitos"></a>

## ✅ Requisitos
- Python 3.8+
- Ollama para as funcionalidades de IA local (opcional).
- Chaves de API para os serviços desejados (VirusTotal é altamente recomendado).
- Um backend de Keyring instalado no sistema (para Linux, ex: `keyrings.alt`).

<a id="instalacao-fonte"></a>

## 📦 Instalação pelo Código-Fonte
```bash
# Clone o repositório
git clone https://github.com/DevGreick/ThreatDeflect.git
cd ThreatDeflect

# Crie e ative um ambiente virtual (recomendado)
python3 -m venv .venv
source .venv/bin/activate  # No Windows: .venv\Scripts\activate

# Instale as dependências
pip install -r requirements.txt

# Instale o pacote em modo editável para registrar os comandos
pip install -e .

# Execute a versão GUI
threatdeflect-gui  # Ou acesse o arquivo main_gui.py na pasta \ThreatDeflect\threatdeflect\ui

# Execute a versão CLI
threatdeflect --help
```

<a id="calibragem"></a>

## 🎛️ Calibrando a Precisão da Análise

- Como toda ferramenta de Análise Estática de Segurança, o **ThreatDeflect** trabalha encontrando padrões que podem representar riscos, isso significa que ela pode gerar falsos positivos.  
- A precisão do ThreatDeflect é diretamente controlada pelo arquivo **rules.yaml**, se você é um desenvolvedor ou analista de segurança, é fortemente encorajado a calibrar este arquivo para reduzir o ruído e focar em riscos reais, ajustando as regras de detecção (`rules`) e principalmente a lista de exclusão (`ignore_patterns`) para remover pastas de teste, documentação ou outros diretórios que não são relevantes.  


<a id="aviso"></a>

## ⚖️ Aviso de Segurança e Privacidade
- Os IPs e URLs fornecidos são enviados para as APIs de terceiros configuradas.
- O ThreatDeflect não envia seus arquivos, apenas o **hash SHA256** é calculado localmente e enviado para as APIs.
- Não submeta dados sensíveis ou internos. A responsabilidade pela segurança dos dados analisados é **sua**.

<a id="tech"></a>

## 🛠️ Tecnologias
- **Core**: Python
- **GUI**: PySide6
- **CLI**: Typer, Rich
- **APIs**: Requests
- **Cache**: SQLite
- **Relatórios**: XlsxWriter, ReportLab
- **IA Local**: Integração com Ollama
- **Testes**: Pytest
- **Empacotamento**: PyInstaller

<a id="contribuicao"></a>

## 🤝 Contribuição

1. Faça um fork.  
2. Crie a branch `feature/nova-feature`.  
3. Commit: `git commit -m "Adiciona nova feature"`.  
4. Push: `git push origin feature/nova-feature`.  
5. Abra um Pull Request.  

---

> *Ao submeter um Pull Request, você concorda que suas contribuições serão licenciadas sob a mesma licença GPLv3 do projeto, concedendo ao mantenedor o direito de usar, modificar e distribuir seu código como parte do ThreatDeflect.*

<a id="apoie"></a>

## ☕ Apoie o Projeto

<div align="center">
<a href="https://buymeacoffee.com/devgreick" target="_blank">
<img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" width="200">
</a>
</div>

<a id="licenca"></a>

## 📜 Licença
Distribuído sob a licença GPLv3. Consulte o arquivo LICENSE para mais informações.
