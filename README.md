
<div align="center">
  <h1 align="center">🔐 ThreatDeflect</h1>
  <img src="https://github.com/DevGreick/ThreatSpy/blob/main/spy2-1.png" alt="Logo do ThreatDeflect" width="150"/>
</div>

<div align="center">
<strong>Plataforma integrada de Análise de Ameaças, Análise de Código e Threat Intelligence com IA Local.</strong>
<br>
Automatiza a análise de IOCs, varredura de repositórios e geração de relatórios com IA local para priorização de riscos.
</div>

<br>

<div align="center">
⭐ Dê uma estrela se o projeto te ajudou! | <a href="https://github.com/DevGreick/ThreatDeflect/releases"><strong>Baixar a Última Versão »</strong></a>
</div>



## 📑 Sumário
- [✨ Novidades da Versão 2.0](#novidades)
- [🚀 Funcionalidades Principais](#features)
- [⚡ Instale em 30 segundos](#instalacao-rapida)
- [🛠️ Exemplos de Uso (CLI)](#uso)
- [⚙️ Configuração](#configuracao)
- [✅ Requisitos](#requisitos)
- [📦 Instalação pelo Código-Fonte](#instalacao-fonte)
- [⚖️ Aviso de Segurança e Privacidade](#aviso)
- [🛠️ Tecnologias](#tech)
- [🤝 Contribuição](#contribuicao)
- [☕ Apoie o Projeto](#apoie)
- [📜 Licença](#licenca)

<a id="novidades"></a>

## ✨ Novidades da Versão 2.0
A transição para ThreatDeflect traz melhorias massivas de arquitetura e novas capacidades de detecção:

### 🧠 Análise de Repositórios Aprimorada por IA:
- **Validação de Segredos**: Usa um modelo de IA local (Ollama) para analisar achados genéricos (ex: chaves de API) e reduzir drasticamente falsos positivos, distinguindo segredos reais de placeholders.
- **Priorização de Riscos**: Gera um Resumo Executivo para relatórios, utilizando a IA para triar todas as vulnerabilidades encontradas e destacar os 3 riscos mais críticos em linguagem de negócio.

### ⚡ Sistema de Cache Inteligente:
- Implementado um cache local em SQLite para a análise de repositórios. Arquivos inalterados não são reanalisados, resultando em uma performance significativamente mais rápida em varreduras subsequentes.

### 🕵️ Detecção Avançada de Ameaças:
- **IOCs Ocultos**: Extrai e decodifica ativamente strings em Base64 para encontrar URLs e indicadores de comprometimento ofuscados no código-fonte.
- **Detecção de Spoofing Visual**: Alerta sobre URLs que utilizam ataques de Punycode/Homograph e ofuscação com RTLO (Right-to-Left Override), técnicas comuns em phishing.

### 📦 Análise de Dependências:
- Integração com a API do OSV.dev para verificar vulnerabilidades conhecidas nos pacotes listados em package.json e requirements.txt.

### 📊 Relatórios Mais Completos:
- **Relatórios em PDF**: Além do Excel, agora gera relatórios técnicos em PDF, formatando a resposta da IA (incluindo tabelas em Markdown) em um documento profissional.
- **Planilhas Dedicadas**: O relatório Excel foi reestruturado com abas específicas para "Resumo Executivo", "Avisos de Segurança", "Achados", "Dependências" e "IOCs Extraídos".

### 🔧 Motor de Análise Configurável:
- Todas as regras de detecção de segredos, palavras-chave suspeitas, arquivos e diretórios a serem ignorados são definidas externamente no arquivo `rules.yaml`, permitindo fácil customização.

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

<a id="instalacao-rapida"></a>

## ⚡ Instale em 30 segundos
Baixe o executável para o seu sistema operacional na página de [Releases](https://github.com/DevGreick/ThreatDeflect/releases).

<a id="uso"></a>

## 🛠️ Exemplos de Uso (CLI)

### Analisar IOCs (IPs/URLs)
```bash
# Analisa múltiplos alvos e gera um relatório com resumo da IA
threatdeflect ioc 8.8.8.8 https://malware.com/payload.php --ai llama3

# Analisa alvos a partir de um arquivo de texto
threatdeflect ioc --file targets.txt -o report_iocs.xlsx
```

### Analisar Repositórios
```bash
# Analisa um repositório, salva o relatório e gera um resumo com a IA
threatdeflect repo https://github.com/some/repo --ai mistral
```

### Configurações
```bash
# Configurar a chave da API do VirusTotal
threatdeflect config set virustotal YOUR_KEY_HERE

# Configurar o endpoint do Ollama
threatdeflect config set-ollama http://localhost:11434/api/generate

# Alterar o idioma
threatdeflect config set-lang en_us

# Mostrar a configuração atual
threatdeflect config show
```

<a id="configuracao"></a>

## ⚙️ Configuração
As chaves de API e outras configurações podem ser gerenciadas via CLI (`threatdeflect config ...`) ou pela janela de "Configurações" na GUI.

**Arquivo de Configuração (`settings.ini`):**
- Linux: `~/.config/ThreatDeflect/settings.ini`
- Windows: `%APPDATA%\ThreatDeflect\settings.ini`

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
threatdeflect-gui

# Execute a versão CLI
threatdeflect --help
```

<a id="aviso"></a>

## ⚖️ Aviso de Segurança e Privacidade
- **Análise de IOCs**: Os IPs e URLs fornecidos são enviados para as APIs de terceiros configuradas.
- **Análise de Arquivos**: O ThreatDeflect não envia seus arquivos. Apenas o hash SHA256 é calculado localmente e enviado para as APIs.
- **Análise de Repositórios**: O conteúdo dos arquivos de repositórios públicos é baixado para análise local.
- **Uso Responsável**: Não submeta dados sensíveis ou internos. A responsabilidade pela segurança dos dados analisados é sua.

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
Pull requests são bem-vindos. Para grandes mudanças, por favor, abra uma issue primeiro para discutirmos o que você gostaria de mudar.

Ao submeter um Pull Request, você concorda que suas contribuições serão licenciadas sob a mesma licença GPLv3 do projeto, concedendo ao mantenedor o direito de usar, modificar e distribuir seu código como parte do ThreatDeflect.

<a id="licenca"></a>


<a id="apoie"></a>

## ☕ Apoie o Projeto

<div align="center">
<a href="https://buymeacoffee.com/devgreick" target="_blank">
<img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" width="200">
</a>
</div>

## 📜 Licença
Distribuído sob a licença GPLv3. Consulte o arquivo LICENSE para mais informações.
