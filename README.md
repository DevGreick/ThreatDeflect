<div align="center">
  <h1 align="center">🔎 ThreatSpy</h1>
  <img src="https://raw.githubusercontent.com/DevGreick/ThreatSpy/master/spy2-1.png" alt="Logo do ThreatSpy" width="150"/>
</div>

<div align="center">
<strong>Uma ferramenta de análise de ameaças que automatiza a consulta de IOCs e repositórios em múltiplas fontes, gera relatórios e cria resumos com IA local.</strong>
</div>

<br>

<div align="center">
⭐ Dê uma estrela se o projeto te ajudou! | <a href="https://github.com/DevGreick/ThreatSpy/releases"><strong>Baixar a Última Versão »</strong></a>
</div>

<br>

<div align="center">
<!-- Badges -->
<a href="https://www.python.org/downloads/release/python-380/"><img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python Version"></a>
<a href="https://github.com/DevGreick/ThreatSpy/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
<img src="https://img.shields.io/badge/status-active-success.svg" alt="Project Status">
<a href="https://doc.qt.io/qtforpython/"><img src="https://img.shields.io/badge/GUI-PySide6-purple.svg" alt="GUI Framework"></a>
<a href="#contribuicao"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg" alt="Contributions"></a>
</div>

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/DevGreick/ThreatSpy/master/ThreatsSy.png" alt="Screenshot da interface do ThreatSpy" width="700"/>
</div>

---

<a id="sumario"></a>

## 📑 Sumário

- [⚡ Comece a Usar em 30 Segundos](#start)
- [🛠️ Como Usar (Exemplos Práticos)](#uso)
- [✨ Funcionalidades Principais](#features)
- [✅ Requisitos](#requisitos)
- [📦 Instalação pelo Código-Fonte](#instalacao)
- [⚙️ Configuração Essencial](#configuracao-essencial)
- [⚖️ Use com responsabilidade](#responsavel)
- [⚠️ Aviso de Segurança e Privacidade](#aviso)
- [🛠️ Tecnologias Utilizadas](#tech)
- [🤝 Contribuição](#contribuicao)
- [☕ Apoie o Projeto](#apoie)
- [📜 Licença](#licenca)

---

<a id="start"></a>

## ⚡ Comece a Usar em 30 Segundos

Quer usar IA local? Instale e rode o Ollama (veja [Requisitos](#requisitos)).

Baixe a versão do seu sistema em [Releases](https://github.com/DevGreick/ThreatSpy/releases).

Abra o ThreatSpy e adicione a chave do VirusTotal.

### Windows
- Acesse [Releases](https://github.com/DevGreick/ThreatSpy/releases).
- Baixe `ThreatSpyWindows.zip`.  
- Descompacte e execute `ThreatSpy.exe`.  

### macOS
- Acesse [Releases](https://github.com/DevGreick/ThreatSpy/releases).
- Baixe `ThreatSpy.app.zip`.  
- Descompacte e abra `ThreatSpy.app`.  
- Se houver aviso de segurança, clique com o botão direito em **Abrir** e confirme.  

### Linux
- Acesse [Releases](https://github.com/DevGreick/ThreatSpy/releases).
- Baixe `ThreatSpyLinux.zip`.  
- Descompacte e torne executável:  
```bash
chmod +x ThreatSpy
```
- Execute:  
```bash
./ThreatSpy
```

> **Keyring no Linux:**
> 
> Se o seu sistema operacional não tiver o Keyring, o programa não vai funcionar. Então, instale conforme sua distribuição:
>  
> **Debian / Ubuntu:**  
> ```bash
> sudo apt update && sudo apt install gnome-keyring
> ```
>  
> **Fedora / CentOS:**  
> ```bash
> sudo dnf install gnome-keyring
> ```
>  
> **Arch Linux e derivados (como Manjaro):**  
> ```bash
> sudo pacman -S gnome-keyring libsecret
> ```

---

<a id="uso"></a>

## 🛠️ Como Usar (Exemplos Práticos)

**Exemplo 1: Analisando IOCs**

Abra **Análise de IOCs** e cole indicadores (um por linha), ou clique em **Importar Alvos de Arquivo** para enviar IPs/domínios em lote:

```
185.172.128.150
https://some-random-domain.net/path
8.8.8.8
```

Clique em **Analisar Alvos**. O app consulta APIs em paralelo e gera um Excel com os resultados.

---

**Exemplo 2: Analisando um repositório suspeito**

Abra **Análise de Repositórios** e cole repositórios (um por linha), ou clique em **Importar Alvos de Arquivo** para enviar repositórios em lote (*não recomendado sem token de API; para volumes corporativos, pode ser necessário GitHub Enterprise*).  

```
https://github.com/DevGreick/threatspy-test-env
```

Clique em **Analisar Repositórios**. A ferramenta detecta segredos e IOCs, gerando um relatório sem precisar clonar o repositório inteiro.

---

**Exemplo 3: Analisando Arquivos Locais**

- Na aba **Análise de IOCs**, clique em **Verificar Reputação de Arquivos**.  
- Selecione um ou mais arquivos (PDFs, executáveis, etc.).  
- O ThreatSpy **não envia seus arquivos**: ele calcula o hash SHA256 localmente e consulta no VirusTotal e no MalwareBazaar.  

---


<a id="features"></a>

## ✨ Funcionalidades Principais

- **Análise de IOCs (IPs e URLs):** reputação em fontes como VirusTotal, AbuseIPDB, URLHaus e Shodan.  
- **Análise de Repositórios (GitHub/GitLab):** busca por segredos expostos, links suspeitos e comandos perigosos.  
- **Análise de Arquivos:** verificação de reputação por hash SHA256.  
- **GUI Moderna:** interface em PySide6 com tema escuro.  
- **Relatórios Detalhados:** exportação para Excel e PDF.  
- **IA Local (Ollama):** resumos automáticos com total privacidade.  
- **Gestão Segura de Chaves:** usa keyring e cofres nativos do sistema.  

---

<a id="requisitos"></a>

## ✅ Requisitos

- **Executável:** não precisa de Python.  
- **Código-fonte:** Python 3.8+ e Git.  
- **Chave do VirusTotal:** obrigatória para análises de IPs, URLs e arquivos.  

**Para usar a IA local (opcional):**  
Ollama instalado e em execução.  

Windows: <https://ollama.com>  

macOS:
```bash
brew install --cask ollama
```

Linux:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Teste rápido:**
```bash
ollama --version
ollama pull llama3
```

Sem Ollama, os botões de resumo por IA ficam indisponíveis. As demais funções seguem ativas.

---

<a id="instalacao"></a>

## 📦 Instalação pelo Código-Fonte

```bash
# 1. Clone o repositório
git clone https://github.com/DevGreick/ThreatSpy.git
cd ThreatSpy

# 2. Crie e ative o ambiente virtual
python -m venv venv
# No Windows: venv\Scripts\activate
# No macOS/Linux: source venv/bin/activate

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Execute a aplicação
python main_gui.py
```

---

<a id="configuracao-essencial"></a>

## ⚙️ Configuração Essencial

| Serviço       | Necessidade | O que habilita? |
|---------------|-------------|-----------------|
| VirusTotal    | Obrigatória | Reputação de IPs, URLs e arquivos |
| GitHub/GitLab | Recomendada | Análise de repositórios com mais limites da API |
| AbuseIPDB     | Opcional    | Score de abuso de IPs |
| Shodan        | Opcional    | Portas e serviços para IPs |
| URLHaus       | Opcional    | Maiores limites de consulta |
| MalwareBazaar | Opcional    | Maiores limites de consulta |
| Ollama (IA)   | Opcional    | Resumos automáticos locais |

As chaves são salvas de forma segura com **keyring** no cofre do seu sistema operacional.  
Para um guia detalhado sobre como obter e configurar cada chave, consulte o nosso [Guia de Configuração de APIs ](./config.md).

---

<a id="responsavel"></a>

## ⚖️ Use com responsabilidade

- Ferramenta para fins educacionais e de análise de segurança.
- Respeite os Termos de Serviço das APIs utilizadas.  
- Não analise dados ou sistemas de terceiros sem autorização explícita.  

---

<a id="aviso"></a>

## ⚠️ Aviso de Segurança e Privacidade

Esta ferramenta interage com serviços externos para análise. Isso significa:

- Indicadores fornecidos (IPs, URLs, hashes) são enviados para APIs como VirusTotal, AbuseIPDB, Shodan e URLHaus.  
- Se você analisar dados internos (como repositórios privados), eles podem ser expostos a essas APIs.  
- Funções de IA usam o Ollama local por padrão (`http://localhost:11434`). Caso configure um endpoint remoto, os dados sairão da sua máquina.  

Use por sua conta e risco. O desenvolvedor não se responsabiliza por vazamentos causados pelo uso indevido.  

---

<a id="tech"></a>

## 🛠️ Tecnologias Utilizadas

| Tecnologia | Propósito |
|------------|-----------|
| Python     | Linguagem principal |
| PySide6    | Interface gráfica |
| Ollama     | IA local |
| Requests   | Comunicação com APIs |
| Keyring    | Cofre de credenciais |
| XlsxWriter / ReportLab | Relatórios Excel e PDF |
| PyInstaller| Executáveis multiplataforma |

---

<a id="contribuicao"></a>

## 🤝 Contribuição

1. Faça um fork.  
2. Crie a branch `feature/nova-feature`.  
3. Commit: `git commit -m "Adiciona nova feature"`.  
4. Push: `git push origin feature/nova-feature`.  
5. Abra um Pull Request.  

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

Distribuído sob a licença MIT. Veja o arquivo [LICENSE](https://github.com/DevGreick/ThreatSpy/blob/master/LICENSE) para mais informações.
