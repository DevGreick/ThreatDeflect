# Referencia CLI

## Uso geral

```bash
threatdeflect [COMANDO] [OPCOES]
```

Para ver a ajuda de qualquer comando:

```bash
threatdeflect --help
threatdeflect ioc --help
threatdeflect config --help
```

### Idioma

O CLI suporta Portugues (BR) e Ingles (US). Para trocar:

```bash
threatdeflect config set-lang pt_br   # Portugues
threatdeflect config set-lang en_us   # Ingles
```

---

## `threatdeflect ioc`

Analise de IOCs (IPs, URLs, dominios).

```bash
threatdeflect ioc [ALVOS...] [OPCOES]
```

| Argumento / Opcao | Descricao |
|-------------------|-----------|
| `ALVOS` | Um ou mais IPs, URLs ou dominios separados por espaco |
| `--file`, `-f` | Caminho para arquivo com alvos (um por linha) |
| `--output`, `-o` | Caminho do relatorio de saida (padrao: `Analise_IOCs.xlsx`) |
| `--ai` | Modelo Ollama para gerar resumo (ex: `llama3`, `gpt-oss:20b`) |

### Exemplos

```bash
# Analise simples
threatdeflect ioc 8.8.8.8

# Multiplos alvos com resumo por IA
threatdeflect ioc 8.8.8.8 1.1.1.1 https://evil.com --ai gpt-oss:20b

# A partir de arquivo
threatdeflect ioc -f targets.txt -o relatorio.xlsx
```

---

## `threatdeflect file`

Analise de arquivos por hash SHA256. O hash e calculado localmente e consultado no VirusTotal e MalwareBazaar. **Nenhum arquivo e enviado.**

```bash
threatdeflect file ARQUIVO [ARQUIVO...] [OPCOES]
```

| Argumento / Opcao | Descricao |
|-------------------|-----------|
| `ARQUIVO` | Um ou mais caminhos de arquivos locais |
| `--output`, `-o` | Caminho do relatorio (padrao: `Analise_Arquivos.xlsx`) |
| `--ai` | Modelo Ollama para gerar resumo |

### Exemplos

```bash
threatdeflect file suspicious.exe
threatdeflect file malware.dll trojan.pdf --ai llama3 -o audit.xlsx
```

---

## `threatdeflect repo`

Analise de repositorios GitHub e GitLab. Detecta segredos expostos, dependencias vulneraveis, IOCs e padroes suspeitos via API, sem clonar.

```bash
threatdeflect repo URL [URL...] [OPCOES]
```

| Argumento / Opcao | Descricao |
|-------------------|-----------|
| `URL` | Uma ou mais URLs de repositorios GitHub ou GitLab |
| `--output`, `-o` | Caminho do relatorio (padrao: `Analise_Repositorios.xlsx`) |
| `--ai` | Modelo Ollama para gerar resumo |

### Exemplos

```bash
threatdeflect repo https://github.com/org/repo
threatdeflect repo https://github.com/org/repo1 https://gitlab.com/org/repo2 --ai mistral
```

---

## `threatdeflect config`

Gerenciamento de configuracoes.

| Subcomando | Descricao | Exemplo |
|------------|-----------|---------|
| `config set SERVICE KEY` | Define chave de API | `config set virustotal SUA_CHAVE` |
| `config set-ollama URL` | Define endpoint Ollama | `config set-ollama http://localhost:11434/api/generate` |
| `config set-log-path PATH` | Define caminho dos logs | `config set-log-path /var/log/td.log` |
| `config set-lang LANG` | Define idioma | `config set-lang en_us` |
| `config show` | Exibe todas as configuracoes | `config show` |

### Servicos disponiveis

`virustotal` . `abuseipdb` . `urlhaus` . `shodan` . `malwarebazaar` . `github` . `gitlab`

### Exemplo de configuracao inicial

```bash
threatdeflect config set virustotal SUA_CHAVE_VT
threatdeflect config set abuseipdb SUA_CHAVE_ABUSE
threatdeflect config set github SEU_TOKEN_GH
threatdeflect config set-lang pt_br
threatdeflect config show
```

!!! info "Seguranca"
    As chaves sao armazenadas no keyring do sistema operacional, nao em arquivos de texto.

---

## Exemplos por plataforma

=== "Linux / macOS"

    ```bash
    threatdeflect ioc 8.8.8.8 --ai llama3
    threatdeflect file ~/Downloads/suspicious.bin
    threatdeflect repo https://github.com/org/repo -o audit.xlsx
    ```

=== "Windows (PowerShell)"

    ```powershell
    threatdeflect ioc 8.8.8.8 --ai gpt-oss:20b
    threatdeflect file C:\Users\User\Downloads\suspicious.exe
    threatdeflect repo https://github.com/org/repo -o C:\Users\User\Desktop\report.xlsx
    ```
