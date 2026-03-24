# Guia da GUI

## Iniciando

```bash
threatdeflect-gui
# ou com uv:
uv run threatdeflect-gui
```

A interface possui abas para cada tipo de analise e uma area de configuracoes.

---

## Analise de IOCs

Permite consultar IPs, URLs e dominios em multiplas fontes de inteligencia.

1. Abra a aba **Analise de IOCs**
2. Cole os indicadores (um por linha) ou clique em **Importar de Arquivo**
3. Clique em **Analisar Alvos**

```
185.172.128.150
https://some-random-domain.net/path
8.8.8.8
```

O app consulta as APIs em paralelo e gera um relatorio Excel com os resultados.

### Verificacao de Arquivos

Na mesma aba, clique em **Verificar Reputacao de Arquivo** para verificar arquivos locais. O ThreatDeflect calcula o hash SHA256 localmente e consulta no VirusTotal e MalwareBazaar. **Nenhum arquivo e enviado.**

---

## Analise de Repositorios

Permite escanear repositorios GitHub e GitLab em busca de segredos, dependencias vulneraveis, IOCs e padroes suspeitos.

1. Abra a aba **Analise de Repositorio**
2. Cole as URLs dos repositorios (uma por linha)
3. Clique em **Analisar Repositorios**

```
https://github.com/org/repo
```

!!! info "Sem clone"
    A analise e feita via API, sem precisar clonar o repositorio inteiro.

---

## Console de Atividade

Mostra os logs em tempo real durante a analise. Util para acompanhar o progresso e identificar erros.

---

## Resumo por IA

Na aba **Resumo Gerado por IA**, voce pode gerar resumos executivos usando modelos locais do Ollama.

1. Selecione o modelo na lista (ex: `llama3:8b`, `gpt-oss:20b`, `mistral`)
2. Clique em **Gerar Resumo em Texto** ou **Gerar Resumo em PDF**

!!! tip "Privacidade"
    Todos os resumos sao gerados localmente. Nenhum dado e enviado para servicos de nuvem.

---

## Atualizacoes

A aba **Atualizacoes** verifica automaticamente se ha novas versoes disponiveis e exibe as notas de release.

---

## Configuracoes

Acesse via o botao **Configuracoes** no canto superior direito.

### Abas disponiveis

| Aba | Conteudo |
|-----|----------|
| **Geral** | Caminho dos logs, idioma (PT-BR / EN-US) |
| **Chaves de API** | VirusTotal, AbuseIPDB, URLHaus, Shodan, MalwareBazaar, GitHub, GitLab |
| **Ollama** | Endpoint do Ollama, teste de conexao |
| **Sobre** | Versao, autor, licenca |

### Idioma

O ThreatDeflect suporta Portugues (BR) e Ingles (US). Troque o idioma na aba Geral das configuracoes. A mudanca e aplicada imediatamente.

### Armazenamento de chaves

As chaves de API sao armazenadas no keyring do sistema operacional:

- **Windows**: Credential Locker
- **macOS**: Keychain
- **Linux**: Secret Service (GNOME Keyring, KWallet)
