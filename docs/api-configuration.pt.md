# Configuracao de APIs

## Visao geral

| Servico | Necessidade | O que habilita |
|---------|-------------|----------------|
| **VirusTotal** | Obrigatoria | Reputacao de IPs, URLs e arquivos |
| **GitHub** | Recomendada | Analise de repositorios (rate limit 5000 req/hr) |
| **GitLab** | Recomendada | Analise de repositorios GitLab |
| **AbuseIPDB** | Opcional | Score de abuso de IPs |
| **Shodan** | Opcional | Portas abertas e servicos |
| **URLHaus** | Opcional | URLs usadas para distribuir malware |
| **MalwareBazaar** | Opcional | Identificacao de ameacas por hash |
| **Ollama** | Opcional | Resumos automaticos com IA local |

---

## Como obter as chaves

### VirusTotal (obrigatoria)

1. Crie uma conta em [virustotal.com](https://www.virustotal.com)
2. Acesse seu perfil e copie a API Key
3. Plano gratuito: 500 requisicoes/dia

### GitHub

1. Acesse [github.com/settings/tokens](https://github.com/settings/tokens)
2. Gere um token com permissao de leitura publica
3. Aumenta o rate limit de 60 para 5000 req/hr

### GitLab

1. Acesse Settings > Access Tokens no GitLab
2. Crie um token com scope `read_api`

### AbuseIPDB

1. Registre-se em [abuseipdb.com](https://www.abuseipdb.com)
2. Acesse API > Create Key
3. Plano gratuito: 1000 checks/dia

### Shodan

1. Crie conta em [shodan.io](https://www.shodan.io)
2. A API Key esta no dashboard
3. Plano gratuito disponivel

### URLHaus

1. Registre-se em [urlhaus.abuse.ch](https://urlhaus.abuse.ch)
2. A API e gratuita e sem limite

### MalwareBazaar

1. API gratuita em [bazaar.abuse.ch](https://bazaar.abuse.ch)
2. Nao requer autenticacao para consultas por hash

---

## Configurando as chaves

=== "CLI"

    ```bash
    threatdeflect config set virustotal SUA_CHAVE
    threatdeflect config set github SEU_TOKEN
    threatdeflect config set abuseipdb SUA_CHAVE
    threatdeflect config set shodan SUA_CHAVE
    threatdeflect config show
    ```

=== "GUI"

    1. Clique em **Configuracoes** no canto superior direito
    2. Navegue ate a aba **Chaves de API**
    3. Cole cada chave no campo correspondente
    4. As chaves sao salvas automaticamente

---

## Armazenamento seguro

As chaves sao armazenadas no keyring do sistema operacional:

| Sistema | Backend |
|---------|---------|
| Windows | Credential Locker |
| macOS | Keychain |
| Linux | Secret Service (GNOME Keyring, KWallet) |

As chaves nunca sao salvas em arquivos de texto ou variaveis de ambiente.

---

## Cache

O ThreatDeflect usa cache SQLite para evitar consultas repetidas as APIs. O cache e armazenado na subpasta `.threatdeflect_cache/` no diretorio do executavel.

Isso preserva sua cota de requisicoes e acelera analises recorrentes.

Para limpar o cache na GUI, use o botao **Limpar** na aba de IOCs.
