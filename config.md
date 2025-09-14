# ⚙️ Guia de Configuração de APIs para o ThreatDeflect

Este guia detalha como obter e configurar as chaves de API necessárias para habilitar todas as funcionalidades do **ThreatDeflect**.  
As chaves são armazenadas de forma segura no cofre de credenciais do seu sistema operacional usando a biblioteca **keyring**.

---

## 📑 Sumário

- [VirusTotal (Obrigatória)](#virustotal)  
- [GitHub / GitLab (Recomendada)](#github)  
- [AbuseIPDB (Opcional)](#abuseipdb)  
- [Shodan (Opcional)](#shodan)  
- [URLHaus & MalwareBazaar (Opcional)](#urlhaus-malwarebazaar)  
- [Ollama (Opcional)](#ollama)  

---

<a id="virustotal"></a>
## 🔑 VirusTotal (Obrigatória)

**Propósito:** Essencial para verificar a reputação de IPs, URLs, domínios e hashes de arquivos.  
**Nível:** Chave gratuita é suficiente para uso moderado.  

### Como Obter a Chave
1. Crie uma conta ou faça login no site do [VirusTotal](https://www.virustotal.com).  
2. Navegue até o seu perfil no canto superior direito e clique em **API Key**.  
3. Copie a chave exibida.  

### Configuração no ThreatDeflect
Na primeira vez que você executar, o ThreatDeflect solicitará a chave do VirusTotal. Cole-a no campo correspondente.  

---

> **Notas sobre Limites de API:**  
> A maioria dos serviços (como o VirusTotal) impõe limites de requisições para chaves gratuitas.  
> Esses limites são adequados para **uso pessoal ou moderado**.  
>  
> **Exemplo de uso moderado:** verificar algumas dezenas de domínios, IPs ou arquivos por semana.  
>  
> Caso a utilização seja em **ambiente corporativo ou com grande volume de análises (ex.: varrer centenas de domínios, IPs ou arquivos por dia)**, considere adquirir uma **chave de API paga** para garantir estabilidade e evitar bloqueios.



<a id="github"></a>
## 🔑 GitHub / GitLab (Recomendada)

**Propósito:** Permite a análise de repositórios privados e aumenta o limite de requisições para APIs de repositórios públicos.  
**Nível:** Token de acesso pessoal (**PAT - Personal Access Token**).  

### Como Obter a Chave (GitHub)
1. Acesse sua conta do [GitHub](https://github.com).  
2. Vá para **Settings > Developer settings > Personal access tokens > Tokens (classic)**.  
3. Clique em **Generate new token (classic)**.  
4. Dê um nome ao token (ex: `ThreatDeflect-token`).  
5. Selecione o escopo `public_repo` (para repositórios públicos) e `repo` (se precisar analisar repositórios privados).  
6. Clique em **Generate token** e copie a chave gerada.  

### Configuração no ThreatDeflect
Na aba **Configurações**, cole o token nos campos correspondentes do GitHub ou GitLab.  

> **Notas sobre Limites de API:**  
> A análise de um único repositório pode gerar dezenas de chamadas à API do GitHub para listar diretórios e arquivos.  
>  
> Sem token, o limite é de **aprox. 60 requisições por hora** por IP.  
>  
> Com token, esse limite sobe para **5.000 requisições por hora** por usuário.  
>  
>  
> Para evitar falhas, o ThreatDeflect alerta se você tentar analisar mais de **2 repositórios** ao mesmo tempo.  
>  
> Em repositórios muito grandes, use um **token**, divida a análise em **lotes menores** e, se necessário, considere **planos pagos corporativos**.


---

**Dica: verifique seu limite atual antes de rodar análises:**

```bash
curl -i -H "Authorization: Bearer SEU_TOKEN_AQUI" https://api.github.com/rate_limit
```

isso retorna os limites e o saldo restante de requisições, incluindo a quota especial de `search`.

<a id="abuseipdb"></a>
## 🔑 AbuseIPDB (Opcional)

**Propósito:** Fornece um "score de abuso" para endereços IP, indicando a probabilidade de ser uma fonte maliciosa.  
**Nível:** Chave gratuita.  

### Como Obter a Chave
1. Crie uma conta no site do [AbuseIPDB](https://www.abuseipdb.com).  
2. Após o login, vá para a seção **Account**.  
3. Clique em **Create API Key**.  
4. Copie a chave gerada.  

### Configuração no ThreatDeflect
Na aba **Configurações**, cole a chave no campo do AbuseIPDB.  

---

<a id="shodan"></a>
## 🔑 Shodan (Opcional)

**Propósito:** Identifica portas abertas, serviços e banners para um determinado endereço IP.  
**Nível:** Chave gratuita (limitada) ou paga.  

### Como Obter a Chave
1. Crie uma conta no site do [Shodan](https://www.shodan.io).  
2. Após o login, sua chave de API estará visível no topo da página da sua conta.  
3. Copie a chave.  

### Configuração no ThreatDeflect
Na aba **Configurações**, cole a chave no campo do Shodan.  

---

<a id="urlhaus-malwarebazaar"></a>
## 🔑 URLHaus & MalwareBazaar (Opcional)

**Propósito:**  
- **URLHaus** identifica URLs associadas à distribuição de malware.  
- **MalwareBazaar** mapeia hashes de arquivos para nomes de ameaças conhecidas.  

**Nível:** Chave de API gratuita. 

### Como Obter as Chaves
**URLHaus:**  
1. Acesse o site [urlhaus.chabuse](https://urlhaus.abuse.ch/) 
2. Faça login usando uma conta.  
3. Navegue até a sua página de perfil para encontrar sua chave de API.  

**MalwareBazaar:**  
1. Crie uma conta no site do [MalwareBazaar](https://bazaar.abuse.ch).  
2. Após o login, sua chave de API estará disponível na sua página de conta.  

### Configuração no ThreatDeflect
Na aba **Configurações**, cole as chaves nos campos correspondentes do URLHaus e MalwareBazaar.  

---

<a id="ollama"></a>


## 🔑 Ollama (Opcional)

**Propósito:** Habilita a funcionalidade de resumo por IA, rodando modelos de linguagem localmente para garantir a privacidade.  
**Nível:** Não requer chave de API, mas precisa do serviço **Ollama** em execução.  

### Como Configurar
1. Instale o Ollama seguindo as instruções em [ollama.com](https://ollama.com).  
2. Execute o serviço Ollama em seu sistema.  
3. Puxe um modelo de linguagem (o `llama3` é recomendado):  
```bash
ollama pull llama3
```

### Configuração no ThreatDeflect
No ThreatSpy, vá para a aba **Configurações**. O endpoint padrão (`http://localhost:11434`) já estará configurado.  
Se você estiver rodando o Ollama em outra máquina ou porta, ajuste o endereço.  
