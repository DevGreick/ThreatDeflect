# IA Local (Ollama)

O ThreatDeflect integra com o [Ollama](https://ollama.com) para gerar resumos executivos e analises de risco usando modelos de IA rodando localmente na sua maquina.

!!! tip "Privacidade total"
    Nenhum dado e enviado para servicos de nuvem. Tudo roda na sua maquina.

---

## Instalacao do Ollama

=== "Windows"

    Baixe o instalador em [ollama.com](https://ollama.com)

=== "macOS"

    ```bash
    brew install --cask ollama
    ```

=== "Linux"

    ```bash
    curl -fsSL https://ollama.com/install.sh | sh
    ```

### Verificando a instalacao

```bash
ollama --version
```

### Baixando um modelo

```bash
ollama pull llama3
```

---

## Modelos recomendados

| Modelo | Tamanho | Uso recomendado |
|--------|---------|-----------------|
| `llama3:8b` | ~4.7 GB | Uso geral, boa relacao velocidade/qualidade |
| `gpt-oss:20b` | ~12 GB | Resumos mais detalhados, requer mais RAM |
| `mistral` | ~4.1 GB | Rapido, bom para maquinas com menos recursos |
| `llama3:70b` | ~40 GB | Melhor qualidade, requer GPU potente |

---

## Usando no CLI

Adicione a flag `--ai` seguida do nome do modelo:

```bash
# Analise de IOCs com resumo por IA
threatdeflect ioc 8.8.8.8 185.172.128.150 --ai llama3

# Analise de repositorio com IA
threatdeflect repo https://github.com/org/repo --ai gpt-oss:20b

# Analise de arquivos com IA
threatdeflect file suspicious.exe --ai mistral
```

O resumo e incluido automaticamente no relatorio Excel gerado.

---

## Usando na GUI

1. Realize uma analise (IOC, Repositorio ou Arquivo)
2. Selecione o modelo na lista **Modelo IA** na parte inferior
3. Clique em **Gerar Resumo em Texto** ou **Gerar Resumo em PDF**

---

## Configuracao do endpoint

Por padrao, o Ollama roda em `http://localhost:11434/api/generate`.

Para alterar:

=== "CLI"

    ```bash
    threatdeflect config set-ollama http://seu-servidor:11434/api/generate
    ```

=== "GUI"

    1. Abra **Configuracoes**
    2. Va na aba **Ollama**
    3. Altere o endpoint
    4. Clique em **Testar Conexao** para verificar

---

## Solucao de problemas

### "A IA nao retornou uma resposta"

Verifique se o modelo esta respondendo:

```bash
curl http://localhost:11434/api/generate -d '{"model":"llama3:8b","prompt":"test","stream":false}' | jq .response
```

Se retornar `null`, o modelo pode estar corrompido:

```bash
ollama rm llama3:8b
ollama pull llama3:8b
```

### Ollama nao esta rodando

```bash
ollama serve
```

Ou inicie o servico:

```bash
sudo systemctl start ollama
```
