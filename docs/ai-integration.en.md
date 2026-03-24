# Local AI (Ollama)

ThreatDeflect integrates with [Ollama](https://ollama.com) to generate executive summaries and risk analyses using AI models running locally on your machine.

!!! tip "Full privacy"
    No data is sent to cloud services. Everything runs on your machine.

---

## Installing Ollama

=== "Windows"

    Download the installer from [ollama.com](https://ollama.com)

=== "macOS"

    ```bash
    brew install --cask ollama
    ```

=== "Linux"

    ```bash
    curl -fsSL https://ollama.com/install.sh | sh
    ```

### Verifying the installation

```bash
ollama --version
```

### Downloading a model

```bash
ollama pull llama3
```

---

## Recommended models

| Model | Size | Recommended use |
|-------|------|-----------------|
| `llama3:8b` | ~4.7 GB | General use, good speed/quality ratio |
| `gpt-oss:20b` | ~12 GB | More detailed summaries, requires more RAM |
| `mistral` | ~4.1 GB | Fast, good for machines with fewer resources |
| `llama3:70b` | ~40 GB | Best quality, requires a powerful GPU |

---

## Using in CLI

Add the `--ai` flag followed by the model name:

```bash
# IOC analysis with AI summary
threatdeflect ioc 8.8.8.8 185.172.128.150 --ai llama3

# Repository analysis with AI
threatdeflect repo https://github.com/org/repo --ai gpt-oss:20b

# File analysis with AI
threatdeflect file suspicious.exe --ai mistral
```

The summary is automatically included in the generated Excel report.

---

## Using in GUI

1. Perform an analysis (IOC, Repository or File)
2. Select the model from the **AI Model** list at the bottom
3. Click **Generate Text Summary** or **Generate PDF Summary**

---

## Endpoint configuration

By default, Ollama runs at `http://localhost:11434/api/generate`.

To change it:

=== "CLI"

    ```bash
    threatdeflect config set-ollama http://seu-servidor:11434/api/generate
    ```

=== "GUI"

    1. Open **Settings**
    2. Go to the **Ollama** tab
    3. Change the endpoint
    4. Click **Test Connection** to verify

---

## Troubleshooting

### "AI did not return a response"

Check if the model is responding:

```bash
curl http://localhost:11434/api/generate -d '{"model":"llama3:8b","prompt":"test","stream":false}' | jq .response
```

If it returns `null`, the model may be corrupted:

```bash
ollama rm llama3:8b
ollama pull llama3:8b
```

### Ollama is not running

```bash
ollama serve
```

Or start the service:

```bash
sudo systemctl start ollama
```
