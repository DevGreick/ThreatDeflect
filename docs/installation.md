# Instalacao

## Executaveis (Recomendado)

Baixe o executavel para o seu sistema na pagina de [Releases](https://github.com/DevGreick/ThreatDeflect/releases). Nao precisa de Python instalado.

| Sistema | Arquivo | Execucao |
|---------|---------|----------|
| Windows | `ThreatDeflect-GUI-Windows.exe` | Duplo clique |
| Linux   | `ThreatDeflect-CLI-Linux` | `chmod +x` e execute |
| macOS   | `ThreatDeflect-CLI-macOS` | Veja instrucoes abaixo |

### Windows

Basta baixar o `.exe` e executar com duplo clique.

### Linux

```bash
chmod +x ThreatDeflect-CLI-Linux
./ThreatDeflect-CLI-Linux --help
```

### macOS

O macOS bloqueia binarios de fontes externas. Execute no terminal:

```bash
chmod +x ThreatDeflect-CLI-macOS
xattr -cr ThreatDeflect-CLI-macOS
./ThreatDeflect-CLI-macOS --help
```

!!! warning "Finder"
    O Finder nao executa binarios sem extensao `.app`. Use sempre o terminal.

---

## Codigo-Fonte

### Requisitos

| Modo | Requisitos |
|------|-----------|
| **Executavel (Release)** | Nenhum |
| **Codigo-fonte** | Python 3.11+, Git |
| **Motor Rust (opcional)** | Rust toolchain, Maturin |
| **IA local (opcional)** | Ollama instalado e em execucao |

### Com `uv` (recomendado)

```bash
git clone https://github.com/DevGreick/ThreatDeflect.git
cd ThreatDeflect

uv sync
uv run threatdeflect --help       # CLI
uv run threatdeflect-gui          # GUI
```

### Com `pip`

```bash
git clone https://github.com/DevGreick/ThreatDeflect.git
cd ThreatDeflect

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
pip install -e .

threatdeflect --help               # CLI
threatdeflect-gui                  # GUI
```

---

## Primeiro uso

Apos instalar, configure pelo menos a chave do **VirusTotal**:

=== "CLI"

    ```bash
    threatdeflect config set virustotal SUA_CHAVE
    threatdeflect config show
    ```

=== "GUI"

    Abra a aba **Configuracoes** e cole sua chave no campo VirusTotal.

Veja o [Guia de APIs](api-configuration.md) para obter as chaves.
