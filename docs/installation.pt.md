# Instalacao

## Executaveis (Recomendado)

Baixe o executavel para o seu sistema na pagina de [Releases](https://github.com/DevGreick/ThreatDeflect/releases). Nao precisa de Python instalado.

| Sistema | Arquivo | Execucao |
|---------|---------|----------|
| Windows | `ThreatDeflect-GUI-Windows.exe` | Duplo clique |
| Linux   | `ThreatDeflect-CLI-Linux` | `chmod +x` e execute |
| macOS   | `ThreatDeflect-CLI-macOS` | Veja instrucoes abaixo |

### Windows

**GUI:** Baixe o `.exe` e execute com duplo clique.

**CLI:** Para usar o CLI no terminal (CMD ou PowerShell):

1. Crie uma pasta, por exemplo `C:\Tools\`
2. Mova o `ThreatDeflect-CLI-Windows.exe` para essa pasta
3. Adicione ao PATH do sistema:
    - Abra **Configuracoes > Sistema > Sobre > Configuracoes avancadas do sistema**
    - Clique em **Variaveis de Ambiente**
    - Em **Variaveis do sistema**, selecione `Path` e clique em **Editar**
    - Clique em **Novo** e adicione `C:\Tools\`
    - Clique **OK** em tudo
4. Abra um novo terminal e teste:

```powershell
ThreatDeflect-CLI-Windows.exe --help
```

!!! tip "Alternativa rapida"
    Se nao quiser adicionar ao PATH, navegue ate a pasta do executavel e rode direto:
    ```powershell
    cd C:\Users\SeuUsuario\Downloads
    .\ThreatDeflect-CLI-Windows.exe --help
    ```

### Linux

**GUI:** Baixe, de permissao e execute:

```bash
chmod +x ThreatDeflect-GUI-Linux
./ThreatDeflect-GUI-Linux
```

**CLI:** Para usar de qualquer lugar no terminal:

1. Mova o executavel para uma pasta no PATH:

```bash
sudo mv ThreatDeflect-CLI-Linux /usr/local/bin/threatdeflect
sudo chmod +x /usr/local/bin/threatdeflect
```

2. Teste:

```bash
threatdeflect --help
```

!!! tip "Alternativa sem sudo"
    Se preferir instalar so para o seu usuario:
    ```bash
    mkdir -p ~/.local/bin
    mv ThreatDeflect-CLI-Linux ~/.local/bin/threatdeflect
    chmod +x ~/.local/bin/threatdeflect
    ```
    Certifique-se de que `~/.local/bin` esta no seu PATH (adicione `export PATH="$HOME/.local/bin:$PATH"` ao seu `.bashrc` ou `.zshrc`).

### macOS

O macOS bloqueia binarios de fontes externas. Primeiro remova o bloqueio:

```bash
chmod +x ThreatDeflect-GUI-macOS ThreatDeflect-CLI-macOS
xattr -cr ThreatDeflect-GUI-macOS ThreatDeflect-CLI-macOS
```

**GUI:** Execute pelo terminal:

```bash
./ThreatDeflect-GUI-macOS
```

!!! warning "Finder"
    O Finder nao executa binarios sem extensao `.app`. Use sempre o terminal.

**CLI:** Para usar de qualquer lugar no terminal:

1. Mova o executavel para uma pasta no PATH:

```bash
sudo mv ThreatDeflect-CLI-macOS /usr/local/bin/threatdeflect
sudo chmod +x /usr/local/bin/threatdeflect
```

2. Teste:

```bash
threatdeflect --help
```

!!! tip "Alternativa sem sudo"
    ```bash
    mkdir -p ~/.local/bin
    mv ThreatDeflect-CLI-macOS ~/.local/bin/threatdeflect
    chmod +x ~/.local/bin/threatdeflect
    ```
    Adicione `export PATH="$HOME/.local/bin:$PATH"` ao seu `.zshrc` se necessario.

---

## Codigo-Fonte

### Requisitos

| Modo | Requisitos |
|------|-----------|
| **Executavel (Release)** | Nenhum |
| **Codigo-fonte** | Python 3.11+, Git |
| **Rust engine (opcional)** | Rust toolchain, Maturin |
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
