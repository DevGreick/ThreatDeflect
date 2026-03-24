# Installation

## Executables (Recommended)

Download the executable for your system from the [Releases](https://github.com/DevGreick/ThreatDeflect/releases) page. No Python installation required.

| System | File | How to run |
|--------|------|------------|
| Windows | `ThreatDeflect-GUI-Windows.exe` | Double-click |
| Linux   | `ThreatDeflect-CLI-Linux` | `chmod +x` and run |
| macOS   | `ThreatDeflect-CLI-macOS` | See instructions below |

### Windows

**GUI:** Download the `.exe` and double-click to run.

**CLI:** To use the CLI in a terminal (CMD or PowerShell):

1. Create a folder, for example `C:\Tools\`
2. Move `ThreatDeflect-CLI-Windows.exe` to that folder
3. Add it to the system PATH:
    - Open **Settings > System > About > Advanced system settings**
    - Click **Environment Variables**
    - Under **System variables**, select `Path` and click **Edit**
    - Click **New** and add `C:\Tools\`
    - Click **OK** on everything
4. Open a new terminal and test:

```powershell
ThreatDeflect-CLI-Windows.exe --help
```

!!! tip "Quick alternative"
    If you don't want to add it to PATH, navigate to the executable's folder and run it directly:
    ```powershell
    cd C:\Users\YourUser\Downloads
    .\ThreatDeflect-CLI-Windows.exe --help
    ```

### Linux

**GUI:** Download, set permissions, and run:

```bash
chmod +x ThreatDeflect-GUI-Linux
./ThreatDeflect-GUI-Linux
```

**CLI:** To use it from anywhere in the terminal:

1. Move the executable to a folder in your PATH:

```bash
sudo mv ThreatDeflect-CLI-Linux /usr/local/bin/threatdeflect
sudo chmod +x /usr/local/bin/threatdeflect
```

2. Test:

```bash
threatdeflect --help
```

!!! tip "Alternative without sudo"
    If you prefer to install only for your user:
    ```bash
    mkdir -p ~/.local/bin
    mv ThreatDeflect-CLI-Linux ~/.local/bin/threatdeflect
    chmod +x ~/.local/bin/threatdeflect
    ```
    Make sure `~/.local/bin` is in your PATH (add `export PATH="$HOME/.local/bin:$PATH"` to your `.bashrc` or `.zshrc`).

### macOS

macOS blocks binaries from external sources. First remove the quarantine flag:

```bash
chmod +x ThreatDeflect-GUI-macOS ThreatDeflect-CLI-macOS
xattr -cr ThreatDeflect-GUI-macOS ThreatDeflect-CLI-macOS
```

**GUI:** Run from the terminal:

```bash
./ThreatDeflect-GUI-macOS
```

!!! warning "Finder"
    Finder does not execute binaries without a `.app` extension. Always use the terminal.

**CLI:** To use it from anywhere in the terminal:

1. Move the executable to a folder in your PATH:

```bash
sudo mv ThreatDeflect-CLI-macOS /usr/local/bin/threatdeflect
sudo chmod +x /usr/local/bin/threatdeflect
```

2. Test:

```bash
threatdeflect --help
```

!!! tip "Alternative without sudo"
    ```bash
    mkdir -p ~/.local/bin
    mv ThreatDeflect-CLI-macOS ~/.local/bin/threatdeflect
    chmod +x ~/.local/bin/threatdeflect
    ```
    Add `export PATH="$HOME/.local/bin:$PATH"` to your `.zshrc` if needed.

---

## Source Code

### Requirements

| Mode | Requirements |
|------|-------------|
| **Executable (Release)** | None |
| **Source code** | Python 3.11+, Git |
| **Rust engine (optional)** | Rust toolchain, Maturin |
| **Local AI (optional)** | Ollama installed and running |

### With `uv` (recommended)

```bash
git clone https://github.com/DevGreick/ThreatDeflect.git
cd ThreatDeflect

uv sync
uv run threatdeflect --help       # CLI
uv run threatdeflect-gui          # GUI
```

### With `pip`

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

## First Use

After installing, configure at least the **VirusTotal** key:

=== "CLI"

    ```bash
    threatdeflect config set virustotal YOUR_KEY
    threatdeflect config show
    ```

=== "GUI"

    Open the **Settings** tab and paste your key in the VirusTotal field.

See the [API Guide](api-configuration.md) for instructions on obtaining your keys.
