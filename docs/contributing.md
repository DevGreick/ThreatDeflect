# Contribuicao

## Como contribuir

1. Faca um fork do repositorio
2. Crie uma branch: `git checkout -b feature/nova-feature`
3. Commit: `git commit -m "feat: add nova feature"`
4. Push: `git push origin feature/nova-feature`
5. Abra um Pull Request

---

## Padroes de commit

Usamos [Conventional Commits](https://www.conventionalcommits.org/) em ingles:

| Prefixo | Uso |
|---------|-----|
| `feat:` | Nova funcionalidade |
| `fix:` | Correcao de bug |
| `docs:` | Alteracao na documentacao |
| `refactor:` | Refatoracao sem mudanca de comportamento |
| `test:` | Adicao ou correcao de testes |
| `build:` | Mudanca no sistema de build ou dependencias |
| `ci:` | Mudanca nos arquivos de CI/CD |

Exemplos:

```
feat: add Discord webhook detection rule
fix: resolve false positive on JWT detection
docs: update CLI reference with new config commands
```

---

## Ambiente de desenvolvimento

```bash
git clone https://github.com/DevGreick/ThreatDeflect.git
cd ThreatDeflect

# Setup com uv
uv sync
uv run threatdeflect --help
uv run threatdeflect-gui

# Motor Rust (opcional)
pip install maturin
maturin develop --release
```

---

## Estrutura do projeto

```
threatdeflect/
  cli/main.py              # CLI (Typer)
  ui/main_gui.py           # GUI (PySide6)
  core/engine.py           # Motor de analise
  core/repository_analyzer.py  # Analisador de repositorios
  core/rules.yaml          # Regras de deteccao
  api/api_client.py        # Cliente de APIs
  utils/utils.py           # Utilidades
rust_core/
  src/lib.rs               # Motor Rust (PyO3)
  Cargo.toml               # Config Rust
```

---

## Licenca

Ao submeter um Pull Request, voce concorda que suas contribuicoes serao licenciadas sob a mesma licenca **GPLv3** do projeto.
