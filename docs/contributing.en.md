# Contributing

## How to contribute

1. Fork the repository
2. Create a branch: `git checkout -b feature/nova-feature`
3. Commit: `git commit -m "feat: add nova feature"`
4. Push: `git push origin feature/nova-feature`
5. Open a Pull Request

---

## Commit standards

We use [Conventional Commits](https://www.conventionalcommits.org/) in English:

| Prefix | Usage |
|--------|-------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation change |
| `refactor:` | Refactoring without behavior change |
| `test:` | Adding or fixing tests |
| `build:` | Change in build system or dependencies |
| `ci:` | Change in CI/CD files |

Examples:

```
feat: add Discord webhook detection rule
fix: resolve false positive on JWT detection
docs: update CLI reference with new config commands
```

---

## Development environment

```bash
git clone https://github.com/DevGreick/ThreatDeflect.git
cd ThreatDeflect

# Setup with uv
uv sync
uv run threatdeflect --help
uv run threatdeflect-gui

# Rust engine (optional)
pip install maturin
maturin develop --release
```

---

## Project structure

```
threatdeflect/
  cli/main.py              # CLI (Typer)
  ui/main_gui.py           # GUI (PySide6)
  core/engine.py           # Analysis engine
  core/repository_analyzer.py  # Repository analyzer
  core/rules.yaml          # Detection rules
  api/api_client.py        # API client
  utils/utils.py           # Utilities
rust_core/
  src/lib.rs               # Rust engine (PyO3)
  Cargo.toml               # Rust config
```

---

## License

By submitting a Pull Request, you agree that your contributions will be licensed under the same **GPLv3** license as the project.
