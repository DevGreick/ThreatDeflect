# Contributing to ThreatDeflect

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USER/ThreatDeflect.git`
3. Create a branch from `dev`: `git checkout -b feature/your-feature dev`
4. Make your changes
5. Open a Pull Request targeting the `dev` branch

## Development Setup

### Requirements

- Python 3.8+
- Rust (stable toolchain)
- Maturin (`pip install maturin`)

### Build

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
maturin develop --release
```

### Run Tests

```bash
pytest
```

## Pull Request Guidelines

- Target the `dev` branch (not `main`)
- Keep PRs focused on a single change
- Follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages
- Add tests for new detection rules
- Ensure all tests pass before submitting
- Direct pushes to `main` and `dev` are blocked by a CI check (`validate-author`). Always use Pull Requests

## Adding Detection Rules

Rules are defined in `threatdeflect/core/rules.yaml`. Each rule needs:

- `id`: Unique identifier (e.g., `CLOUD_METADATA_SSRF`)
- `pattern`: Regex pattern
- `severity`: `Critical`, `High`, `Medium`, `Low`, or `Info`
- `description`: What the rule detects
- `recommendation`: How to fix

## Code Style

- Python: PEP 8, type hints required
- Rust: Standard formatting (`cargo fmt`)
- No comments in code, clarity through naming and types

## Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Production, protected |
| `dev` | Development, accepts PRs |

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
