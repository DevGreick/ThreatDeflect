# Rust Engine

O ThreatDeflect possui um hybrid engine em Rust compilado via **Maturin/PyO3** que oferece performance nativa para as operacoes mais pesadas da analise.

O engine e publicado como crate independente no crates.io: [**threatdeflect-core**](https://crates.io/crates/threatdeflect-core)

---

## O que o Rust engine acelera

| Funcao | Descricao |
|--------|-----------|
| Deteccao de segredos | Compila e executa todas as regras regex do rules.yaml |
| Calculo de entropia | Identifica strings de alta entropia (possiveis segredos) |
| Confidence scoring | Ajusta confianca por entropia, contexto de arquivo e placeholders |
| Analise de contexto | Valida se comandos suspeitos estao em contexto seguro (comentarios, docs) |
| Deteccao de Base64 | Encontra IOCs ofuscados em Base64 |
| Extracao de URLs | Identifica URLs diretas em codigo-fonte |
| Paste Service C2 | Detecta URLs de servicos de paste usados como C2/staging |

---

## Usando como crate Rust (independente do Python)

Adicione ao seu `Cargo.toml`:

```toml
[dependencies]
threatdeflect-core = "0.1"
```

```rust
use threatdeflect_core::SecretAnalyzer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rules = vec![
        ("AWS Key".to_string(), r"AKIA[0-9A-Z]{16}".to_string()),
        ("GitHub Token".to_string(), r"ghp_[a-zA-Z0-9]{36}".to_string()),
    ];

    let suspicious = vec![
        ("Reverse Shell".to_string(), r"bash\s+-i\s+>&\s+/dev/tcp".to_string()),
    ];

    let analyzer = SecretAnalyzer::new(rules, suspicious)?;
    let result = analyzer.analyze_content(
        "aws_key = AKIAIOSFODNN7EXAMPLE1",
        "src/config.py",
        "config.py",
    );

    for finding in &result.findings {
        println!(
            "[{:.0}%] {} in {} ({})",
            finding.confidence * 100.0,
            finding.finding_type,
            finding.file,
            finding.file_context.as_str(),
        );
    }

    Ok(())
}
```

Documentacao completa da crate: [docs.rs/threatdeflect-core](https://docs.rs/threatdeflect-core)

---

## Fallback automatico

O Rust engine e **opcional** no contexto Python. Se o modulo `threatdeflect_rs` nao estiver compilado, o ThreatDeflect usa automaticamente a implementacao em Python puro. Todas as funcionalidades permanecem disponiveis, apenas com menor performance em analises grandes.

---

## Compilando para Python

### Requisitos

- Rust toolchain (instale via [rustup.rs](https://rustup.rs))
- Maturin (`uv tool install maturin`)
- Python 3.11+ em um ambiente virtual

### Compilacao

```bash
source .venv/bin/activate
maturin develop --release
```

O comando `maturin develop --release` compila o modulo Rust e instala diretamente no ambiente virtual ativo.

!!! warning "Ambiente virtual obrigatorio"
    O `maturin develop` exige um virtualenv ativo. Nao funciona com Python do sistema.

### Verificando a instalacao

```python
python -c "import threatdeflect_rs; print('Rust engine available')"
```

---

## Arquitetura

```
threatdeflect-core/          Crate pura (publicada no crates.io)
  src/
    lib.rs                   Re-exports publicos
    analyzer.rs              SecretAnalyzer: orquestra deteccao
    confidence.rs            Entropia Shannon, scoring, ajustes
    context.rs               Classificacao de arquivo, comentarios
    types.rs                 Finding, Ioc, AnalysisResult (com zeroize)
    error.rs                 AnalyzerError (thiserror)

rust_core/                   Wrapper PyO3 (~50 linhas)
  src/
    lib.rs                   Converte tipos Rust -> PyDict/PyList
```

A classe `RustAnalyzer` e exposta para Python via PyO3 e disponibiliza o metodo principal `process_file_content()` que recebe o conteudo de um arquivo e retorna todos os achados (segredos, comandos suspeitos, IOCs, etc.).

---

## Seguranca de memoria

| Recurso | Implementacao |
|---------|---------------|
| Limpeza de secrets | `zeroize` no `Drop` de `Finding` e `Ioc` |
| Parsing seguro | `serde(deny_unknown_fields)` em todos os tipos |
| Error handling | `thiserror` com `Result`, zero `.unwrap()` em runtime |
| Unsafe | Zero blocos `unsafe` |

---

## Dependencias Rust

| Crate | Versao | Uso |
|-------|--------|-----|
| `regex` | 1.11 | Compilacao e execucao de patterns |
| `base64` | 0.22 | Decodificacao de payloads Base64 |
| `url` | 2.5 | Parsing e validacao de URLs |
| `serde` | 1.0 | Serializacao/desserializacao (JSON, YAML, etc.) |
| `thiserror` | 2 | Erros tipados |
| `zeroize` | 1.8 | Limpeza segura de memoria sensivel |
| `pyo3` | 0.28 | Bridge Python/Rust (apenas no wrapper) |
