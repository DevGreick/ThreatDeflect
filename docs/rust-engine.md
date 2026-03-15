# Motor Rust

O ThreatDeflect possui um motor hibrido em Rust (`threatdeflect_rs`) compilado via **Maturin/PyO3** que oferece performance nativa para as operacoes mais pesadas da analise.

---

## O que o motor Rust acelera

| Funcao | Descricao |
|--------|-----------|
| Deteccao de segredos | Compila e executa todas as regras regex do rules.yaml |
| Calculo de entropia | Identifica strings de alta entropia (possiveis segredos) |
| Analise de contexto | Valida se comandos suspeitos estao em contexto seguro (comentarios, docs) |
| Deteccao de Base64 | Encontra IOCs ofuscados em Base64 |
| Extracao de URLs | Identifica URLs diretas em codigo-fonte |

---

## Fallback automatico

O motor Rust e **opcional**. Se o modulo `threatdeflect_rs` nao estiver compilado, o ThreatDeflect usa automaticamente a implementacao em Python puro. Todas as funcionalidades permanecem disponiveis, apenas com menor performance em analises grandes.

---

## Compilando o motor Rust

### Requisitos

- Rust toolchain (instale via [rustup.rs](https://rustup.rs))
- Maturin (`pip install maturin`)
- Python 3.11+ em um ambiente virtual

### Compilacao

```bash
# Ative o ambiente virtual
source .venv/bin/activate   # ou: uv sync

# Compile o modulo
pip install maturin
maturin develop --release
```

O comando `maturin develop --release` compila o modulo Rust e instala diretamente no ambiente virtual ativo.

!!! warning "Ambiente virtual obrigatorio"
    O `maturin develop` exige um virtualenv ativo. Nao funciona com Python do sistema.

### Verificando a instalacao

```python
python -c "import threatdeflect_rs; print('Motor Rust disponivel')"
```

---

## Dependencias Rust

| Crate | Versao | Uso |
|-------|--------|-----|
| `pyo3` | 0.28 | Bridge Python/Rust |
| `regex` | 1.11 | Compilacao e execucao de patterns |
| `base64` | 0.22 | Decodificacao de payloads Base64 |
| `url` | 2.5 | Parsing e validacao de URLs |

---

## Arquitetura

```
rust_core/
  Cargo.toml       # Configuracao do projeto Rust
  src/
    lib.rs          # Modulo principal com RustAnalyzer
```

A classe `RustAnalyzer` e exposta para Python via PyO3 e disponibiliza o metodo principal `process_file_content()` que recebe o conteudo de um arquivo e retorna todos os achados (segredos, comandos suspeitos, IOCs, etc.).
