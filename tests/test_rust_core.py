import pytest
from threatdeflect_rs import RustAnalyzer


def test_rust_analyzer_instantiation():
    rules = {"AWS Key": "AKIA[0-9A-Z]{16}"}
    suspicious = {"Wget Command": "wget\\s+.*"}
    analyzer = RustAnalyzer(rules, suspicious)
    assert analyzer is not None


def test_rust_finds_aws_key():
    rules = {"AWS Key": "AKIA[0-9A-Z]{16}"}
    analyzer = RustAnalyzer(rules, {})

    content = "const key = 'AKIAIOSFODNN7EXAMPLE';"
    findings, iocs = analyzer.process_file_content(
        content, "src/config.js", "config.js"
    )

    assert len(findings) == 1
    assert findings[0]["type"] == "AWS Key"
    assert findings[0]["description"] == "Possível segredo 'AWS Key' exposto"
    assert "confidence" in findings[0]
    assert "file_context" in findings[0]
    assert findings[0]["file_context"] == "Production"


def test_rust_calculates_entropy():
    analyzer = RustAnalyzer({}, {})

    high_entropy_str = '"Kj7mRpX9sLqW3vNcBfTy8ZaEuGdHxI2oA5wC6nM4bQ0rVtYjFl"'
    content = f"const secret = {high_entropy_str};"

    findings, iocs = analyzer.process_file_content(
        content, "src/secret.js", "secret.js"
    )

    has_entropy_finding = any(f["type"] == "High Entropy String" for f in findings)
    assert has_entropy_finding


def test_rust_extracts_base64_ioc():
    analyzer = RustAnalyzer({}, {})

    content = "let url = 'aHR0cHM6Ly9tYWxpY2lvdXMuY29t';"

    findings, iocs = analyzer.process_file_content(
        content, "src/loader.js", "loader.js"
    )

    assert len(iocs) == 1
    assert iocs[0]["ioc"] == "https://malicious.com"
    assert any(f["type"] == "Hidden IOC (Base64)" for f in findings)


def test_confidence_reduced_in_test_files():
    rules = {"AWS Key": "AKIA[0-9A-Z]{16}"}
    analyzer = RustAnalyzer(rules, {})

    content = 'key = "AKIAJ5ZCGRE4XPOLSA7Q"'
    prod_findings, _ = analyzer.process_file_content(content, "src/config.py", "config.py")
    test_findings, _ = analyzer.process_file_content(content, "tests/test_config.py", "test_config.py")

    assert prod_findings[0]["confidence"] > test_findings[0]["confidence"]
    assert test_findings[0]["file_context"] == "Test"
    assert prod_findings[0]["file_context"] == "Production"


def test_placeholder_detection():
    rules = {"AWS Key": "AKIA[0-9A-Z]{16}"}
    analyzer = RustAnalyzer(rules, {})

    content = 'key = "AKIAIOSFODNN7EXAMPLE"'
    findings, _ = analyzer.process_file_content(content, "src/config.py", "config.py")

    assert len(findings) == 1
    assert findings[0]["confidence"] < 0.1


def test_file_context_classification():
    rules = {"AWS Key": "AKIA[0-9A-Z]{16}"}
    analyzer = RustAnalyzer(rules, {})

    content = 'key = "AKIAJ5ZCGRE4XPOLSA7Q"'

    contexts = {
        "src/config.py": "Production",
        "tests/test_config.py": "Test",
        "examples/demo.py": "Example",
        "docs/setup.md": "Documentation",
    }

    for path, expected_ctx in contexts.items():
        fname = path.rsplit("/", 1)[-1]
        findings, _ = analyzer.process_file_content(content, path, fname)
        assert findings[0]["file_context"] == expected_ctx, f"Expected {expected_ctx} for {path}, got {findings[0]['file_context']}"


def test_secret_validator_aws_fake():
    from threatdeflect.core.secret_validator import validate_finding
    f = {"type": "AWS Key", "match_content": "AKIAIOSFODNN7EXAMPLE", "confidence": 0.9}
    assert validate_finding(f) < 0.1


def test_secret_validator_uuid_as_entropy():
    from threatdeflect.core.secret_validator import validate_finding
    f = {"type": "High Entropy String", "match_content": "550e8400-e29b-41d4-a716-446655440000", "confidence": 0.6}
    assert validate_finding(f) < 0.1


def test_risk_score_calculation():
    from threatdeflect.core.repository_analyzer import RepositoryAnalyzer

    test_findings = [
        {"severity": "CRITICAL", "type": "AWS Key", "confidence": 0.015, "file_context": "Test"}
    ]
    score = RepositoryAnalyzer._calculate_risk_score(None, test_findings)
    assert score < 20

    prod_findings = [
        {"severity": "CRITICAL", "type": "AWS Key", "confidence": 0.90, "file_context": "Production"}
    ]
    score2 = RepositoryAnalyzer._calculate_risk_score(None, prod_findings)
    assert score2 > 80
