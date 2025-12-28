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


def test_rust_calculates_entropy():
    analyzer = RustAnalyzer({}, {})

    high_entropy_str = '"7f8a9b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v_very_long_string_to_trigger_detection"'
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
