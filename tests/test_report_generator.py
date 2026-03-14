# ===================================================================
# Módulo de Testes do Report Generator (test_report_generator.py)
# ===================================================================
# tests/test_report_generator.py

import os
import tempfile
import pytest

from threatdeflect.core.report_generator import ReportGenerator


@pytest.fixture
def sample_ip_results():
    return {
        "8.8.8.8": {
            "virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}, "as_owner": "Google"}}},
            "abuseipdb": {"data": {"abuseConfidenceScore": 0, "countryCode": "US"}},
            "shodan": {"ports": [53, 443], "org": "Google LLC", "hostnames": ["dns.google"], "vulns": []},
        }
    }


@pytest.fixture
def sample_url_results():
    return {
        "https://example.com": {
            "virustotal": {"data": {"id": "u-test-123", "attributes": {"stats": {"malicious": 0}}}},
            "urlhaus": {"query_status": "no_results"},
        }
    }


@pytest.fixture
def sample_file_results():
    return {
        "a" * 64: {
            "filename": "test.exe",
            "virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 5}, "trid": [{"file_type": "PE32"}], "size": 1024}}},
            "malwarebazaar": {"query_status": "ok", "data": [{"signature": "Trojan.Generic"}]},
        }
    }


@pytest.fixture
def sample_repo_results():
    return [
        {
            "url": "https://github.com/test/repo",
            "risk_score": 75,
            "findings": [
                {"severity": "HIGH", "description": "Hardcoded API Key", "type": "Generic API Key", "file": "config.py"},
                {"severity": "MEDIUM", "description": "Suspicious command", "type": "Suspicious Command", "file": "setup.py"},
            ],
            "dependencies": {"requirements.txt": ["requests", "flask"]},
            "extracted_iocs": [
                {"ioc": "https://malicious.example.com", "source_file": "main.py", "reputation": {"virustotal": {"data": {"attributes": {"stats": {"malicious": 3}}}}}},
            ],
        }
    ]


class TestReportGeneratorInit:
    def test_defaults(self):
        rg = ReportGenerator()
        assert rg.ip_results == {}
        assert rg.url_results == {}
        assert rg.file_results == {}
        assert rg.repo_results == []
        assert rg.executive_summary == ""

    def test_with_data(self, sample_ip_results, sample_url_results):
        rg = ReportGenerator(ip_results=sample_ip_results, url_results=sample_url_results)
        assert len(rg.ip_results) == 1
        assert len(rg.url_results) == 1

    def test_spoofing_detection(self):
        url_results = {"https://www.xn--80ak6aa92e.com": {"virustotal": {}}}
        rg = ReportGenerator(url_results=url_results)
        assert "https://www.xn--80ak6aa92e.com" in rg.spoofing_warnings
        assert rg.spoofing_warnings["https://www.xn--80ak6aa92e.com"] == "Punycode/Cyrillic"


class TestExcelGeneration:
    def test_generate_empty_report(self):
        rg = ReportGenerator()
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_excel(filepath)
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)

    def test_generate_ip_report(self, sample_ip_results):
        rg = ReportGenerator(ip_results=sample_ip_results)
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_excel(filepath)
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)

    def test_generate_url_report(self, sample_url_results):
        rg = ReportGenerator(url_results=sample_url_results)
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_excel(filepath)
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)

    def test_generate_file_report(self, sample_file_results):
        rg = ReportGenerator(file_results=sample_file_results)
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_excel(filepath)
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)

    def test_generate_repo_report(self, sample_repo_results):
        rg = ReportGenerator(repo_results=sample_repo_results, executive_summary="Test summary")
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_excel(filepath)
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)

    def test_generate_combined_report(self, sample_ip_results, sample_url_results, sample_file_results):
        rg = ReportGenerator(
            ip_results=sample_ip_results,
            url_results=sample_url_results,
            file_results=sample_file_results,
        )
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_excel(filepath)
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)

    def test_spoofing_warning_sheet(self):
        url_results = {"https://www.xn--80ak6aa92e.com": {"virustotal": {"data": {"attributes": {"stats": {"malicious": 0}}}}}}
        rg = ReportGenerator(url_results=url_results)
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_excel(filepath)
            assert os.path.exists(filepath)
        finally:
            os.unlink(filepath)


class TestPdfGeneration:
    def test_generate_pdf_with_ip_data(self, sample_ip_results):
        rg = ReportGenerator(ip_results=sample_ip_results)
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_pdf_summary(filepath, "## Resumo\nNenhuma ameaca critica.")
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)

    def test_generate_pdf_with_repo_data(self, sample_repo_results):
        rg = ReportGenerator(repo_results=sample_repo_results)
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_pdf_summary(filepath, "## Resumo\nRisco alto detectado.")
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)

    def test_generate_pdf_with_error_summary(self, sample_ip_results):
        rg = ReportGenerator(ip_results=sample_ip_results)
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_pdf_summary(filepath, "Erro: Modelo nao encontrado.")
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)

    def test_generate_pdf_with_markdown_table(self, sample_url_results):
        rg = ReportGenerator(url_results=sample_url_results)
        summary = "## Tabela\n| IOC | Score |\n|---|---|\n| test | 0 |\n\n### Conclusao\nNenhuma ameaca."
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_pdf_summary(filepath, summary)
            assert os.path.exists(filepath)
            assert os.path.getsize(filepath) > 0
        finally:
            os.unlink(filepath)


class TestEdgeCases:
    def test_empty_findings_repo(self):
        repo_results = [{"url": "https://github.com/clean/repo", "risk_score": 0, "findings": [], "dependencies": {}, "extracted_iocs": []}]
        rg = ReportGenerator(repo_results=repo_results)
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_excel(filepath)
            assert os.path.exists(filepath)
        finally:
            os.unlink(filepath)

    def test_shodan_not_found(self):
        ip_results = {"1.1.1.1": {"virustotal": None, "abuseipdb": None, "shodan": {"error": "Not Found"}}}
        rg = ReportGenerator(ip_results=ip_results)
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_excel(filepath)
            assert os.path.exists(filepath)
        finally:
            os.unlink(filepath)

    def test_vt_not_found_file(self):
        file_results = {"b" * 64: {"filename": "clean.txt", "virustotal": {"error": "Not Found"}, "malwarebazaar": {"query_status": "hash_not_found"}}}
        rg = ReportGenerator(file_results=file_results)
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            filepath = f.name
        try:
            rg.generate_excel(filepath)
            assert os.path.exists(filepath)
        finally:
            os.unlink(filepath)
