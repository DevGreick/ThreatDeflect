# tests/test_engine.py

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from threatdeflect.core import engine
from threatdeflect.core.engine import NoValidTargetsError, AnalysisError, InterruptedException


@pytest.fixture
def mock_api_responses():
    """Fornece respostas de API simuladas."""
    return {
        "ip_response": {
            "virustotal": {"data": {"id": "8.8.8.8"}},
            "abuseipdb": {"data": {"abuseConfidenceScore": 0}},
            "shodan": {"data": {"ports": [53]}}
        },
        "url_response": {
            "virustotal": {"data": {"attributes": {"stats": {"malicious": 1}}}},
            "urlhaus": {"query_status": "ok"}
        },
        "file_response": {
            "virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 10}}}},
            "malwarebazaar": {"query_status": "ok", "data": [{"signature": "Cerber"}]}
        }
    }


def test_run_ioc_analysis_success(monkeypatch, tmp_path, mock_api_responses):
    """Testa o fluxo completo de análise de IOCs com sucesso, usando mocks."""
    mock_api_client = MagicMock()
    mock_api_client.check_ip_multi.return_value = mock_api_responses["ip_response"]
    mock_api_client.check_url_multi.return_value = mock_api_responses["url_response"]
    
    monkeypatch.setattr('threatdeflect.core.engine.ApiClient', lambda: mock_api_client)
    monkeypatch.setattr('threatdeflect.core.report_generator.ReportGenerator.generate_excel', lambda self, path: None)

    targets = "8.8.8.8\nhttps://example.com"
    output_file = tmp_path / "report.xlsx"
    
    results = engine.run_ioc_analysis(targets, output_file)

    assert "ips" in results
    assert "urls" in results
    assert results["ips"]["8.8.8.8"]["abuseipdb"]["data"]["abuseConfidenceScore"] == 0
    mock_api_client.check_ip_multi.assert_called_once_with("8.8.8.8")
    mock_api_client.check_url_multi.assert_called_once_with("https://example.com")


def test_run_ioc_analysis_no_targets_raises_error(monkeypatch, tmp_path):
    """Testa se NoValidTargetsError é levantada quando nenhum alvo válido é fornecido."""
    monkeypatch.setattr('threatdeflect.core.report_generator.ReportGenerator.generate_excel', lambda self, path: None)
    
    targets = "\n# Apenas comentários e linhas vazias\n"
    output_file = tmp_path / "report.xlsx"
    
    with pytest.raises(NoValidTargetsError, match="Nenhum alvo válido"):
        engine.run_ioc_analysis(targets, output_file)


def test_run_file_analysis_success(monkeypatch, tmp_path, mock_api_responses):
    """Testa o fluxo de sucesso da análise de arquivos."""
    mock_file = tmp_path / "testfile.txt"
    mock_file.write_text("dummy content")
    
    mock_api_client = MagicMock()
    mock_api_client.check_file_multi.return_value = mock_api_responses["file_response"]
    
    monkeypatch.setattr('threatdeflect.core.engine.ApiClient', lambda: mock_api_client)
    monkeypatch.setattr('threatdeflect.core.engine.calculate_sha256', lambda path: "dummy_hash")
    monkeypatch.setattr('threatdeflect.core.report_generator.ReportGenerator.generate_excel', lambda self, path: None)

    results = engine.run_file_analysis([str(mock_file)], tmp_path / "report.xlsx")

    assert "files" in results
    assert "dummy_hash" in results["files"]
    assert results["files"]["dummy_hash"]["malwarebazaar"]["data"][0]["signature"] == "Cerber"
    mock_api_client.check_file_multi.assert_called_once_with("dummy_hash")

def test_run_file_analysis_no_valid_files_raises_error(monkeypatch, tmp_path):
    """Testa se a exceção correta é levantada quando nenhum hash pode ser gerado."""
    monkeypatch.setattr('threatdeflect.core.engine.calculate_sha256', lambda path: None)
    
    with pytest.raises(NoValidTargetsError):
        engine.run_file_analysis(["nonexistent_file.txt"], tmp_path / "report.xlsx")


@pytest.fixture
def mock_cache_manager(monkeypatch):
    mock_cache = MagicMock()
    mock_cache.get_cached_results.return_value = {}
    monkeypatch.setattr('threatdeflect.core.engine.CacheManager', lambda url: mock_cache)
    return mock_cache

@pytest.fixture
def mock_repo_analyzer(monkeypatch):
    mock_analyzer_instance = MagicMock()
    mock_analyzer_instance.run_analysis.return_value = (
        {"url": "mock_url", "findings": [{"severity": "HIGH", "description": "mock finding"}]},
        {"mock_file.py": {"hash": "abc", "findings": []}}
    )
    monkeypatch.setattr('threatdeflect.core.engine.RepositoryAnalyzer', lambda *args, **kwargs: mock_analyzer_instance)
    return mock_analyzer_instance

def test_run_repo_analysis_success(monkeypatch, tmp_path, mock_cache_manager, mock_repo_analyzer):
    """Testa o fluxo de sucesso da análise de repositórios."""
    monkeypatch.setattr('threatdeflect.core.report_generator.ReportGenerator.generate_excel', lambda self, path: None)
    monkeypatch.setattr('threatdeflect.core.engine.build_triage_prompt', lambda *a, **k: "")
    monkeypatch.setattr('threatdeflect.api.api_client.ApiClient.get_ai_summary', lambda *a, **k: "")
    
    repo_urls = ["https://github.com/user/repo"]
    output_file = tmp_path / "report.xlsx"

    results = engine.run_repo_analysis(repo_urls, output_file)

    assert "repositories" in results
    assert len(results["repositories"]) == 1
    assert results["repositories"][0]["findings"][0]["description"] == "mock finding"
    mock_cache_manager.get_cached_results.assert_called_once()
    mock_repo_analyzer.run_analysis.assert_called_once()
    mock_cache_manager.update_cache.assert_called_once()



def test_run_repo_analysis_cancellation(monkeypatch, tmp_path):
    """Verifica se a análise de repositório é interrompida quando o callback levanta a exceção."""
    def mock_progress_interrupt(current, total):
        raise InterruptedException("Cancelado pelo teste")

    monkeypatch.setattr('threatdeflect.core.engine.ApiClient', MagicMock())
    
    with pytest.raises(InterruptedException):
        engine.run_repo_analysis(["http://github.com/repo"], tmp_path / "report.xlsx", progress_callback=mock_progress_interrupt)

@patch('threatdeflect.core.engine.ApiClient')
@patch('threatdeflect.core.engine.build_dossier_prompt', return_value="Test Prompt")
def test_get_ai_summary_calls_status_callback(mock_prompt, MockApiClient):
    """Verifica se o status_callback é chamado para notificar a UI sobre a análise de IA."""
    mock_api_instance = MockApiClient.return_value
    mock_api_instance.get_local_models.return_value = ["test-model"]
    mock_api_instance.get_ai_summary.return_value = "Resumo da IA"
    
    mock_status_callback = MagicMock()
    
    engine.get_ai_summary(
        analysis_data={"ips": {"1.1.1.1": {}}}, 
        model="test-model",
        status_callback=mock_status_callback
    )
    
    mock_status_callback.assert_called_once()
    
    assert len(mock_status_callback.call_args[0]) == 2
    assert isinstance(mock_status_callback.call_args[0][0], str)
