# ===================================================================
# Módulo de Testes do Analisador de Repositório
# ===================================================================
import pytest
from unittest.mock import MagicMock
from threatdeflect.core.repository_analyzer import RepositoryAnalyzer

@pytest.fixture
def mock_api_client():
    """Cria um mock simples do ApiClient para não fazer chamadas reais."""
    return MagicMock()

def test_finds_aws_key_in_file_content(mock_api_client):
    """
    Testa se o analisador consegue encontrar uma chave da AWS
    dentro do conteúdo de um arquivo.
    """
    # 1. Prepara os dados de entrada
    repo_url = "https://github.com/test/repo"
    # Simula o conteúdo de um arquivo que será analisado
    file_content = "const accessKeyId = 'AKIAIOSFODNN7EXAMPLE';"
    # Simula a informação do arquivo como viria da API
    file_info = {'path': 'src/config.js', 'name': 'config.js'}

    # 2. Cria a instância do analisador
    analyzer = RepositoryAnalyzer(repo_url, mock_api_client)

    # 3. Executa o método que queremos testar
    findings, iocs, deps = analyzer._process_file_content(file_content, file_info)

    # 4. Verifica o resultado
    assert len(findings) == 1
    assert findings[0]["type"] == "AWS Key"
    assert findings[0]["description"] == "Possível segredo 'AWS Key' exposto"
    assert findings[0]["file"] == "src/config.js"