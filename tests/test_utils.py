# ===================================================================
# Módulo de Testes de Utilitários (test_utils.py)
# ===================================================================
# tests/test_utils.py

import pytest
from threatdeflect.utils.utils import defang_ioc, parse_targets, parse_repo_urls, safe_get, detect_visual_spoofing

# Testes para a função defang_ioc
@pytest.mark.parametrize("input_ioc, expected_output", [
    ("http://google.com", "hxxp://google[.]com"),
    ("https://example.com/path?q=1", "hxxps://example[.]com/path?q=1"),
    ("8.8.8.8", "8[.]8[.]8[.]8"),
    ("ftp://malicious.net", "ftp://malicious[.]net"),
    ("sem_protocolo.com", "sem_protocolo[.]com"),
    ("https://www.xn--80ak6aa92e.com", "hxxps://www.xn--80ak6aa92e.com"),
    ("", ""),
])
def test_defang_ioc(input_ioc, expected_output):
    """Testa a função de 'defang' com vários tipos de IOCs."""
    assert defang_ioc(input_ioc) == expected_output

@pytest.mark.parametrize("input_text, expected_result", [
    ("https://www.xn--80ak6aa92e.com", "Punycode/Cyrillic"),
    ("esto no es cirílico", None),
    ("пример.com", "Punycode/Cyrillic"),
    ("google.com", None),
    ("file_gpj‮exe", "RTLO"), # Exemplo de RTLO
    ("", None),
    (None, None)
])
def test_detect_visual_spoofing(input_text, expected_result):
    """Testa a detecção de Punycode, Cirílico e RTLO."""
    assert detect_visual_spoofing(input_text) == expected_result


class TestParsingFunctions:
    """Grupo de testes para funções de parsing de texto."""

    def test_parse_targets(self):
        """Testa a extração de IPs e URLs de um bloco de texto."""
        input_text = """
        # IPs Válidos
        8.8.8.8
        1.1.1.1
        
        # URLs Válidas
        google.com
        https://sub.domain.co.uk/path
        
        # Inválidos
        isso nao e um ip
        127.0.0.1.1
        """
        ips, urls = parse_targets(input_text)
        
        assert sorted(ips) == ["1.1.1.1", "8.8.8.8"]
        # ===================================================================
        # ALTERAÇÃO: O teste agora espera 'https://' como prefixo padrão
        # ===================================================================
        assert sorted(urls) == ["https://google.com", "https://sub.domain.co.uk/path"]

    def test_parse_repo_urls(self):
        """Testa a extração de URLs de repositório."""
        input_text = """
        https://github.com/owner/repo1
        gitlab.com/owner/repo2.git
        owner/repo3 # Shorthand para GitHub

        # Duplicado
        https://github.com/owner/repo1

        # Inválido
        not-a-repo
        """
        valid, invalid, duplicates = parse_repo_urls(input_text)
        
        assert sorted(valid) == [
            "https://github.com/owner/repo1",
            "https://github.com/owner/repo3",
            "https://gitlab.com/owner/repo2",
        ]
        assert invalid == ["not-a-repo"]
        assert duplicates == ["https://github.com/owner/repo1"]


class TestSafeGetData:
    """Grupo de testes para a função utilitária safe_get."""

    @pytest.fixture
    def nested_dict(self):
        """Fornece um dicionário aninhado como um 'fixture' para os testes."""
        return {
            "data": {
                "attributes": {
                    "stats": {
                        "malicious": 5,
                        "harmless": 60
                    },
                    "tags": ["phishing", "malware"]
                }
            },
            "error": None
        }

    def test_safe_get_success(self, nested_dict):
        """Testa caminhos válidos na extração de dados."""
        assert safe_get(nested_dict, "data.attributes.stats.malicious") == 5
        assert safe_get(nested_dict, "data.attributes.tags") == ["phishing", "malware"]

    def test_safe_get_failure(self, nested_dict):
        """Testa caminhos inválidos e o valor padrão."""
        assert safe_get(nested_dict, "data.attributes.nonexistent.key") is None
        assert safe_get(nested_dict, "data.attributes.nonexistent.key", default="fallback") == "fallback"
        assert safe_get(None, "data.path", default="fallback") == "fallback"