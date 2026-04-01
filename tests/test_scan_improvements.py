import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from threatdeflect.core.repository_analyzer import RepositoryAnalyzer


@pytest.fixture
def mock_api_client():
    return MagicMock()


@pytest.fixture
def analyzer(mock_api_client):
    return RepositoryAnalyzer("https://github.com/test/repo", mock_api_client)


class TestLockFileDepsNotIgnored:
    def test_lock_file_in_dependency_files_not_ignored(self, analyzer):
        file_content = '{"dependencies": {"lodash": {"version": "4.17.21"}}}'
        file_info = {'path': 'package-lock.json', 'name': 'package-lock.json'}
        _, _, deps = analyzer._process_file_content(file_content, file_info)
        assert 'package-lock.json' in deps
        dep_names = [d['name'] for d in deps['package-lock.json']]
        assert 'lodash' in dep_names

    def test_cargo_lock_parsed_for_deps(self, analyzer):
        file_content = '[[package]]\nname = "serde"\nversion = "1.0.0"\n\n[[package]]\nname = "tokio"\nversion = "1.0.0"'
        file_info = {'path': 'Cargo.lock', 'name': 'Cargo.lock'}
        _, _, deps = analyzer._process_file_content(file_content, file_info)
        assert 'Cargo.lock' in deps
        dep_names = [d['name'] for d in deps['Cargo.lock']]
        assert 'serde' in dep_names
        assert 'tokio' in dep_names


class TestSensitiveFilesScan:
    def test_sensitive_file_scanned_for_secrets(self, analyzer):
        file_content = "AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
        file_info = {'path': '.env', 'name': '.env'}
        findings, _, _ = analyzer._process_file_content(file_content, file_info)
        secret_findings = [f for f in findings if 'AWS' in f.get('type', '')]
        assert len(secret_findings) > 0

    def test_sensitive_filename_generates_ai_candidate(self, analyzer):
        file_info = {'path': 'credentials.json', 'name': 'credentials.json'}
        assert 'credentials.json' in analyzer.sensitive_filenames


class TestPyprojectTomlParser:
    def test_parses_pep621_dependencies(self, analyzer):
        content = '[project]\nname = "myapp"\ndependencies = [\n  "requests>=2.28",\n  "click~=8.0",\n]'
        file_info = {'path': 'pyproject.toml', 'name': 'pyproject.toml'}
        _, _, deps = analyzer._process_file_content(content, file_info)
        assert 'pyproject.toml' in deps
        dep_names = [d['name'] for d in deps['pyproject.toml']]
        assert 'requests' in dep_names
        assert 'click' in dep_names

    def test_parses_poetry_dependencies(self, analyzer):
        content = '[tool.poetry.dependencies]\npython = "^3.10"\nfastapi = "^0.100"\nuvicorn = {version = "^0.23"}\n\n[tool.poetry.dev-dependencies]\npytest = "^7.0"'
        file_info = {'path': 'pyproject.toml', 'name': 'pyproject.toml'}
        _, _, deps = analyzer._process_file_content(content, file_info)
        assert 'pyproject.toml' in deps
        dep_names = [d['name'] for d in deps['pyproject.toml']]
        assert 'fastapi' in dep_names
        assert 'uvicorn' in dep_names
        assert 'pytest' in dep_names
        assert 'python' not in dep_names

    def test_parses_optional_dependencies(self, analyzer):
        content = '[project]\nname = "myapp"\n\n[project.optional-dependencies]\ndev = ["pytest>=7.0", "ruff"]\ndocs = ["mkdocs"]'
        file_info = {'path': 'pyproject.toml', 'name': 'pyproject.toml'}
        _, _, deps = analyzer._process_file_content(content, file_info)
        assert 'pyproject.toml' in deps
        dep_names = [d['name'] for d in deps['pyproject.toml']]
        assert 'pytest' in dep_names
        assert 'ruff' in dep_names
        assert 'mkdocs' in dep_names


class TestGitTreesAPI:
    def test_trees_api_parses_blobs(self):
        mock_client = MagicMock()
        tree_response = {
            'truncated': False,
            'tree': [
                {'path': 'src/main.py', 'type': 'blob', 'sha': 'abc123'},
                {'path': 'src', 'type': 'tree', 'sha': 'def456'},
                {'path': 'README.md', 'type': 'blob', 'sha': 'ghi789'},
            ]
        }
        repo_info = {'default_branch': 'main'}
        ref_data = {'object': {'sha': 'deadbeef'}}

        mock_client._make_request = MagicMock(side_effect=[repo_info, ref_data, tree_response])
        mock_client.session = MagicMock()

        from threatdeflect.api.api_client import ApiClient
        client = ApiClient.__new__(ApiClient)
        client.session = MagicMock()
        client.github_api_key = "test_token"
        client._make_request = MagicMock(side_effect=[repo_info, ref_data, tree_response])

        result = client._list_github_files_via_trees("owner", "repo", "", {"Authorization": "token test"})

        assert result is not None
        assert len(result) == 2
        names = [f['name'] for f in result]
        assert 'main.py' in names
        assert 'README.md' in names
        assert all(f['platform'] == 'github' for f in result)

    def test_trees_api_returns_none_on_truncated(self):
        from threatdeflect.api.api_client import ApiClient
        client = ApiClient.__new__(ApiClient)
        client.session = MagicMock()
        client.github_api_key = "test"

        repo_info = {'default_branch': 'main'}
        ref_data = {'object': {'sha': 'deadbeef'}}
        tree_data = {'truncated': True, 'tree': []}

        client._make_request = MagicMock(side_effect=[repo_info, ref_data, tree_data])
        result = client._list_github_files_via_trees("owner", "repo", "", {})
        assert result is None

    def test_branch_extraction_from_url(self):
        from threatdeflect.api.api_client import ApiClient
        client = ApiClient.__new__(ApiClient)
        client.session = MagicMock()
        client.github_api_key = "test"
        client.gitlab_api_key = None
        client._make_request = MagicMock(return_value={"error": "mock"})
        client._get_platform_from_url = MagicMock(return_value='github')

        result = client.list_repository_files("https://github.com/owner/repo/tree/dev-branch/src")

        calls = client._make_request.call_args_list
        assert len(calls) >= 1


class TestRateLimitCheck:
    def test_rate_limit_returns_data(self):
        from threatdeflect.api.api_client import ApiClient
        client = ApiClient.__new__(ApiClient)
        client.session = MagicMock()
        client.github_api_key = "test"

        client._make_request = MagicMock(return_value={
            'resources': {'core': {'remaining': 4999, 'limit': 5000, 'reset': 1700000000}}
        })
        result = client.check_github_rate_limit()
        assert result['remaining'] == 4999
        assert result['limit'] == 5000

    def test_rate_limit_handles_failure(self):
        from threatdeflect.api.api_client import ApiClient
        client = ApiClient.__new__(ApiClient)
        client.session = MagicMock()
        client.github_api_key = None

        client._make_request = MagicMock(return_value=None)
        result = client.check_github_rate_limit()
        assert result['remaining'] == 0


class TestContentSizeLimit:
    def test_large_file_returns_none(self):
        from threatdeflect.api.api_client import ApiClient
        client = ApiClient.__new__(ApiClient)
        client.session = MagicMock()
        client.github_api_key = "test"

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.headers = {'Content-Length': str(2_000_000)}
        mock_response.close = MagicMock()
        client.session.get = MagicMock(return_value=mock_response)

        result = client.get_repository_file_content({
            'platform': 'github',
            'item_url': 'https://api.github.com/repos/o/r/contents/big.bin'
        })
        assert result is None
        mock_response.close.assert_called()

    def test_normal_file_returns_content(self):
        from threatdeflect.api.api_client import ApiClient
        client = ApiClient.__new__(ApiClient)
        client.session = MagicMock()
        client.github_api_key = "test"

        content_bytes = b"secret = 'test123'"
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.headers = {'Content-Length': str(len(content_bytes))}
        mock_response.iter_content = MagicMock(return_value=[content_bytes])
        mock_response.close = MagicMock()
        client.session.get = MagicMock(return_value=mock_response)

        result = client.get_repository_file_content({
            'platform': 'github',
            'item_url': 'https://api.github.com/repos/o/r/contents/config.py'
        })
        assert result == "secret = 'test123'"


class TestGitLabHostDynamic:
    def test_gitlab_file_uses_correct_host(self):
        from threatdeflect.api.api_client import ApiClient
        client = ApiClient.__new__(ApiClient)
        client.session = MagicMock()
        client.gitlab_api_key = "glpat-test"

        content_bytes = b"data = 1"
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.headers = {'Content-Length': str(len(content_bytes))}
        mock_response.iter_content = MagicMock(return_value=[content_bytes])
        mock_response.close = MagicMock()
        client.session.get = MagicMock(return_value=mock_response)

        result = client.get_repository_file_content({
            'platform': 'gitlab',
            'project_id': 123,
            'path': 'src/main.py',
            'default_branch': 'main',
            'gitlab_host': 'gitlab.mycompany.com',
        })
        assert result == "data = 1"

        call_url = client.session.get.call_args[0][0]
        assert 'gitlab.mycompany.com' in call_url
        assert 'gitlab.com' not in call_url


class TestURLhausIOCCheck:
    def test_ioc_check_calls_urlhaus(self, mock_api_client):
        mock_api_client.check_url.return_value = {"data": {}}
        mock_api_client.check_url_urlhaus.return_value = {"query_status": "no_results"}

        analyzer = RepositoryAnalyzer("https://github.com/test/repo", mock_api_client)
        analyzer.results["extracted_iocs"] = [{"ioc": "http://evil.com/payload"}]

        analyzer._check_extracted_iocs_reputation()

        mock_api_client.check_url_urlhaus.assert_called_once_with("http://evil.com/payload")
