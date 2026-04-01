import configparser
import ipaddress
import logging
import base64
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse, quote_plus
from typing import Optional, Dict, Any, List

import keyring
import requests

from threatdeflect.utils.utils import get_config_path, safe_get

# SSL warning suppression removed: verify=True is the default (and desired),
# so there should be no InsecureRequestWarning in normal operation.

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

class ApiClient:
    def __init__(self) -> None:
        self.vt_api_key: Optional[str] = keyring.get_password("vtotalscan", "virustotal_api_key")
        self.abuseipdb_api_key: Optional[str] = keyring.get_password("vtotalscan", "abuseipdb_api_key")
        self.urlhaus_api_key: Optional[str] = keyring.get_password("vtotalscan", "urlhaus_api_key")
        self.shodan_api_key: Optional[str] = keyring.get_password("vtotalscan", "shodan_api_key")
        self.mb_api_key: Optional[str] = keyring.get_password("vtotalscan", "malwarebazaar_api_key")
        self.github_api_key: Optional[str] = keyring.get_password("vtotalscan", "github_api_key")
        self.gitlab_api_key: Optional[str] = keyring.get_password("vtotalscan", "gitlab_api_key")
        self.ai_endpoint: Optional[str] = self._read_config('AI', 'endpoint')

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": f"ThreatDeflect/{self._get_version()}"})

    @staticmethod
    def _get_version() -> str:
        try:
            from importlib.metadata import version, PackageNotFoundError
            return version("threatdeflect")
        except PackageNotFoundError:
            return "3.0.0"

    def _read_config(self, section: str, key: str) -> Optional[str]:
        try:
            config = configparser.ConfigParser()
            config_path = get_config_path()
            config.read(config_path)
            return config.get(section, key, fallback=None)
        except (configparser.Error, OSError) as e:
            logging.error(f"Erro ao ler config: {e}")
            return None

    @staticmethod
    def _redact_url(url: str) -> str:
        return urlparse(url)._replace(query="", fragment="").geturl()

    def _make_request(self, method: str, url: str, max_retries: int = 3, **kwargs: Any) -> Optional[Dict[str, Any]]:
        retries = 0
        backoff_factor = 2
        safe_url = self._redact_url(url)
        while retries < max_retries:
            try:
                response = self.session.request(method, url, timeout=20, **kwargs)
                if response.status_code == 404:
                    return {"error": "Not Found", "data": {"attributes": {"stats": {"malicious": 0}}}}
                response.raise_for_status()
                if not response.content:
                    return {}
                content_type = response.headers.get('Content-Type', '')
                if 'json' not in content_type and 'javascript' not in content_type:
                    logging.warning("Unexpected Content-Type from %s: %s", safe_url, content_type)
                return response.json()
            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code if e.response else 500
                if status_code in RETRYABLE_STATUS_CODES:
                    wait_time = (backoff_factor ** retries)
                    time.sleep(wait_time)
                    retries += 1
                else:
                    logging.warning("Client error %s from %s", status_code, safe_url)
                    return {"error": f"Client Error {status_code}"}
            except requests.exceptions.RequestException as e:
                logging.debug("Request error on %s (attempt %d): %s", safe_url, retries + 1, type(e).__name__)
                time.sleep((backoff_factor ** retries))
                retries += 1
        logging.warning("Request to %s failed after %d retries.", safe_url, max_retries)
        return None

    def check_package_vulnerability(self, package_name: str, ecosystem: str, version: str = "") -> Optional[List[Dict[str, Any]]]:
        try:
            api_url = "https://api.osv.dev/v1/query"
            payload: Dict[str, Any] = {"package": {"name": package_name, "ecosystem": ecosystem}}
            if version:
                payload["version"] = version
            response = self.session.post(api_url, json=payload, timeout=10)
            if response.status_code == 200 and response.content:
                return response.json().get('vulns')
            return None
        except (requests.exceptions.RequestException, ValueError, KeyError):
            return None

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.vt_api_key: return None
        return self._make_request('GET', f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": self.vt_api_key})

    def check_url(self, url_to_check: str) -> Optional[Dict[str, Any]]:
        if not self.vt_api_key: return None
        
        try:
            url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            headers = {"x-apikey": self.vt_api_key}
            report = self._make_request('GET', api_url, headers=headers)
            
            if report and report.get('error') == 'Not Found':
                return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}, "last_analysis_results": {}}}}
                
            return report
        except (requests.exceptions.RequestException, ValueError, KeyError) as e:
            logging.error(f"Erro URL ID: {e}")
            return None

    def check_file(self, file_hash: str) -> Optional[Dict[str, Any]]:
        if not self.vt_api_key: return None
        return self._make_request('GET', f"https://www.virustotal.com/api/v3/files/{file_hash}", headers={"x-apikey": self.vt_api_key})

    def check_url_urlhaus(self, url_to_check: str) -> Optional[Dict[str, Any]]:
        if not self.urlhaus_api_key: return None
        headers = {'Auth-Key': self.urlhaus_api_key}
        data = {'url': url_to_check}
        return self._make_request('POST', 'https://urlhaus-api.abuse.ch/v1/url/', headers=headers, data=data)

    def check_hash_malwarebazaar(self, file_hash: str) -> Optional[Dict[str, Any]]:
        if not self.mb_api_key: return None
        headers = {'Auth-Key': self.mb_api_key}
        data = {'query': 'get_info', 'hash': file_hash}
        return self._make_request('POST', "https://mb-api.abuse.ch/api/v1/", headers=headers, data=data)

    def check_ip_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.abuseipdb_api_key: return None
        return self._make_request('GET', 'https://api.abuseipdb.com/api/v2/check', headers={'Accept': 'application/json', 'Key': self.abuseipdb_api_key}, params={'ipAddress': ip, 'maxAgeInDays': '90'})

    def check_ip_shodan(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.shodan_api_key: return None
        # NOTE: Shodan API only supports key-based auth via query string parameter.
        # Ensure logging does not capture full request URLs to avoid leaking the API key.
        return self._make_request('GET', f"https://api.shodan.io/shodan/host/{ip}", params={'key': self.shodan_api_key})

    def check_ip_multi(self, ip: str) -> Dict[str, Any]:
        return {'virustotal': self.check_ip(ip), 'abuseipdb': self.check_ip_abuseipdb(ip), 'shodan': self.check_ip_shodan(ip)}

    def check_url_multi(self, url: str) -> Dict[str, Any]:
        return {'virustotal': self.check_url(url), 'urlhaus': self.check_url_urlhaus(url)}

    def check_file_multi(self, file_hash: str) -> Dict[str, Any]:
        return {'virustotal': self.check_file(file_hash), 'malwarebazaar': self.check_hash_malwarebazaar(file_hash)}

    def get_api_usage_stats(self) -> Dict[str, Any]:
        stats = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_vt = executor.submit(self._get_vt_usage)
            future_shodan = executor.submit(self._get_shodan_usage)
            future_github = executor.submit(self._get_github_usage)
            
            stats['virustotal'] = future_vt.result()
            stats['shodan'] = future_shodan.result()
            stats['github'] = future_github.result()
        return stats

    def _get_vt_usage(self) -> Dict[str, Any]:
        if not self.vt_api_key: return {"error": "Chave não configurada"}
        url = "https://www.virustotal.com/api/v3/users/me"
        headers = {"x-apikey": self.vt_api_key}
        data = self._make_request('GET', url, headers=headers)
        if data and 'data' in data:
            daily_used = safe_get(data, 'data.attributes.quotas.api_requests_daily.used', 0)
            daily_allowed = safe_get(data, 'data.attributes.quotas.api_requests_daily.allowed', 0)
            return {"daily_used": daily_used, "daily_allowed": daily_allowed}
        return {"error": "Falha ao buscar dados"}

    def _get_shodan_usage(self) -> Dict[str, Any]:
        if not self.shodan_api_key: return {"error": "Chave não configurada"}
        url = "https://api.shodan.io/api-info"
        data = self._make_request('GET', url, params={'key': self.shodan_api_key})
        if data and 'query_credits' in data:
            return {"remaining": data.get('query_credits', 0), "allowed": data.get('usage_limits', {}).get('query_credits', 0)}
        return {"error": "Falha ao buscar dados"}

    def _get_github_usage(self) -> Dict[str, Any]:
        if not self.github_api_key: return {"error": "Chave não configurada"}
        url = "https://api.github.com/rate_limit"
        headers = {"Authorization": f"token {self.github_api_key}"}
        data = self._make_request('GET', url, headers=headers)
        if core_limit := safe_get(data, 'resources.core'):
            resets_at_str = "N/A"
            if reset_timestamp := core_limit.get('reset'):
                resets_at_str = datetime.fromtimestamp(reset_timestamp).strftime('%H:%M:%S')
            return {
                "limit": core_limit.get('limit', 0),
                "remaining": core_limit.get('remaining', 0),
                "resets_at": resets_at_str
            }
        return {"error": "Falha ao buscar dados do GitHub"}

    def check_github_rate_limit(self) -> Dict[str, Any]:
        headers = {}
        if self.github_api_key:
            headers["Authorization"] = f"token {self.github_api_key}"
        data = self._make_request('GET', "https://api.github.com/rate_limit", headers=headers)
        if data and 'resources' in data:
            core = data['resources'].get('core', {})
            return {
                "remaining": core.get('remaining', 0),
                "limit": core.get('limit', 0),
                "reset": core.get('reset', 0),
            }
        return {"remaining": 0, "limit": 0, "reset": 0}

    def _list_github_files_via_trees(self, owner: str, repo: str, ref: str, headers: Dict[str, str]) -> Optional[List[Dict[str, Any]]]:
        repo_info = self._make_request('GET', f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
        if not repo_info or isinstance(repo_info, dict) and 'error' in repo_info:
            return None

        if not ref:
            ref = repo_info.get('default_branch', 'main')

        ref_data = self._make_request('GET', f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{ref}", headers=headers)
        if not ref_data or isinstance(ref_data, dict) and 'error' in ref_data:
            return None

        tree_sha = safe_get(ref_data, 'object.sha')
        if not tree_sha:
            return None

        tree_data = self._make_request('GET', f"https://api.github.com/repos/{owner}/{repo}/git/trees/{tree_sha}", headers=headers, params={"recursive": "1"})
        if not tree_data or isinstance(tree_data, dict) and 'error' in tree_data:
            return None

        if tree_data.get('truncated', False):
            logging.warning("Git Trees API retornou resultado truncado para %s/%s. Usando fallback.", owner, repo)
            return None

        MAX_FILES = 5000
        all_files: List[Dict[str, Any]] = []
        for item in tree_data.get('tree', []):
            if len(all_files) >= MAX_FILES:
                break
            if item.get('type') != 'blob':
                continue
            path = item.get('path', '')
            name = path.rsplit('/', 1)[-1] if '/' in path else path
            all_files.append({
                'name': name,
                'path': path,
                'sha': item.get('sha'),
                'type': 'file',
                'platform': 'github',
                'item_url': f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            })
        return all_files

    def _list_github_files_via_contents(self, owner: str, repo: str, ref: str, subdirectory: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        MAX_FILES = 5000
        MAX_DEPTH = 20
        all_files: List[Dict[str, Any]] = []
        params: Dict[str, str] = {}
        if ref:
            params["ref"] = ref

        def get_content_recursively(path: str, depth: int = 0) -> None:
            if depth > MAX_DEPTH or len(all_files) >= MAX_FILES:
                return
            api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
            contents = self._make_request('GET', api_url, headers=headers, params=params)

            if not contents or isinstance(contents, dict) and 'error' in contents:
                return
            if isinstance(contents, dict):
                contents = [contents]

            for item in contents:
                if len(all_files) >= MAX_FILES:
                    return
                if item.get('type') == 'file':
                    all_files.append({
                        'name': item.get('name'),
                        'path': item.get('path'),
                        'sha': item.get('sha'),
                        'type': 'file',
                        'platform': 'github',
                        'item_url': item.get('url')
                    })
                elif item.get('type') == 'dir':
                    get_content_recursively(item.get('path'), depth + 1)

        get_content_recursively(subdirectory)
        return all_files

    def list_repository_files(self, repo_url: str) -> List[Dict[str, Any]] | Dict[str, str]:
        platform = self._get_platform_from_url(repo_url)
        parsed_url = urlparse(repo_url)
        path_parts = parsed_url.path.strip('/').split('/')
        headers = {}

        if platform == 'github':
            if len(path_parts) < 2: return {"error": "URL do GitHub inválida"}
            owner, repo = path_parts[0], path_parts[1]
            if self.github_api_key: headers["Authorization"] = f"token {self.github_api_key}"

            ref = ""
            subdirectory_path = ""
            if len(path_parts) > 3 and path_parts[2] == 'tree':
                ref = path_parts[3]
                subdirectory_path = "/".join(path_parts[4:])

            if not subdirectory_path:
                tree_result = self._list_github_files_via_trees(owner, repo, ref, headers)
                if tree_result is not None:
                    return tree_result

            return self._list_github_files_via_contents(owner, repo, ref, subdirectory_path, headers)
            
        elif platform == 'gitlab':
            base_repo_path = "/".join(path_parts[:2])
            if self.gitlab_api_key: headers["PRIVATE-TOKEN"] = self.gitlab_api_key
            
            project_details = self._get_gitlab_project_details(base_repo_path, parsed_url.hostname)
            if not project_details: return {"error": "Projeto GitLab não encontrado"}
            
            project_id = project_details.get('id')
            default_branch = project_details.get('default_branch')
            if not default_branch: return {"error": "Branch principal não encontrada"}

            api_url = f"https://{parsed_url.hostname}/api/v4/projects/{project_id}/repository/tree"
            MAX_PAGES = 50
            MAX_FILES_GL = 5000
            all_files, page = [], 1
            while page <= MAX_PAGES and len(all_files) < MAX_FILES_GL:
                params = {'recursive': True, 'per_page': 100, 'page': page}
                if not (files := self._make_request('GET', api_url, headers=headers, params=params)): break

                all_files.extend([{
                    'name': f.get('name'),
                    'path': f.get('path'),
                    'sha': f.get('id'),
                    'type': 'file',
                    'platform': 'gitlab',
                    'project_id': project_id,
                    'default_branch': default_branch,
                    'gitlab_host': parsed_url.hostname,
                } for f in files if f.get('type') == 'blob'])
                if len(files) < 100: break
                page += 1
            return all_files
            
        return {"error": "Plataforma não suportada"}

    def _get_platform_from_url(self, repo_url: str) -> Optional[str]:
        if hostname := urlparse(repo_url).hostname:
            hostname = hostname.lower()
            if hostname == 'github.com' or hostname.endswith('.github.com'):
                return 'github'
            if hostname == 'gitlab.com' or hostname.endswith('.gitlab.com'):
                return 'gitlab'
        return None

    def _get_gitlab_project_details(self, project_path: str, gitlab_host: str) -> Optional[Dict[str, Any]]:
        url = f"https://{gitlab_host}/api/v4/projects/{quote_plus(project_path)}"
        headers = {"PRIVATE-TOKEN": self.gitlab_api_key} if self.gitlab_api_key else {}
        project_data = self._make_request('GET', url, headers=headers)
        if not project_data or 'id' not in project_data:
            return None
        return project_data

    MAX_CONTENT_SIZE: int = 1_048_576

    def get_repository_file_content(self, file_info: Dict[str, Any]) -> Optional[str]:
        platform = file_info.get('platform')
        try:
            if platform == 'github':
                headers = {"Accept": "application/vnd.github.v3.raw"}
                if self.github_api_key: headers["Authorization"] = f"token {self.github_api_key}"
                response = self.session.get(file_info['item_url'], headers=headers, timeout=20, stream=True)
            elif platform == 'gitlab':
                gitlab_host = file_info.get('gitlab_host', 'gitlab.com')
                branch = file_info.get('default_branch', 'main')
                api_url = f"https://{gitlab_host}/api/v4/projects/{file_info['project_id']}/repository/files/{quote_plus(file_info['path'])}/raw?ref={branch}"
                headers = {"PRIVATE-TOKEN": self.gitlab_api_key} if self.gitlab_api_key else {}
                response = self.session.get(api_url, headers=headers, timeout=20, stream=True)
            else:
                return None
            response.raise_for_status()

            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > self.MAX_CONTENT_SIZE:
                response.close()
                return None

            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=8192):
                total += len(chunk)
                if total > self.MAX_CONTENT_SIZE:
                    response.close()
                    return None
                chunks.append(chunk)
            response.close()

            raw = b"".join(chunks)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return raw.decode("utf-8", errors="replace")
        except (requests.exceptions.RequestException, ValueError, KeyError):
            return None

    _ALLOWED_AI_HOSTS = {"localhost", "127.0.0.1", "::1"}
    _ALLOWED_SCHEMES = {"http", "https"}

    def _is_safe_ai_endpoint(self) -> bool:
        if not self.ai_endpoint:
            return False
        parsed = urlparse(self.ai_endpoint)
        if parsed.scheme not in self._ALLOWED_SCHEMES:
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        if hostname not in self._ALLOWED_AI_HOSTS:
            return False
        try:
            resolved = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
            for _, _, _, _, sockaddr in resolved:
                addr = ipaddress.ip_address(sockaddr[0])
                if not addr.is_loopback:
                    logging.warning(f"Endpoint AI resolveu para endereco nao-loopback: {addr}")
                    return False
        except (socket.gaierror, ValueError, OSError) as e:
            logging.error(f"Falha ao resolver endpoint AI: {e}")
            return False
        return True

    def get_local_models(self) -> List[str]:
        if not self.ai_endpoint: return ["Erro: Endpoint não configurado"]
        if not self._is_safe_ai_endpoint(): return ["Erro: Endpoint deve ser localhost"]
        try:
            base_url = "/".join(self.ai_endpoint.split('/')[:3])
            response = self.session.get(f"{base_url}/api/tags", timeout=5)
            return [model['name'] for model in response.json().get("models", [])]
        except (requests.exceptions.RequestException, ValueError, KeyError):
            return ["Ollama não encontrado"]

    def get_ai_summary(self, model: str, prompt: str) -> str:
        if not self.ai_endpoint or not model: return "Erro configuração IA"
        if not self._is_safe_ai_endpoint(): return "Erro: Endpoint deve ser localhost"
        try:
            payload = {"model": model, "prompt": prompt, "stream": False}
            response = self.session.post(self.ai_endpoint, json=payload, timeout=300)
            return response.json().get("response", "").strip()
        except requests.exceptions.Timeout:
            logging.warning("Timeout ao contatar IA para summary")
            return "Erro: Timeout na IA"
        except (requests.exceptions.RequestException, ValueError, KeyError) as e:
            logging.error(f"Falha ao contatar IA: {e}")
            return "Erro ao contatar IA"

    def get_ai_judge_response(self, model: str, prompt: str) -> str:
        if not self.ai_endpoint or not model: return "FALHA"
        if not self._is_safe_ai_endpoint(): return "FALHA"
        try:
            payload = {"model": model, "prompt": prompt, "stream": False}
            response = self.session.post(self.ai_endpoint, json=payload, timeout=60)
            return response.json().get("response", "").strip()
        except requests.exceptions.Timeout:
            logging.warning("Timeout ao contatar IA para judge")
            return "FALHA"
        except (requests.exceptions.RequestException, ValueError, KeyError) as e:
            logging.error(f"Falha no AI judge: {e}")
            return "FALHA"

    def get_latest_release_info(self) -> Dict[str, Any]:
        url = "https://api.github.com/repos/DevGreick/ThreatDeflect/releases/latest"
        release_data = self._make_request('GET', url)
        if release_data and 'name' in release_data and 'body' in release_data:
            return {
                "name": release_data.get("name", "N/A"),
                "tag_name": release_data.get("tag_name", "0.0.0"),
                "body": release_data.get("body", "Não foi possível carregar as notas da versão."),
                "assets": release_data.get("assets", []),
                "url": release_data.get("html_url", "#")
            }
        return {"error": "Falha ao buscar informações de release."}