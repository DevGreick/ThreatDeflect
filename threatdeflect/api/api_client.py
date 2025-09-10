# threatdeflect/api/api_client.py

import configparser
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse, quote_plus
from typing import Optional, Dict, Any, List

import keyring
import requests
import urllib3

from threatdeflect.utils.utils import get_config_path, safe_get

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        self.session.headers.update({"User-Agent": "ThreatDeflect/2.0"})

    def _read_config(self, section: str, key: str) -> Optional[str]:
        try:
            config = configparser.ConfigParser()
            config_path = get_config_path()
            config.read(config_path)
            return config.get(section, key, fallback=None)
        except Exception as e:
            logging.error(f"Erro ao ler o arquivo de configuração {get_config_path()}: {e}")
            return None

    def _make_request(self, method: str, url: str, max_retries: int = 3, **kwargs: Any) -> Optional[Dict[str, Any]]:
        retries = 0
        backoff_factor = 2
        while retries < max_retries:
            try:
                response = self.session.request(method, url, timeout=20, **kwargs)
                if response.status_code == 404:
                    logging.info(f"Recurso não encontrado (404): {url}")
                    return {"error": "Not Found"}
                response.raise_for_status()
                return response.json() if response.content else {}
            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code if e.response else 500
                if status_code in RETRYABLE_STATUS_CODES:
                    wait_time = (backoff_factor ** retries)
                    logging.warning(f"Erro de API ({status_code}) em '{url}'. Aguardando {wait_time}s para tentar novamente...")
                    time.sleep(wait_time)
                    retries += 1
                else:
                    logging.error(f"Erro de Cliente HTTP não recuperável ({status_code}) em '{url}': {e}")
                    return {"error": f"Client Error {status_code}"}
            except requests.exceptions.RequestException as e:
                logging.warning(f"Erro de requisição em '{url}': {e}. Tentando novamente...")
                time.sleep((backoff_factor ** retries))
                retries += 1
        
        logging.error(f"Máximo de tentativas atingido para a URL: {url}")
        return None

    def check_package_vulnerability(self, package_name: str, ecosystem: str) -> Optional[List[Dict[str, Any]]]:
        try:
            api_url = "https://api.osv.dev/v1/query"
            payload = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
                }
            }
            response = self.session.post(api_url, json=payload, timeout=15)
            if response.status_code == 200 and response.content:
                data = response.json()
                return data.get('vulns')
            return None
        except requests.RequestException as e:
            logging.error(f"Erro ao consultar API OSV para o pacote {package_name}: {e}")
            return None

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.vt_api_key: return None
        return self._make_request('GET', f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": self.vt_api_key})

    def check_url(self, url_to_check: str) -> Optional[Dict[str, Any]]:
        if not self.vt_api_key: return None
        headers = {"x-apikey": self.vt_api_key}
        post_response = self._make_request('POST', "https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url_to_check})
        if not (analysis_id := safe_get(post_response, 'data.id')): return None
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(10):
            if (report := self._make_request('GET', analysis_url, headers=headers)) and safe_get(report, 'data.attributes.status') == 'completed':
                return report
            time.sleep(15)
        logging.warning(f"Análise da URL {url_to_check} não completou a tempo.")
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
        return self._make_request('GET', f"https://api.shodan.io/shodan/host/{ip}", params={'key': self.shodan_api_key})

    def check_ip_multi(self, ip: str) -> Dict[str, Any]:
        return {'virustotal': self.check_ip(ip), 'abuseipdb': self.check_ip_abuseipdb(ip), 'shodan': self.check_ip_shodan(ip)}

    def check_url_multi(self, url: str) -> Dict[str, Any]:
        return {'virustotal': self.check_url(url), 'urlhaus': self.check_url_urlhaus(url)}

    def check_file_multi(self, file_hash: str) -> Dict[str, Any]:
        return {'virustotal': self.check_file(file_hash), 'malwarebazaar': self.check_hash_malwarebazaar(file_hash)}

    def _get_vt_usage(self) -> Dict[str, Any]:
        if not self.vt_api_key: return {"error": "Chave não configurada"}
        url = f"https://www.virustotal.com/api/v3/users/{self.vt_api_key.split('-')[0]}"
        headers = {"x-apikey": self.vt_api_key}
        data = self._make_request('GET', url, headers=headers)
        if data and 'data' in data:
            daily_used = safe_get(data, 'data.attributes.quotas.api_requests_daily.used', 0)
            daily_allowed = safe_get(data, 'data.attributes.quotas.api_requests_daily.allowed', 0)
            return {"daily_used": daily_used, "daily_allowed": daily_allowed}
        return {"error": "Falha ao buscar dados"}

    def _get_shodan_usage(self) -> Dict[str, Any]:
        if not self.shodan_api_key: return {"error": "Chave não configurada"}
        url = f"https://api.shodan.io/api-info?key={self.shodan_api_key}"
        data = self._make_request('GET', url)
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
        
    def _get_platform_from_url(self, repo_url: str) -> Optional[str]:
        if hostname := urlparse(repo_url).hostname:
            if 'github.com' in hostname: return 'github'
            if 'gitlab.com' in hostname: return 'gitlab'
        return None

    def _get_gitlab_project_details(self, project_path: str, gitlab_host: str) -> Optional[Dict[str, Any]]:
        url = f"https://{gitlab_host}/api/v4/projects/{quote_plus(project_path)}"
        headers = {"PRIVATE-TOKEN": self.gitlab_api_key} if self.gitlab_api_key else {}
        project_data = self._make_request('GET', url, headers=headers)
        if not project_data or 'id' not in project_data:
            logging.error(f"Não foi possível encontrar os detalhes do projeto GitLab para: {project_path}")
            return None
        return project_data

    def list_repository_files(self, repo_url: str) -> List[Dict[str, Any]] | Dict[str, str]:
        platform = self._get_platform_from_url(repo_url)
        parsed_url = urlparse(repo_url)
        path_parts = parsed_url.path.strip('/').split('/')
        headers = {}
        
        if platform == 'github':
            if len(path_parts) < 2: return {"error": "URL do GitHub inválida"}
            owner, repo = path_parts[0], path_parts[1]
            if self.github_api_key: headers["Authorization"] = f"token {self.github_api_key}"

            subdirectory_path = ""
            if len(path_parts) > 3 and path_parts[2] == 'tree':
                subdirectory_path = "/".join(path_parts[4:])

            all_files = []
            
            def get_content_recursively(path: str):
                api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
                contents = self._make_request('GET', api_url, headers=headers)
                
                if not contents or isinstance(contents, dict) and 'error' in contents:
                    logging.warning(f"Não foi possível buscar o conteúdo de '{path}'.")
                    return []
                
                if isinstance(contents, dict):
                    contents = [contents]

                for item in contents:
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
                        get_content_recursively(item.get('path'))

            get_content_recursively(subdirectory_path)
            return all_files

        elif platform == 'gitlab':
            base_repo_path = "/".join(path_parts[:2])
            if self.gitlab_api_key: headers["PRIVATE-TOKEN"] = self.gitlab_api_key
            
            project_details = self._get_gitlab_project_details(base_repo_path, parsed_url.hostname)
            if not project_details: return {"error": "Projeto GitLab não encontrado ou inacessível."}
            
            project_id = project_details.get('id')
            default_branch = project_details.get('default_branch')
            if not default_branch: return {"error": "Não foi possível determinar a branch principal."}

            api_url = f"https://{parsed_url.hostname}/api/v4/projects/{project_id}/repository/tree"
            all_files, page = [], 1
            while True:
                params = {'recursive': True, 'per_page': 100, 'page': page}
                if not (files := self._make_request('GET', api_url, headers=headers, params=params)): break
                
                all_files.extend([{
                    'name': f.get('name'),
                    'path': f.get('path'),
                    'sha': f.get('id'),
                    'type': 'file', 
                    'platform': 'gitlab', 
                    'project_id': project_id, 
                    'default_branch': default_branch
                } for f in files if f.get('type') == 'blob'])
                if len(files) < 100: break
                page += 1
            return all_files
            
        return {"error": "Plataforma não suportada"}

    def get_repository_file_content(self, file_info: Dict[str, Any]) -> Optional[str]:
        platform = file_info.get('platform')
        try:
            if platform == 'github':
                headers = {"Accept": "application/vnd.github.v3.raw"}
                if self.github_api_key: headers["Authorization"] = f"token {self.github_api_key}"
                response = self.session.get(file_info['item_url'], headers=headers, timeout=20)
            elif platform == 'gitlab':
                branch = file_info.get('default_branch', 'main')
                api_url = f"https://gitlab.com/api/v4/projects/{file_info['project_id']}/repository/files/{quote_plus(file_info['path'])}/raw?ref={branch}"
                headers = {"PRIVATE-TOKEN": self.gitlab_api_key} if self.gitlab_api_key else {}
                response = self.session.get(api_url, headers=headers, timeout=20)
            else:
                return None
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            logging.error(f"Não foi possível obter o conteúdo do arquivo {file_info.get('path')}: {e}")
            return None

    def get_local_models(self) -> List[str]:
        if not self.ai_endpoint: return ["Erro: Endpoint não configurado"]
        try:
            base_url = "/".join(self.ai_endpoint.split('/')[:3])
            response = self.session.get(f"{base_url}/api/tags", timeout=5)
            response.raise_for_status()
            models = response.json().get("models", [])
            return [model['name'] for model in models] or ["Nenhum modelo local encontrado"]
        except requests.exceptions.ConnectionError:
            return ["Ollama não encontrado (Verifique Endpoint)"]
        except Exception as e:
            logging.error(f"Erro ao buscar modelos de IA: {e}")
            return ["Erro ao buscar modelos"]

    def get_ai_summary(self, model: str, prompt: str) -> str:
        if not self.ai_endpoint or not model:
            raise ValueError("Endpoint ou modelo da IA inválido/não selecionado.")
        try:
            payload = {"model": model, "prompt": prompt, "stream": False}
            response = self.session.post(self.ai_endpoint, json=payload, timeout=600)
            response.raise_for_status()
            return response.json().get("response", "").strip()
        except requests.exceptions.ConnectionError as e:
            logging.error(f"Erro de Conexão com Ollama: {e}", exc_info=True)
            return f"Erro de Conexão: Não foi possível conectar ao Ollama em {self.ai_endpoint}."
        except requests.exceptions.ReadTimeout:
            logging.error("Timeout ao contatar a IA após 600 segundos.")
            return "Falha ao contatar a IA: Timeout. O modelo demorou mais de 10 minutos para responder."
        except Exception as e:
            logging.error(f"Falha genérica ao contatar a IA: {e}", exc_info=True)
            return f"Falha ao contatar a IA. Veja threatdeflect.log para detalhes."
    
    def get_ai_judge_response(self, model: str, prompt: str) -> str:
        """Envia um prompt para a IA para uma análise de 'juiz' (mais curta e focada)."""
        if not self.ai_endpoint or not model:
            raise ValueError("Endpoint ou modelo da IA inválido/não selecionado.")
        try:
            payload = {"model": model, "prompt": prompt, "stream": False}
            response = self.session.post(self.ai_endpoint, json=payload, timeout=120)
            response.raise_for_status()
            return response.json().get("response", "").strip()
        except requests.exceptions.ReadTimeout:
            logging.error("Timeout (120s) ao esperar resposta do juiz de IA.")
            return "FALHA: Timeout do Juiz de IA."
        except Exception as e:
            logging.error(f"Falha ao contatar o juiz de IA: {e}", exc_info=True)
            return f"FALHA: Erro ao contatar Juiz de IA."

    def get_latest_release_info(self) -> Dict[str, Any]:
        """Busca as informações do último release do repositório oficial."""
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