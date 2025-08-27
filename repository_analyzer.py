
# ThreatSpy
# Copyright (C) 2025  Jackson Greick <seczeror.ocelot245@passmail.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import base64
import json
import logging
import math
import os
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Callable, Optional, List, Set

from api_client import ApiClient

# Constantes de Configuração
IGNORE_DIR_PATTERNS: List[str] = ['/node_modules/', '/dist/', '/build/', '/__tests__/', '/test/', '/tests/', '/docs/']
IGNORE_FILE_PATTERNS: List[str] = [
    '.lock', '.min.js', '.spec.js', '.test.js', '.png', '.jpg', '.jpeg', '.gif',
    '.svg', '.ico', '.webp', '.mp4', '.mov', '.avi', '.pdf', '.zip', '.tar.gz',
    '.rar', '.woff', '.woff2', '.eot', '.ttf', '.otf'
]
INTERESTING_EXTENSIONS: Set[str] = {
    '.js', '.ts', '.py', '.json', '.yml', '.yaml', '.sh', '.bash', '.config',
    '.conf', '.properties', '.toml', '.xml', '.pem', '.key', '.tf', '.tfvars',
    'Dockerfile'
}
SEVERITY_MAP: Dict[str, str] = {
    "Malicious Dependency": "CRITICAL", "Private Key": "CRITICAL",
    "High Entropy String": "CRITICAL", "Suspicious JS Keyword": "HIGH",
    "GitHub Token": "CRITICAL", "GitLab PAT": "CRITICAL", "AWS Key": "HIGH",
    "NPM Dangerous Hook": "HIGH", "Remote Script Execution": "HIGH",
    "Generic API Key": "MEDIUM", "Suspicious Command": "MEDIUM",
    "Hidden IOC (Base64)": "MEDIUM", "Sensitive File": "MEDIUM",
    "PowerShell Encoded": "MEDIUM"
}
SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "AWS Key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "GitHub Token": re.compile(r'(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}'),
    "GitLab PAT": re.compile(r'glpat-[0-9a-zA-Z\-\_]{20}'),
    "Generic API Key": re.compile(r'[aA][pP][iI]_?[kK][eE][yY].*[\'|"][0-9a-zA-Z]{32,}[\'|"]'),
    "Private Key": re.compile(r'-----BEGIN ((EC|RSA|OPENSSH) )?PRIVATE KEY-----'),
}
SUSPICIOUS_COMMAND_PATTERNS: Dict[str, tuple] = {
    "NPM Force Install": ("Suspicious Command", re.compile(r'npm\s+(install|i)\s+--force')),
    "Remote Script Execution (curl | sh)": ("Remote Script Execution", re.compile(r'curl\s+[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)\s*\|\s*(bash|sh)')),
    "PowerShell Encoded Command": ("PowerShell Encoded", re.compile(r'powershell\s+(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{20,}', re.IGNORECASE)),
    "Invoke-Expression (IEX)": ("Suspicious Command", re.compile(r'iex\s*\(', re.IGNORECASE))
}
SUSPICIOUS_JS_KEYWORDS: List[str] = [
    'eth_sendTransaction', 'personal_sign', 'wallet_requestPermissions',
    '_sendTransaction', 'estimateGas', 'transferFrom', 'sendSignedTransaction',
    'drain', 'atob', 'eval'
]
BASE64_PATTERN: re.Pattern = re.compile(r'[^A-Za-z0-9+/]([A-Za-z0-9+/]{32,}=*)[^A-Za-z0-9+/]')
LONG_STRING_PATTERN: re.Pattern = re.compile(r'["\']([a-zA-Z0-9+/=,.\-_]{50,})["\']')
SUSPICIOUS_FILENAMES: List[str] = [
    '.env', '.env.local', '.env.development', '.env.production', '.envrc',
    'credentials', 'credentials.json', 'credentials.yml', 'config.json',
    'config.yml', 'settings.xml', 'database.yml', 'id_rsa', 'private.key',
    'server.key', '.pem', '.npmrc', '.pypirc', '.git-credentials', '.boto',
    'terraform.tfstate', '.bash_history', '.zsh_history'
]
DEPENDENCY_FILES: List[str] = ['package.json']


def _decode_safe_base64(s: str) -> Optional[bytes]:
    """Tenta decodificar uma string Base64, adicionando padding se necessário."""
    try:
        return base64.b64decode(s)
    except (base64.binascii.Error, ValueError):
        try:
            padding = len(s) % 4
            if padding != 0:
                s += '=' * (4 - padding)
            return base64.b64decode(s, validate=True)
        except (base64.binascii.Error, ValueError):
            return None


class RepositoryAnalyzer:
    def __init__(self, repo_url: str, api_client: ApiClient, status_callback: Optional[Callable[[str], None]] = None) -> None:
        self.repo_url = repo_url
        self.api_client = api_client
        self.results: Dict[str, Any] = {"url": repo_url, "risk_score": 0, "findings": [], "dependencies": {}, "extracted_iocs": []}
        self.status_callback = status_callback

    def _update_status(self, message: str) -> None:
        if self.status_callback:
            self.status_callback(message)

    def _analyze_dependencies(self) -> None:
        npm_deps = self.results.get("dependencies", {}).get("package.json", [])
        if not npm_deps:
            return

        self._update_status(f"Analisando {len(npm_deps)} dependências...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_pkg = {executor.submit(self.api_client.check_package_vulnerability, pkg, "npm"): pkg for pkg in npm_deps}
            for future in as_completed(future_to_pkg):
                package_name = future_to_pkg[future]
                try:
                    if vulns := future.result():
                        vuln_ids = ", ".join([v.get('id', 'N/A') for v in vulns])
                        self._add_finding(f"Dependência vulnerável: '{package_name}' (OSV IDs: {vuln_ids})", "package.json", "Malicious Dependency")
                except Exception as exc:
                    logging.error(f"Erro ao analisar a dependência {package_name}: {exc}")

    def _add_finding(self, description: str, file_path: str, finding_type: str) -> None:
        severity = SEVERITY_MAP.get(finding_type, "LOW")
        finding = {"severity": severity, "description": description, "file": file_path}
        if finding not in self.results["findings"]:
            self.results["findings"].append(finding)

    def _calculate_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        p, lns = Counter(s), float(len(s))
        return -sum(count / lns * math.log(count / lns, 2) for count in p.values())

    def _find_malicious_js_patterns(self, content: str, file_path: str) -> None:
        for keyword in SUSPICIOUS_JS_KEYWORDS:
            if keyword in content:
                self._add_finding(f"Palavra-chave suspeita '{keyword}' encontrada", file_path, "Suspicious JS Keyword")
        for match in LONG_STRING_PATTERN.finditer(content):
            long_string = match.group(1)
            entropy = self._calculate_entropy(long_string)
            if entropy > 4.5:
                self._add_finding(f"String de alta entropia ({entropy:.2f}) detectada", file_path, "High Entropy String")

    def _find_suspicious_files(self, file_list: List[Dict[str, Any]]) -> None:
        for file_info in file_list:
            if file_info.get('name', '').lower() in SUSPICIOUS_FILENAMES:
                self._add_finding(f"Arquivo sensível encontrado: {file_info['name']}", file_info['path'], "Sensitive File")

    def _find_exposed_secrets(self, content: str, file_path: str) -> None:
        for key_type, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                self._add_finding(f"Possível segredo '{key_type}' exposto", file_path, key_type)

    def _find_suspicious_commands(self, content: str, file_path: str) -> None:
        for description, (finding_type, pattern) in SUSPICIOUS_COMMAND_PATTERNS.items():
            if pattern.search(content):
                self._add_finding(f"Comando suspeito: '{description}'", file_path, finding_type)

    def _find_and_decode_base64(self, content: str, file_path: str) -> None:
        url_pattern = re.compile(r'https?://[^\s/$.?#].[^\s]*|www\.[^\s/$.?#].[^\s]*')
        for match in BASE64_PATTERN.finditer(content):
            b64_string = match.group(1)
            if decoded_bytes := _decode_safe_base64(b64_string):
                try:
                    decoded_content = decoded_bytes.decode('utf-8', errors='ignore')
                    for url_match in url_pattern.finditer(decoded_content):
                        ioc_url = url_match.group(0)
                        self._add_finding(f"URL ofuscada em Base64: {ioc_url[:50]}...", file_path, "Hidden IOC (Base64)")
                        self.results["extracted_iocs"].append({"ioc": ioc_url, "source_file": file_path, "reputation": {}})
                except UnicodeDecodeError:
                    continue

    def _analyze_npm_scripts(self, content: str, file_path: str) -> None:
        try:
            data = json.loads(content)
            for script_name in ['preinstall', 'postinstall', 'prepare']:
                if script_name in data.get('scripts', {}):
                    self._add_finding(f"Hook de NPM perigoso ('{script_name}')", file_path, "NPM Dangerous Hook")
        except json.JSONDecodeError:
            logging.warning(f"Não foi possível analisar o JSON de {file_path}")

    def _parse_dependencies(self, content: str, file_path: str) -> None:
        file_name = os.path.basename(file_path)
        try:
            if file_name == 'package.json':
                data = json.loads(content)
                deps = list(data.get('dependencies', {}).keys()) + list(data.get('devDependencies', {}).keys())
                if deps:
                    self.results["dependencies"].setdefault(file_name, []).extend(deps)
                self._analyze_npm_scripts(content, file_path)
        except Exception as e:
            logging.warning(f"Não foi possível analisar dependências de {file_path}: {e}")

    def _calculate_risk_score(self) -> int:
        if not self.results["findings"]:
            return 0
        severities = {finding["severity"] for finding in self.results["findings"]}
        if "CRITICAL" in severities: return 95
        if "HIGH" in severities: return 75
        if "MEDIUM" in severities: return 50
        return 25

    def _filter_files_for_inspection(self, all_repo_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filtra a lista de arquivos de um repositório para inspecionar apenas os relevantes."""
        files_to_inspect = []
        for file_info in all_repo_files:
            file_path = file_info.get('path', '')
            file_name = file_info.get('name', '')
            
            if any(dir_p in f'/{file_path}/' for dir_p in IGNORE_DIR_PATTERNS) or \
               any(file_name.endswith(file_p) for file_p in IGNORE_FILE_PATTERNS):
                continue
            
            _, extension = os.path.splitext(file_name)
            if (file_name.lower() in SUSPICIOUS_FILENAMES) or \
               (extension.lower() in INTERESTING_EXTENSIONS) or \
               (file_name in DEPENDENCY_FILES):
                files_to_inspect.append(file_info)
        return files_to_inspect
    
    def run_analysis(self) -> Dict[str, Any]:
        repo_name = os.path.basename(self.repo_url)
        self._update_status(f"Iniciando: {repo_name}")
        
        all_repo_files = self.api_client.list_repository_files(self.repo_url)
        if isinstance(all_repo_files, dict) and 'error' in all_repo_files:
            self._add_finding(f"Erro de API: {all_repo_files.get('error')}", self.repo_url, "CRITICAL")
            self.results["risk_score"] = 100
            return self.results
        if not all_repo_files:
            self._add_finding("Repositório vazio ou inacessível", self.repo_url, "LOW")
            return self.results
            
        self._find_suspicious_files(all_repo_files)
        
        self._update_status(f"Encontrados {len(all_repo_files)} arquivos. Filtrando...")
        files_to_inspect_content = self._filter_files_for_inspection(all_repo_files)

        self._update_status(f"Analisando conteúdo de {len(files_to_inspect_content)} arquivos...")
        logging.info(f"Total de arquivos: {len(all_repo_files)}. Para análise de conteúdo: {len(files_to_inspect_content)}")

        for item in files_to_inspect_content:
            file_name = item.get('name', '')
            file_path = item.get('path', 'N/A')
            if not (content := self.api_client.get_repository_file_content(item)):
                continue
            
            if file_name.endswith(('.js', '.ts')): self._find_malicious_js_patterns(content, file_path)
            if file_name in DEPENDENCY_FILES: self._parse_dependencies(content, file_path)
            
            self._find_exposed_secrets(content, file_path)
            self._find_suspicious_commands(content, file_path)
            self._find_and_decode_base64(content, file_path)

        self._analyze_dependencies()

        self._update_status("Finalizando análise...")
        for file, deps_list in self.results["dependencies"].items():
            self.results["dependencies"][file] = sorted(list(set(deps_list)))
            
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.results["findings"].sort(key=lambda x: severity_order.get(x["severity"], 99))
        self.results["risk_score"] = self._calculate_risk_score()
        return self.results
