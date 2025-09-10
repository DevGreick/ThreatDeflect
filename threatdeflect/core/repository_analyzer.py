# ===================================================================
# Módulo de Análise de Repositórios (repository_analyzer.py)
# ===================================================================
# ThreatDeflect
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
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Callable, Optional, List, Tuple

import yaml
import requests

from threatdeflect.api.api_client import ApiClient
from threatdeflect.utils.utils import resource_path

BASE64_PATTERN: re.Pattern = re.compile(r'\b([A-Za-z0-9+/=_-]{20,})\b')
LONG_STRING_PATTERN: re.Pattern = re.compile(r'["\']([a-zA-Z0-9+/=,.\-_]{50,})["\']')

def _decode_safe_base64(s: str) -> Optional[bytes]:
    """Tenta decodificar uma string base64, adicionando padding e tratando erros."""
    s = re.sub(r'[^A-Za-z0-9+/=]', '', s)
    try:
        padding = len(s) % 4
        if padding != 0:
            s += '=' * (4 - padding)
        return base64.b64decode(s, validate=True)
    except (base64.binascii.Error, ValueError):
        return None


class RepositoryAnalyzer:
    """Analisa um repositório Git em busca de segredos, vulnerabilidades e outros riscos."""

    def __init__(self, repo_url: str, api_client: ApiClient,
                 status_callback: Optional[Callable[[str], None]] = None,
                 cached_data: Optional[Dict[str, Any]] = None):
        self.repo_url = repo_url
        self.api_client = api_client
        self.results: Dict[str, Any] = {"url": repo_url, "risk_score": 0, "findings": [], "dependencies": {}, "extracted_iocs": []}
        self.status_callback = status_callback
        self.cached_data = cached_data or {}
        
        self.ignore_dirs: List[str] = []
        self.ignore_files: List[str] = []
        self.interesting_extensions: List[str] = []
        self.sensitive_filenames: List[str] = []
        self.dependency_files: List[str] = []
        self.severity_map: Dict[str, str] = {}
        self.secret_patterns: Dict[str, re.Pattern] = {}
        self.suspicious_command_patterns: Dict[str, re.Pattern] = {}

        self.findings_for_ai_validation: List[Tuple[Dict[str, Any], str]] = []
        self.commands_for_ai_validation: List[Tuple[Dict[str, Any], str]] = []

        self._load_config_from_yaml()

    def _load_config_from_yaml(self) -> None:
        """Carrega toda a configuração de análise a partir do arquivo rules.yaml."""
        try:
            rules_path = resource_path('rules.yaml')
            with open(rules_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            self.ignore_dirs = config.get('ignore_patterns', {}).get('directories', [])
            self.ignore_files = config.get('ignore_patterns', {}).get('files', [])
            self.interesting_extensions = config.get('file_scan_targets', {}).get('interesting_extensions', [])
            self.sensitive_filenames = config.get('file_scan_targets', {}).get('sensitive_filenames', [])
            self.dependency_files = config.get('file_scan_targets', {}).get('dependency_files', [])
            self.severity_map = config.get('severity_map', {})

            for rule in config.get('rules', []):
                rule_id, pattern_str = rule.get('id'), rule.get('pattern')
                if not (rule_id and pattern_str): continue
                try:
                    compiled_pattern = re.compile(pattern_str)
                    if "command" in rule_id.lower() or "execution" in rule_id.lower():
                        self.suspicious_command_patterns[rule_id] = compiled_pattern
                    else:
                        self.secret_patterns[rule_id] = compiled_pattern
                except re.error as e:
                    logging.warning(f"Erro ao compilar regex para a regra '{rule_id}': {e}")
        
        except (FileNotFoundError, yaml.YAMLError) as e:
            logging.error(f"FALHA CRÍTICA: Não foi possível carregar 'rules.yaml': {e}", exc_info=True)
            raise ValueError("Arquivo de regras 'rules.yaml' não encontrado ou inválido.") from e

    def _update_status(self, message: str) -> None:
        if self.status_callback:
            self.status_callback(message)

    def _add_finding(self, description: str, file_path: str, finding_type: str) -> None:
        severity = self.severity_map.get(finding_type, "LOW")
        finding = {"severity": severity, "description": description, "file": file_path, "type": finding_type}
        if finding not in self.results["findings"]:
            self.results["findings"].append(finding)

    def _calculate_entropy(self, s: str) -> float:
        if not s: return 0.0
        p, lns = Counter(s), float(len(s))
        return -sum(count / lns * math.log(count / lns, 2) for count in p.values())

    def _process_file_content(self, content: str, file_info: Dict[str, Any]) -> Tuple[List[Dict], List[Dict], Dict]:
        file_path = file_info.get('path', 'N/A')
        file_name = file_info.get('name', '')
        
        local_findings: List[Dict] = []
        local_iocs: List[Dict] = []
        local_deps: Dict = {}
        
        def add_local_finding(description: str, finding_type: str) -> None:
            severity = self.severity_map.get(finding_type, "LOW")
            finding = {"severity": severity, "description": description, "file": file_path, "type": finding_type}
            if finding not in local_findings:
                local_findings.append(finding)

        if file_name.endswith(('.js', '.ts')):
            for keyword in {'eval', 'document.write', 'innerHTML', 'unescape', 'crypto.subtle'}:
                if keyword in content: add_local_finding(f"Palavra-chave suspeita '{keyword}'", "Suspicious JS Keyword")
            for match in LONG_STRING_PATTERN.finditer(content):
                entropy = self._calculate_entropy(match.group(1))
                if entropy > 4.5: add_local_finding(f"String de alta entropia ({entropy:.2f})", "High Entropy String")
        
        if file_name in self.dependency_files:
            deps = []
            try:
                if file_name == 'package.json':
                    data = json.loads(content)
                    deps.extend(data.get('dependencies', {}).keys()); deps.extend(data.get('devDependencies', {}).keys())
                    for script in ['preinstall', 'postinstall', 'prepare']:
                        if script in data.get('scripts', {}): add_local_finding(f"Hook de NPM perigoso ('{script}')", "NPM Dangerous Hook")
                elif file_name == 'requirements.txt':
                    deps.extend(m.group(0) for l in content.splitlines() if l.strip() and not l.strip().startswith('#') and (m := re.match(r'^[a-zA-Z0-9\-_]+', l.strip())))
                if deps: local_deps[file_name] = deps
            except (json.JSONDecodeError, ET.ParseError) as e:
                logging.warning(f"Não foi possível analisar dependências de {file_path}: {e}")

        for key_type, pattern in self.secret_patterns.items():
            for match in pattern.finditer(content):
                if key_type == "Generic API Key":
                    self.findings_for_ai_validation.append(
                        ({"description": "Possível chave de API.", "file": file_path, "type": key_type}, match.group(0))
                    )
                else: add_local_finding(f"Possível segredo '{key_type}' exposto", key_type)

        for desc, pattern in self.suspicious_command_patterns.items():
            for match in pattern.finditer(content):
                self.commands_for_ai_validation.append(
                    ({"description": f"Comando suspeito: '{desc}'", "file": file_path, "type": "Suspicious Command"}, match.group(0))
                )

        # ===================================================================
        # Lógica de Extração de IOCs Refatorada para Maior Robustez
        # ===================================================================
        url_pattern = re.compile(r'https?://[^\s"\'<>]+')
        
        # 1. Busca IOCs em strings Base64
        for match in BASE64_PATTERN.finditer(content):
            if decoded_bytes := _decode_safe_base64(match.group(1)):
                try:
                    # Usa 'ignore' para evitar que caracteres inválidos quebrem a decodificação
                    decoded_content = decoded_bytes.decode('utf-8', errors='ignore')
                    for url_match in url_pattern.finditer(decoded_content):
                        ioc_url = url_match.group(0)
                        add_local_finding(f"URL ofuscada em Base64: {ioc_url[:50]}...", "Hidden IOC (Base64)")
                        local_iocs.append({"ioc": ioc_url, "source_file": file_path})
                except Exception: continue
        
        # 2. Busca IOCs em texto plano, evitando duplicatas da busca em Base64
        existing_iocs = {ioc['ioc'] for ioc in local_iocs}
        for url_match in url_pattern.finditer(content):
            ioc_url = url_match.group(0)
            if ioc_url not in existing_iocs:
                local_iocs.append({"ioc": ioc_url, "source_file": file_path})
                existing_iocs.add(ioc_url)

        return local_findings, local_iocs, local_deps

    def _analyze_dependencies(self) -> None:
        """Verifica as dependências coletadas contra bancos de dados de vulnerabilidades."""
        if not self.results.get("dependencies"): return
        
        ecosystem_map = {'package.json': 'npm', 'requirements.txt': 'PyPI'}
        all_deps = [{'pkg': p, 'eco': eco, 'file': f} for f, pkgs in self.results["dependencies"].items() if (eco := ecosystem_map.get(os.path.basename(f))) for p in pkgs]
        
        if not all_deps: return
        self._update_status(f"Analisando {len(all_deps)} dependências...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_dep = {executor.submit(self.api_client.check_package_vulnerability, d['pkg'], d['eco']): d for d in all_deps}
            for future in as_completed(future_to_dep):
                dep_info = future_to_dep[future]
                try:
                    if vulns := future.result():
                        ids = ", ".join([v.get('id', 'N/A') for v in vulns])
                        self._add_finding(f"Dependência vulnerável: '{dep_info['pkg']}' (IDs: {ids})", dep_info['file'], "Malicious Dependency")
                except Exception as exc:
                    logging.error(f"Erro ao analisar dependência {dep_info['pkg']}: {exc}")

    def _check_extracted_iocs_reputation(self) -> None:
        """Verifica a reputação de IOCs extraídos dos arquivos."""
        iocs_to_check = [ioc for ioc in self.results.get("extracted_iocs", []) if "reputation" not in ioc]
        if not iocs_to_check: return

        self._update_status(f"Verificando reputação de {len(iocs_to_check)} IOCs extraídos...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_ioc = {executor.submit(self.api_client.check_url, ioc['ioc']): ioc for ioc in iocs_to_check}
            for future in as_completed(future_to_ioc):
                ioc = future_to_ioc[future]
                try: ioc['reputation'] = {"virustotal": future.result()}
                except Exception as exc:
                    logging.error(f"Erro ao verificar IOC {ioc['ioc']}: {exc}")
                    ioc['reputation'] = {"virustotal": {"error": "Falha na verificação"}}

    def _validate_findings_with_ai(self) -> None:
        """Usa um modelo de IA para validar se achados genéricos são segredos reais."""
        if not self.findings_for_ai_validation: return
        
        self._update_status(f"Validando {len(self.findings_for_ai_validation)} achados com IA...")
        available_models = self.api_client.get_local_models()
        model_name = available_models[0] if available_models and "erro" not in available_models[0].lower() else None
        
        if not model_name:
            logging.warning("Nenhum modelo de IA válido. Pulando validação de IA.")
            for finding, _ in self.findings_for_ai_validation:
                self._add_finding(finding["description"], finding["file"], finding["type"])
            return

        for finding, code_snippet in self.findings_for_ai_validation:
            prompt = f"Você é um analista de segurança. A linha de código a seguir contém uma chave de API real ou é apenas um exemplo/placeholder? Responda com 'SEGREDO REAL' ou 'PLACEHOLDER' e justifique. Código: `{code_snippet}`"
            response = self.api_client.get_ai_judge_response(model_name, prompt)
            if "SEGREDO REAL" in response:
                self._add_finding(f"[Validado por IA] Chave de API confirmada.", finding["file"], "Validated Generic API Key")

    def run_analysis(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        self._update_status(f"Iniciando: {os.path.basename(self.repo_url)}")
        all_repo_files = self.api_client.list_repository_files(self.repo_url)
        if isinstance(all_repo_files, dict) and 'error' in all_repo_files:
            self._add_finding(f"Erro de API: {all_repo_files.get('error')}", self.repo_url, "CRITICAL"); self.results["risk_score"] = 100
            return self.results, {}
        if not all_repo_files:
            self._add_finding("Repositório vazio ou inacessível", self.repo_url, "LOW"); return self.results, {}

        current_repo_state: Dict[str, Dict] = {}
        files_to_analyze = []
        self._update_status(f"Comparando {len(all_repo_files)} arquivos com o cache...")
        for file_info in all_repo_files:
            path, content_hash = file_info['path'], file_info.get('sha')
            cached_file = self.cached_data.get(path)
            current_repo_state[path] = {'hash': content_hash, 'data': {'findings': [], 'extracted_iocs': [], 'dependencies': {}}}
            if cached_file and cached_file.get('hash') == content_hash:
                cached_data = cached_file.get('data', {})
                self.results['findings'].extend(cached_data.get('findings', []))
                self.results['extracted_iocs'].extend(cached_data.get('extracted_iocs', []))
                for dep_file, pkgs in cached_data.get('dependencies', {}).items():
                    self.results['dependencies'].setdefault(dep_file, []).extend(pkgs)
                current_repo_state[path]['data'] = cached_data
            else:
                files_to_analyze.append(file_info)

        self._update_status(f"{len(all_repo_files) - len(files_to_analyze)} em cache. Analisando {len(files_to_analyze)} novos/modificados.")
        if files_to_analyze:
            for file_info in files_to_analyze:
                if file_info.get('name', '').lower() in self.sensitive_filenames:
                    self._add_finding(f"Arquivo sensível: {file_info['name']}", file_info['path'], "Sensitive File")
            
            files_to_inspect = [f for f in files_to_analyze if any(f.get('name', '').endswith(ext) for ext in self.interesting_extensions) or f.get('name', '') in self.dependency_files or f.get('name', '') in self.sensitive_filenames]            
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_file = {executor.submit(self.api_client.get_repository_file_content, item): item for item in files_to_inspect}
                for future in as_completed(future_to_file):
                    item = future_to_file[future]
                    try:
                        content = future.result()
                        if not content: continue
                        file_findings, file_iocs, file_deps = self._process_file_content(content, item)
                        if file_findings:
                            self.results['findings'].extend(file_findings)
                            current_repo_state[item['path']]['data']['findings'] = file_findings
                        if file_iocs:
                            self.results['extracted_iocs'].extend(file_iocs)
                            current_repo_state[item['path']]['data']['extracted_iocs'] = file_iocs
                        if file_deps:
                            for dep_file, pkgs in file_deps.items():
                                self.results['dependencies'].setdefault(dep_file, []).extend(pkgs)
                            current_repo_state[item['path']]['data']['dependencies'] = file_deps
                    except Exception as exc:
                        logging.error(f"Erro ao processar conteúdo do arquivo {item.get('path')}: {exc}", exc_info=True)

        self._analyze_dependencies()
        self._check_extracted_iocs_reputation()
        self._validate_findings_with_ai()

        self._update_status("Finalizando análise...")
        for file, deps_list in self.results["dependencies"].items():
            self.results["dependencies"][file] = sorted(list(set(deps_list)))

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.results["findings"].sort(key=lambda x: severity_order.get(x["severity"], 99))
        
        score_map = {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 25}
        self.results["risk_score"] = max([score_map.get(f["severity"], 0) for f in self.results["findings"]], default=0)
        
        return self.results, current_repo_state