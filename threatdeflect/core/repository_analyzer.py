import json
import logging
import os
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Callable, Optional, List, Tuple

from threatdeflect.api.api_client import ApiClient
from threatdeflect.utils.utils import resource_path

try:
    from threatdeflect_rs import RustAnalyzer
except ImportError:
    logging.critical("Falha ao importar threatdeflect_rs. Certifique-se de que o módulo Rust foi compilado.")
    raise

class RepositoryAnalyzer:
    MAX_IOC_CHECKS = 50  # Máximo de URLs únicas para checar no VirusTotal
    MAX_AI_CHECKS = 20   # Máximo de itens para a IA julgar

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
        
        self.candidates_for_ai_validation: List[Dict[str, Any]] = []
        
        self.rust_analyzer = None

        self._load_config_from_yaml()

    def _load_config_from_yaml(self) -> None:
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

            rules_map = {}
            suspicious_map = {}

            for rule in config.get('rules', []):
                rule_id = rule.get('id')
                pattern = rule.get('pattern')
                if not rule_id or not pattern:
                    continue
                
                if "command" in rule_id.lower() or "execution" in rule_id.lower():
                    suspicious_map[rule_id] = pattern
                else:
                    rules_map[rule_id] = pattern

            self.rust_analyzer = RustAnalyzer(rules_map, suspicious_map)
        
        except Exception as e:
            logging.error(f"FALHA CRÍTICA: Erro ao configurar analisador: {e}", exc_info=True)
            raise ValueError("Falha na inicialização da configuração ou do motor Rust.") from e

    def _update_status(self, message: str) -> None:
        if self.status_callback:
            self.status_callback(message)

    def _add_finding(self, description: str, file_path: str, finding_type: str, severity: str = None) -> None:
        final_severity = severity or self.severity_map.get(finding_type, "LOW")
        finding = {"severity": final_severity, "description": description, "file": file_path, "type": finding_type}
        
        is_duplicate = any(
            f["type"] == finding_type and f["file"] == file_path and f["description"] == description 
            for f in self.results["findings"]
        )
        
        if not is_duplicate:
            self.results["findings"].append(finding)

    def _process_file_content(self, content: str, file_info: Dict[str, Any]) -> Tuple[List[Dict], List[Dict], Dict]:
        file_path = file_info.get('path', 'N/A')
        file_name = file_info.get('name', '')
        
        try:
            rust_findings, rust_iocs = self.rust_analyzer.process_file_content(content, file_path, file_name)
        except Exception as e:
            logging.error(f"Erro no motor Rust ao processar {file_path}: {e}")
            return [], [], {}

        local_findings = []
        
        validation_targets = {
            "Generic API Key", 
            "Suspicious Command", 
            "High Entropy String", 
            "Password in URL", 
            "Sensitive File",
            "Suspicious JS Keyword"
        }

        for f in rust_findings:
            f_type = f["type"]
            
            if "match_content" in f:
                match_content = f.pop("match_content")
                if f_type in validation_targets:
                    f["match_content"] = match_content
                    self.candidates_for_ai_validation.append(f)
                    continue 

            f["severity"] = self.severity_map.get(f_type, "LOW")
            local_findings.append(f)

        local_iocs = rust_iocs
        local_deps = {}

        if file_name in self.dependency_files:
            deps = []
            try:
                if file_name == 'package.json':
                    data = json.loads(content)
                    deps.extend(data.get('dependencies', {}).keys())
                    deps.extend(data.get('devDependencies', {}).keys())
                    for script in ['preinstall', 'postinstall', 'prepare']:
                        if script in data.get('scripts', {}):
                            severity = self.severity_map.get("NPM Dangerous Hook", "CRITICAL")
                            local_findings.append({
                                "severity": severity,
                                "description": f"Hook de NPM perigoso ('{script}')",
                                "file": file_path,
                                "type": "NPM Dangerous Hook"
                            })
                elif file_name == 'requirements.txt':
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split('==')[0].split('>=')[0].split('<=')[0].split('>')[0].split('<')[0]
                            pkg = parts.strip()
                            if pkg:
                                deps.append(pkg)
                
                if deps:
                    local_deps[file_name] = deps
            except Exception as e:
                logging.warning(f"Não foi possível analisar dependências de {file_path}: {e}")

        return local_findings, local_iocs, local_deps

    def _analyze_dependencies(self) -> None:
        if not self.results.get("dependencies"): return
        
        ecosystem_map = {'package.json': 'npm', 'requirements.txt': 'PyPI'}
        all_deps = [{'pkg': p, 'eco': eco, 'file': f} for f, pkgs in self.results["dependencies"].items() if (eco := ecosystem_map.get(os.path.basename(f))) for p in pkgs]
        
        if not all_deps: return
        self._update_status(f"Analisando vulnerabilidades em {len(all_deps)} dependências...")
        
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
        all_extracted = self.results.get("extracted_iocs", [])
        if not all_extracted:
            return

        unique_urls = list({item['ioc'] for item in all_extracted if "reputation" not in item})
        total_unique = len(unique_urls)
        
        if total_unique == 0:
            return

        urls_to_check = unique_urls
        limit_reached = False
        
        if total_unique > self.MAX_IOC_CHECKS:
            limit_reached = True
            urls_to_check = unique_urls[:self.MAX_IOC_CHECKS]
            self._add_finding(
                f"Limite de IOCs atingido ({total_unique}). Analisando amostra de {self.MAX_IOC_CHECKS} para performance.",
                "Sistema",
                "Performance Limit",
                severity="MEDIUM"
            )
            self._update_status(f"Muitos IOCs ({total_unique}). Verificando amostra de {self.MAX_IOC_CHECKS}...")
        else:
            self._update_status(f"Verificando reputação de {total_unique} IOCs únicos...")
        
        url_reputation_map = {}
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(self.api_client.check_url, url): url for url in urls_to_check}
            
            completed = 0
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    url_reputation_map[url] = {"virustotal": result}
                except Exception as exc:
                    logging.error(f"Erro ao verificar IOC {url}: {exc}")
                    url_reputation_map[url] = {"virustotal": {"error": "Falha na verificação"}}
                
                completed += 1
                if completed % 5 == 0:
                    self._update_status(f"Verificando IOCs: {completed}/{len(urls_to_check)}...")

        for item in all_extracted:
            ioc_url = item.get('ioc')
            if ioc_url in url_reputation_map:
                item['reputation'] = url_reputation_map[ioc_url]
            elif limit_reached and ioc_url not in url_reputation_map:
                item['reputation'] = {"virustotal": {"error": "Ignorado (Limite de Performance)"}}

    def _validate_findings_with_ai(self) -> None:
        if not self.candidates_for_ai_validation: return
        
        total_candidates = len(self.candidates_for_ai_validation)
        items_to_analyze = self.candidates_for_ai_validation
        limit_reached = False

        if total_candidates > self.MAX_AI_CHECKS:
            limit_reached = True
            items_to_analyze = self.candidates_for_ai_validation[:self.MAX_AI_CHECKS]
            
            self._add_finding(
                f"Limite de IA atingido. {total_candidates - self.MAX_AI_CHECKS} itens requerem revisão manual.", 
                "Sistema", 
                "Performance Limit", 
                severity="MEDIUM"
            )
            
            for item in self.candidates_for_ai_validation[self.MAX_AI_CHECKS:]:
                original_type = item["type"]
                original_desc = item["description"]
                
                fallback_severity = "MEDIUM"
                if "Key" in original_type or "Token" in original_type or "Secret" in original_type:
                    fallback_severity = "HIGH"
                
                self._add_finding(
                    f"[CHECAGEM MANUAL] {original_desc}", 
                    item["file"], 
                    f"⚠️ UNVERIFIED ({original_type})", 
                    severity=fallback_severity
                )

        available_models = self.api_client.get_local_models()
        model_name = available_models[0] if available_models and "erro" not in available_models[0].lower() else None
        
        if not model_name:
            for finding in items_to_analyze:
                self._add_finding(finding["description"], finding["file"], finding["type"], severity="LOW")
            return

        msg_status = f"IA: Julgando {len(items_to_analyze)} casos"
        if limit_reached:
            msg_status += f" (Amostra de {total_candidates})"
        msg_status += f" com {model_name}..."
        
        self._update_status(msg_status)

        def validate_single(finding):
            snippet = finding.get("match_content", "")
            f_type = finding["type"]
            f_file = finding["file"]
            
            prompt = (
                f"Analise este trecho de código do arquivo '{f_file}'. O sistema detectou como '{f_type}'.\n"
                f"Trecho: `{snippet}`\n\n"
                "Pergunta: Isso representa um risco de segurança REAL (credencial vazada, comando malicioso) ou é um FALSO POSITIVO (exemplo, teste, placeholder, hash legítimo)?\n"
                "Responda APENAS com uma palavra: 'REAL' ou 'FALSO'."
            )
            
            try:
                response = self.api_client.get_ai_judge_response(model_name, prompt).upper()
                return finding, response
            except Exception:
                return finding, "FALHA"

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(validate_single, f) for f in items_to_analyze]
            
            completed = 0
            for future in as_completed(futures):
                try:
                    original_finding, verdict = future.result()
                    completed += 1
                    if completed % 5 == 0:
                         self._update_status(f"IA: Processando {completed}/{len(items_to_analyze)}...")

                    if "REAL" in verdict:
                        severity = "HIGH" if "Key" in original_finding["type"] or "Token" in original_finding["type"] else "MEDIUM"
                        self._add_finding(
                            f"[IA Confirmou] {original_finding['description']}", 
                            original_finding["file"], 
                            original_finding["type"],
                            severity=severity
                        )
                    elif "FALSO" in verdict:
                        logging.info(f"IA descartou falso positivo em {original_finding['file']}: {original_finding['type']}")
                    else:
                        self._add_finding(
                            f"[IA Inconclusiva] {original_finding['description']}", 
                            original_finding["file"], 
                            f"⚠️ UNVERIFIED ({original_finding['type']})", 
                            severity="MEDIUM"
                        )
                        
                except Exception as e:
                    logging.error(f"Erro na validação IA: {e}")
                    f = items_to_analyze[0]
                    self._add_finding(f["description"], f["file"], f["type"], severity="LOW")

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
            files_to_inspect = []
            for file_info in files_to_analyze:
                fname = file_info.get('name', '').lower()
                fpath = file_info.get('path', '')
                
                if any(ignored in fpath for ignored in self.ignore_dirs):
                    continue
                if fname in self.ignore_files:
                    continue

                if fname in self.sensitive_filenames:
                    self.candidates_for_ai_validation.append({
                        "description": f"Arquivo sensível detectado: {fname}",
                        "file": fpath,
                        "type": "Sensitive File",
                        "match_content": f"Filename: {fname}"
                    })

                if any(fname.endswith(ext) for ext in self.interesting_extensions) or fname in self.dependency_files:
                    files_to_inspect.append(file_info)
            
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
                        logging.error(f"Erro processando {item.get('path')}: {exc}")

        self._analyze_dependencies()
        self._check_extracted_iocs_reputation()
        self._validate_findings_with_ai()

        self._update_status("Finalizando análise...")
        for file, deps_list in self.results["dependencies"].items():
            self.results["dependencies"][file] = sorted(list(set(deps_list)))

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.results["findings"].sort(key=lambda x: severity_order.get(x["severity"], 99))
        
        score_map = {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 10}
        if self.results["findings"]:
            self.results["risk_score"] = max([score_map.get(f["severity"], 0) for f in self.results["findings"]])
        else:
            self.results["risk_score"] = 0
        
        return self.results, current_repo_state