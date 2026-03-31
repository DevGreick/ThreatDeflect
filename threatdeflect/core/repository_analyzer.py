import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Callable, Optional, List, Tuple

import yaml

from threatdeflect.api.api_client import ApiClient
from threatdeflect.core.secret_validator import validate_finding
from threatdeflect.utils.utils import resource_path

try:
    from threatdeflect_rs import RustAnalyzer
except ImportError as e:
    logging.critical(f"Falha ao importar threatdeflect_rs: {e}")
    raise

class RepositoryAnalyzer:
    MAX_IOC_CHECKS: int = 50
    MAX_AI_CHECKS: int = 50
    CONFIDENCE_AUTO_DISCARD: float = 0.15
    CONFIDENCE_AUTO_ACCEPT: float = 0.70
    CONFIDENCE_AI_LOW: float = 0.15
    CONFIDENCE_AI_HIGH: float = 0.70

    def __init__(self, repo_url: str, api_client: ApiClient, status_callback: Optional[Callable[[str], None]] = None, cached_data: Optional[Dict[str, Any]] = None) -> None:
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
        self.rust_analyzer: Optional[RustAnalyzer] = None
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

            rules_map: Dict[str, str] = {}
            suspicious_map: Dict[str, str] = {}

            for rule in config.get('rules', []):
                rule_id = rule.get('id')
                pattern = rule.get('pattern')
                if not rule_id or not pattern:
                    continue

                suspicious_keywords = ("command", "execution", "c2", "loading", "injection", "hook", "mount", "deserialization", "whitespace")
                if any(kw in rule_id.lower() for kw in suspicious_keywords):
                    suspicious_map[rule_id] = pattern
                else:
                    rules_map[rule_id] = pattern

            self.rust_analyzer = RustAnalyzer(rules_map, suspicious_map)

        except Exception as e:
            logging.error(f"FALHA CRITICA: Erro ao configurar analisador: {e}", exc_info=True)
            raise ValueError("Falha na inicializacao da configuracao ou do Rust engine.") from e

    def _update_status(self, message: str) -> None:
        if self.status_callback:
            self.status_callback(message)

    def _add_finding(self, description: str, file_path: str, finding_type: str, severity: Optional[str] = None) -> None:
        final_severity = severity or self.severity_map.get(finding_type, "LOW")
        finding = {"severity": final_severity, "description": description, "file": file_path, "type": finding_type}

        is_duplicate = any(
            f["type"] == finding_type and f["file"] == file_path and f["description"] == description
            for f in self.results["findings"]
        )

        if not is_duplicate:
            self.results["findings"].append(finding)

    def _process_file_content(self, content: str, file_info: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        file_path = file_info.get('path', 'N/A')
        file_name = file_info.get('name', '')

        try:
            rust_findings, rust_iocs = self.rust_analyzer.process_file_content(content, file_path, file_name)
        except Exception as e:
            logging.error(f"Erro no Rust engine ao processar {file_path}: {e}")
            return [], [], {}

        local_findings: List[Dict[str, Any]] = []

        for f in rust_findings:
            f_type = f["type"]
            f["confidence"] = validate_finding(f)
            f["severity"] = self.severity_map.get(f_type, "LOW")

            if f["severity"] in ("CRITICAL", "HIGH") and f["confidence"] < self.CONFIDENCE_AUTO_ACCEPT:
                f["confidence"] = max(f["confidence"], 0.70)

            confidence = f["confidence"]

            if confidence < self.CONFIDENCE_AUTO_DISCARD:
                logging.debug(f"Auto-descartado (conf={confidence:.2f}): {f_type} em {file_path}")
                continue

            if confidence >= self.CONFIDENCE_AUTO_ACCEPT:
                if "match_content" in f:
                    f.pop("match_content")
                local_findings.append(f)
                continue

            if "match_content" in f:
                self.candidates_for_ai_validation.append(f)
            else:
                local_findings.append(f)

        local_iocs = rust_iocs
        local_deps: Dict[str, List[str]] = {}

        if file_name in self.dependency_files:
            deps: List[str] = []
            try:
                if file_name == 'package.json':
                    data = json.loads(content)
                    deps.extend(data.get('dependencies', {}).keys())
                    deps.extend(data.get('devDependencies', {}).keys())
                    dangerous_hooks = {
                        'install', 'preinstall', 'postinstall',
                        'prepare', 'prepublish', 'prepublishOnly',
                        'prepack', 'postpack',
                        'preuninstall', 'postuninstall',
                    }
                    pipe_patterns = re.compile(
                        r'(curl|wget|fetch)\s.*\|\s*(sh|bash|zsh|node|python)',
                        re.IGNORECASE,
                    )
                    scripts_block = data.get('scripts', {})
                    for hook_name, hook_cmd in scripts_block.items():
                        if hook_name in dangerous_hooks:
                            severity = self.severity_map.get("NPM Dangerous Hook", "CRITICAL")
                            local_findings.append({
                                "severity": severity,
                                "description": f"Hook de NPM perigoso ('{hook_name}')",
                                "file": file_path,
                                "type": "NPM Dangerous Hook",
                            })
                        if isinstance(hook_cmd, str) and pipe_patterns.search(hook_cmd):
                            local_findings.append({
                                "severity": "CRITICAL",
                                "description": f"Script NPM com pipe remoto para shell ('{hook_name}')",
                                "file": file_path,
                                "type": "Remote Code Loading",
                            })
                elif file_name == 'requirements.txt':
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith('#') or line.startswith('-'):
                            continue
                        # Strip environment markers (e.g. "; python_version >= '3.8'")
                        line = line.split(';')[0].strip()
                        # Strip extras (e.g. "pkg[extra1,extra2]")
                        line = re.sub(r'\[.*?\]', '', line)
                        # Strip version specifiers
                        pkg = re.split(r'[><=!~]', line)[0].strip()
                        if pkg:
                            deps.append(pkg)

                if deps:
                    local_deps[file_name] = deps
            except Exception as e:
                logging.warning(f"Nao foi possivel analisar dependencias de {file_path}: {e}")

        return local_findings, local_iocs, local_deps

    def _analyze_dependencies(self) -> None:
        if not self.results.get("dependencies"):
            return

        ecosystem_map = {'package.json': 'npm', 'requirements.txt': 'PyPI'}
        all_deps = [{'pkg': p, 'eco': eco, 'file': f} for f, pkgs in self.results["dependencies"].items() if (eco := ecosystem_map.get(os.path.basename(f))) for p in pkgs]

        if not all_deps:
            return

        self._update_status(f"Analisando vulnerabilidades em {len(all_deps)} dependencias...")

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_dep = {executor.submit(self.api_client.check_package_vulnerability, d['pkg'], d['eco']): d for d in all_deps}
            for future in as_completed(future_to_dep):
                dep_info = future_to_dep[future]
                try:
                    if vulns := future.result():
                        ids = ", ".join([v.get('id', 'N/A') for v in vulns])
                        self._add_finding(f"Dependencia vulneravel: '{dep_info['pkg']}' (IDs: {ids})", dep_info['file'], "Malicious Dependency")
                except Exception as exc:
                    logging.error(f"Erro ao analisar dependencia {dep_info['pkg']}: {exc}")

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
            self._update_status(f"Verificando reputacao de {total_unique} IOCs unicos...")

        url_reputation_map: Dict[str, Any] = {}

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
                    url_reputation_map[url] = {"virustotal": {"error": "Falha na verificacao"}}

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
        if not self.candidates_for_ai_validation:
            return

        total_candidates = len(self.candidates_for_ai_validation)
        items_to_analyze = self.candidates_for_ai_validation
        limit_reached = False

        if total_candidates > self.MAX_AI_CHECKS:
            limit_reached = True
            items_to_analyze = self.candidates_for_ai_validation[:self.MAX_AI_CHECKS]

            self._add_finding(
                f"Limite de IA atingido. {total_candidates - self.MAX_AI_CHECKS} itens requerem revisao manual.",
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
                    f"UNVERIFIED ({original_type})",
                    severity=fallback_severity
                )

        available_models = self.api_client.get_local_models()
        try:
            model_name = available_models[0] if available_models and "erro" not in str(available_models[0]).lower() else None
        except (IndexError, TypeError):
            model_name = None

        if not model_name:
            for finding in items_to_analyze:
                self._add_finding(finding["description"], finding["file"], finding["type"], severity="LOW")
            return

        msg_status = f"IA: Julgando {len(items_to_analyze)} casos"
        if limit_reached:
            msg_status += f" (Amostra de {total_candidates})"
        msg_status += f" com {model_name}..."

        self._update_status(msg_status)

        def _mask_secret(value: str) -> str:
            return f"[REDACTED:{len(value)}]"

        def validate_single(finding: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
            snippet = finding.get("match_content", "")
            masked_snippet = _mask_secret(snippet)
            f_type = finding["type"]
            f_file = finding["file"]
            f_conf = finding.get("confidence", 0.5)
            f_ctx = finding.get("file_context", "Unknown")

            prompt = (
                f"Analyze this code snippet from '{f_file}' (context: {f_ctx}, engine confidence: {f_conf:.2f}).\n"
                f"Detection type: '{f_type}'.\n"
                f"Snippet: `{masked_snippet}`\n\n"
                "Respond EXCLUSIVELY in JSON with key 'score' (float 0.0-1.0).\n"
                "0.0 = definitely false positive (test, placeholder, example, documentation).\n"
                "1.0 = definitely real secret/vulnerability.\n"
                "Example: {\"score\": 0.85}"
            )

            try:
                raw_response = self.api_client.get_ai_judge_response(model_name, prompt)
                start_idx = raw_response.find('{')
                end_idx = raw_response.rfind('}') + 1

                if start_idx == -1 or end_idx == 0:
                    raise ValueError("Output nao contem JSON valido.")

                parsed_json = json.loads(raw_response[start_idx:end_idx])

                if "score" in parsed_json:
                    ai_score = float(parsed_json["score"])
                    ai_score = max(0.0, min(1.0, ai_score))
                    if ai_score >= 0.6:
                        return finding, "REAL", ai_score
                    elif ai_score <= 0.3:
                        return finding, "FALSO", ai_score
                    return finding, "INCONCLUSIVO", ai_score

                status = parsed_json.get("status", "").upper()
                if status == "REAL":
                    return finding, "REAL", 0.8
                elif status == "FALSO":
                    return finding, "FALSO", 0.2
                return finding, "INCONCLUSIVO", 0.5

            except Exception as e:
                logging.warning(f"Falha de guardrail na IA para o arquivo {f_file}: {e}")
                return finding, "FALHA", 0.5

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(validate_single, f) for f in items_to_analyze]

            completed = 0
            for future in as_completed(futures):
                try:
                    original_finding, verdict, ai_score = future.result()
                    completed += 1
                    if completed % 5 == 0:
                         self._update_status(f"IA: Processando {completed}/{len(items_to_analyze)}...")

                    if verdict == "REAL":
                        original_finding["confidence"] = ai_score
                        severity = "HIGH" if "Key" in original_finding["type"] or "Token" in original_finding["type"] else "MEDIUM"
                        self._add_finding(
                            f"[IA Confirmou] {original_finding['description']}",
                            original_finding["file"],
                            original_finding["type"],
                            severity=severity
                        )
                    elif verdict == "FALSO":
                        logging.info(f"IA descartou (score={ai_score:.2f}) em {original_finding['file']}: {original_finding['type']}")
                    else:
                        original_finding["confidence"] = ai_score
                        self._add_finding(
                            f"[IA Inconclusiva] {original_finding['description']}",
                            original_finding["file"],
                            f"UNVERIFIED ({original_finding['type']})",
                            severity="MEDIUM"
                        )

                except Exception as e:
                    logging.error(f"Erro na validacao IA: {e}")

    def _correlate_findings(self) -> None:
        findings = self.results.get("findings", [])
        iocs = self.results.get("extracted_iocs", [])
        if not findings:
            return

        files_with_eval: set = set()
        files_with_entropy: set = set()
        files_with_external_url: set = set()

        eval_types = {"Suspicious JS Keyword", "Remote Code Loading", "Encoded Payload Execution"}
        entropy_types = {"High Entropy String"}

        for f in findings:
            ftype = f.get("type", "")
            fpath = f.get("file", "")
            if ftype in eval_types:
                files_with_eval.add(fpath)
            if ftype in entropy_types:
                files_with_entropy.add(fpath)

        for ioc in iocs:
            files_with_external_url.add(ioc.get("source_file", ""))

        correlated_files = files_with_eval & files_with_external_url

        for f in findings:
            if f.get("correlated"):
                continue

            fpath = f.get("file", "")
            ftype = f.get("type", "")

            if fpath in correlated_files and ftype in eval_types:
                f["severity"] = "HIGH"
                f["correlated"] = True
                f["description"] = f.get("description", "") + " [CORRELADO: eval + URL externa no mesmo arquivo]"
            elif fpath in correlated_files and ftype in entropy_types:
                f["severity"] = "HIGH"
                f["correlated"] = True
                f["description"] = f.get("description", "") + " [CORRELADO: payload ofuscado + URL externa]"
            elif fpath in files_with_eval and fpath in files_with_entropy:
                if ftype in entropy_types:
                    f["severity"] = "MEDIUM"
                    f["correlated"] = True
                    f["description"] = f.get("description", "") + " [CORRELADO: entropia alta + eval no mesmo arquivo]"

    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> int:
        if not findings:
            return 0

        weight_map = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 5, "LOW": 1}
        total_weighted = 0.0
        total_weight = 0.0
        unique_types: set = set()
        production_count = 0

        for f in findings:
            severity = f.get("severity", "LOW")
            confidence = f.get("confidence", 0.5)
            weight = weight_map.get(severity, 1)
            total_weighted += weight * confidence
            total_weight += weight
            unique_types.add(f.get("type", ""))
            if f.get("file_context", "Production") == "Production":
                production_count += 1

        if total_weight == 0:
            return 0

        base_score = (total_weighted / total_weight) * 100
        volume_bonus = min(len(findings) * 0.5, 15)
        diversity_bonus = min(len(unique_types) * 3, 15)
        production_ratio = production_count / len(findings) if findings else 0
        production_bonus = 10 if production_ratio > 0.5 else 0

        return min(int(base_score + volume_bonus + diversity_bonus + production_bonus), 100)

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not findings:
            return findings

        groups: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            match_key = f.get("match_content", f.get("description", ""))
            key = f"{f.get('type', '')}::{hash(match_key)}"
            groups.setdefault(key, []).append(f)

        deduplicated: List[Dict[str, Any]] = []
        for group in groups.values():
            best = max(group, key=lambda x: x.get("confidence", 0.5))
            if len(group) > 1:
                best["locations"] = [g.get("file", "") for g in group]
                best["occurrence_count"] = len(group)
            deduplicated.append(best)

        return deduplicated

    def run_analysis(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        self._update_status(f"Iniciando: {os.path.basename(self.repo_url)}")
        all_repo_files = self.api_client.list_repository_files(self.repo_url)
        if isinstance(all_repo_files, dict) and 'error' in all_repo_files:
            self._add_finding(f"Erro de API: {all_repo_files.get('error')}", self.repo_url, "CRITICAL")
            self.results["risk_score"] = 100
            return self.results, {}
        if not all_repo_files:
            self._add_finding("Repositorio vazio ou inacessivel", self.repo_url, "LOW")
            return self.results, {}

        current_repo_state: Dict[str, Dict[str, Any]] = {}
        files_to_analyze: List[Dict[str, Any]] = []
        self._update_status(f"Comparando {len(all_repo_files)} arquivos com o cache...")
        for file_info in all_repo_files:
            path = file_info['path']
            content_hash = file_info.get('sha')
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
            files_to_inspect: List[Dict[str, Any]] = []
            for file_info in files_to_analyze:
                fname = file_info.get('name', '').lower()
                fpath = file_info.get('path', '')

                if any(ignored in fpath for ignored in self.ignore_dirs):
                    continue
                if fname in self.ignore_files:
                    continue

                if fname in self.sensitive_filenames:
                    self.candidates_for_ai_validation.append({
                        "description": f"Arquivo sensivel detectado: {fname}",
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
                        if not content:
                            continue
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

        self._correlate_findings()

        self._update_status("Finalizando analise...")
        for file, deps_list in self.results["dependencies"].items():
            self.results["dependencies"][file] = sorted(list(set(deps_list)))

        self.results["findings"] = self._deduplicate_findings(self.results["findings"])

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.results["findings"].sort(key=lambda x: severity_order.get(x["severity"], 99))

        self.results["risk_score"] = self._calculate_risk_score(self.results["findings"])

        return self.results, current_repo_state
