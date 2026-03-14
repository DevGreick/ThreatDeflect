import logging
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed, Future

from threatdeflect.api.api_client import ApiClient
from threatdeflect.core.report_generator import ReportGenerator
from threatdeflect.core.repository_analyzer import RepositoryAnalyzer
from threatdeflect.utils.utils import parse_targets, calculate_sha256
from threatdeflect.core.prompt_builder import build_dossier_prompt, build_triage_prompt
from threatdeflect.core.cache_manager import CacheManager

ProgressCallback = Optional[Callable[[int, int], None]]
LogCallback = Optional[Callable[[str], None]]

class AnalysisError(Exception):
    pass

class NoValidTargetsError(AnalysisError):
    pass

class InterruptedException(Exception):
    pass

def _log_message(message: str, log_callback: LogCallback) -> None:
    if log_callback:
        log_callback(message)
    logging.info(message)

def run_ioc_analysis(
    targets_text: str,
    output_path: Path,
    log_callback: LogCallback = None,
    progress_callback: ProgressCallback = None
) -> Dict[str, Any]:
    api_client = ApiClient()
    ips, urls = parse_targets(targets_text)
    if not ips and not urls:
        _log_message("Nenhum alvo valido encontrado.", log_callback)
        raise NoValidTargetsError("Nenhum alvo valido.")

    all_ip_results: Dict[str, Any] = {}
    all_url_results: Dict[str, Any] = {}
    total_targets = len(ips) + len(urls)
    processed_count = 0
    if progress_callback:
        progress_callback(0, total_targets)

    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            if ips:
                _log_message(f"Enviando {len(ips)} IPs...", log_callback)
                future_to_ip: Dict[Future[Any], str] = {executor.submit(api_client.check_ip_multi, ip): ip for ip in ips}
                try:
                    for future in as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            all_ip_results[ip] = future.result()
                            _log_message(f"Resultados IP {ip} recebidos.", log_callback)
                        except Exception as exc:
                            logging.error(f"Erro no IP {ip}: {exc}")
                        processed_count += 1
                        if progress_callback:
                            progress_callback(processed_count, total_targets)
                except InterruptedException:
                    # NOTE: future.cancel() only prevents queued futures from starting;
                    # already-running futures will complete in the background.
                    for future in future_to_ip: future.cancel()
                    raise

            if urls:
                _log_message(f"Enviando {len(urls)} URLs...", log_callback)
                future_to_url: Dict[Future[Any], str] = {executor.submit(api_client.check_url_multi, url): url for url in urls}
                try:
                    for future in as_completed(future_to_url):
                        url = future_to_url[future]
                        try:
                            all_url_results[url] = future.result()
                            _log_message(f"Resultados URL {url} recebidos.", log_callback)
                        except Exception as exc:
                            logging.error(f"Erro na URL {url}: {exc}")
                        processed_count += 1
                        if progress_callback:
                            progress_callback(processed_count, total_targets)
                except InterruptedException:
                    for future in future_to_url: future.cancel()
                    raise

        results = {'ips': all_ip_results, 'urls': all_url_results}
        reporter = ReportGenerator(ip_results=all_ip_results, url_results=all_url_results)
        reporter.generate_excel(str(output_path))
        return results
    except InterruptedException:
        _log_message("Cancelado.", log_callback)
        raise 
    except Exception as e:
        logging.error(f"ERRO IOCs: {e}")
        raise AnalysisError("Falha na analise de IOCs.") from e

def run_repo_analysis(
    repo_urls: List[str],
    output_path: Path,
    log_callback: LogCallback = None,
    progress_callback: ProgressCallback = None
) -> Dict[str, Any]:
    try:
        api_client = ApiClient()
        total_repos = len(repo_urls)
        processed_count = 0
        all_repo_results: List[Dict[str, Any]] = []
        if progress_callback:
            progress_callback(0, total_repos)

        for repo_url in repo_urls:
            if progress_callback:
                progress_callback(processed_count, total_repos)

            _log_message(f"Iniciando {repo_url}", log_callback)
            cache_manager = CacheManager(repo_url)
            cached_data = cache_manager.get_cached_results()
            
            analyzer = RepositoryAnalyzer(repo_url, api_client, log_callback, cached_data)
            
            try:
                repo_results, current_repo_state = analyzer.run_analysis()
                cache_manager.update_cache(current_repo_state)
                all_repo_results.append(repo_results)
                _log_message(f"Repositorio {os.path.basename(repo_url)} finalizado.", log_callback)
            except Exception as exc:
                logging.error(f"Erro {repo_url}: {exc}")
            finally:
                cache_manager.close()
                processed_count += 1
                if progress_callback:
                    progress_callback(processed_count, total_repos)

        if progress_callback:
            progress_callback(processed_count, total_repos)

        executive_summary = ""
        all_findings = [finding for repo in all_repo_results for finding in repo.get('findings', [])]
        
        if all_findings:
            _log_message("Gerando Resumo Executivo...", log_callback)
            triage_prompt = build_triage_prompt(all_findings, ", ".join(repo_urls))
            
            available_models = api_client.get_local_models()
            if available_models and "erro" not in available_models[0].lower():
                model = available_models[0]
                executive_summary = api_client.get_ai_summary(model, triage_prompt)
            else:
                executive_summary = "Falha: Nenhum modelo de IA."

        results = {'repositories': all_repo_results, 'executive_summary': executive_summary}
        reporter = ReportGenerator(repo_results=all_repo_results, executive_summary=executive_summary)
        reporter.generate_excel(str(output_path))
        return results
    except InterruptedException:
        _log_message("Cancelado.", log_callback)
        raise
    except Exception as e:
        logging.error(f"ERRO REPOSITORIOS: {e}")
        raise AnalysisError("Falha na analise.") from e

def run_file_analysis(
    file_paths: List[str],
    output_path: Path,
    log_callback: LogCallback = None,
    progress_callback: ProgressCallback = None
) -> Dict[str, Any]:
    try:
        api_client = ApiClient()
        total_files = len(file_paths)
        all_file_results: Dict[str, Any] = {}
        if progress_callback:
            progress_callback(0, total_files)

        hash_to_filename: Dict[str, str] = {}
        for f_path in file_paths:
            file_hash = calculate_sha256(f_path)
            if file_hash:
                hash_to_filename[file_hash] = os.path.basename(f_path)
            else:
                _log_message(f"Falha hash: {f_path}", log_callback)
        
        if not hash_to_filename:
            raise NoValidTargetsError("Sem hashes validos.")

        processed_count = 0
        total_hashes = len(hash_to_filename)
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_hash: Dict[Future[Any], str] = {
                executor.submit(api_client.check_file_multi, f_hash): f_hash
                for f_hash in hash_to_filename
            }
            try:
                for future in as_completed(future_to_hash):
                    f_hash = future_to_hash[future]
                    filename = hash_to_filename[f_hash]
                    try:
                        result = future.result()
                        result['filename'] = filename
                        all_file_results[f_hash] = result
                    except Exception as exc:
                        logging.error(f"Erro arquivo {filename}: {exc}")
                    processed_count += 1
                    if progress_callback:
                        progress_callback(processed_count, total_hashes)
            except InterruptedException:
                for future in future_to_hash: future.cancel()
                raise

        results = {'files': all_file_results}
        reporter = ReportGenerator(file_results=all_file_results)
        reporter.generate_excel(str(output_path))
        return results
        
    except (NoValidTargetsError, InterruptedException):
        raise
    except Exception as e:
        logging.error(f"ERRO ARQUIVOS: {e}")
        raise AnalysisError("Falha arquivos.") from e

def _validate_hallucinations(summary: str, analysis_data: Dict[str, Any]) -> str:
    warnings: List[str] = []

    # Validate IPs
    valid_ips = set(analysis_data.get('ips', {}).keys())
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    found_ips = set(re.findall(ip_pattern, summary))
    hallucinated_ips = [ip for ip in found_ips if ip not in valid_ips]
    if hallucinated_ips:
        warnings.append(f"IPs alucinados: {', '.join(hallucinated_ips)}")

    # Validate URLs
    valid_urls = set(analysis_data.get('urls', {}).keys())
    url_pattern = r'https?://[^\s<>\"\');\]}]+'
    found_urls = set(re.findall(url_pattern, summary))
    if valid_urls:
        hallucinated_urls = [u for u in found_urls if u not in valid_urls]
        if hallucinated_urls:
            warnings.append(f"URLs alucinadas: {', '.join(hallucinated_urls[:10])}")

    # Validate hashes
    valid_hashes = set(analysis_data.get('files', {}).keys())
    hash_pattern = r'\b[a-fA-F0-9]{64}\b'
    found_hashes = set(re.findall(hash_pattern, summary))
    if valid_hashes:
        hallucinated_hashes = [h for h in found_hashes if h not in valid_hashes]
        if hallucinated_hashes:
            warnings.append(f"Hashes alucinados: {', '.join(hallucinated_hashes[:5])}")

    if warnings:
        details = "; ".join(warnings)
        warning = f"\n\n> **ALERTA DE SEGURANCA (GUARDRAIL):** O modelo gerou referencias a indicadores que NAO constam no relatorio base. Desconsidere: {details}"
        summary += warning

    return summary

def get_ai_summary(
    analysis_data: Dict[str, Any], 
    model: str, 
    log_callback: LogCallback = None,
    status_callback: Optional[Callable[[str, str], None]] = None
) -> str:
    _log_message("Preparando dossie IA...", log_callback)
    if not any(analysis_data.values()):
        return "Erro: Nenhuma analise executada."

    prompt = build_dossier_prompt(analysis_data)
    
    if status_callback:
        status_callback("Em Andamento", f"Enviando para {model}...")
        
    api_client = ApiClient()
    local_models = api_client.get_local_models()
    if model not in local_models:
        return "Erro: Modelo nao encontrado."
        
    summary = api_client.get_ai_summary(model, prompt)
    validated_summary = _validate_hallucinations(summary, analysis_data)
    
    return validated_summary
