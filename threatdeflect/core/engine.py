# ===================================================================
# Módulo do Motor de Análise (engine.py)
# ===================================================================
# threatdeflect/core/engine.py

import logging
import os
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
    """Exceção base para erros ocorridos durante a análise."""
    pass

class NoValidTargetsError(AnalysisError):
    """Levantada quando nenhum alvo válido é fornecido para análise."""
    pass

class InterruptedException(Exception):
    """Levantada quando um usuário solicita o cancelamento da análise."""
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
        _log_message("Nenhum alvo válido (IP/URL) encontrado.", log_callback)
        raise NoValidTargetsError("Nenhum alvo válido (IP/URL) foi fornecido para análise.")

    all_ip_results, all_url_results = {}, {}
    total_targets = len(ips) + len(urls)
    processed_count = 0
    if progress_callback:
        progress_callback(0, total_targets)

    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            if ips:
                _log_message(f"Enviando {len(ips)} IPs para análise em paralelo...", log_callback)
                future_to_ip: Dict[Future, str] = {executor.submit(api_client.check_ip_multi, ip): ip for ip in ips}
                try:
                    for future in as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            all_ip_results[ip] = future.result()
                            _log_message(f"Resultados para o IP {ip} recebidos.", log_callback)
                        except Exception as exc:
                            logging.error(f"Erro ao processar o IP {ip}: {exc}", exc_info=True)
                        processed_count += 1
                        if progress_callback:
                            progress_callback(processed_count, total_targets)
                except InterruptedException:
                    for future in future_to_ip: future.cancel()
                    raise

            if urls:
                _log_message(f"Enviando {len(urls)} URLs para análise em paralelo...", log_callback)
                future_to_url: Dict[Future, str] = {executor.submit(api_client.check_url_multi, url): url for url in urls}
                try:
                    for future in as_completed(future_to_url):
                        url = future_to_url[future]
                        try:
                            all_url_results[url] = future.result()
                            _log_message(f"Resultados para a URL {url} recebidos.", log_callback)
                        except Exception as exc:
                            logging.error(f"Erro ao processar a URL {url}: {exc}", exc_info=True)
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
        _log_message("Análise de IOCs cancelada pelo usuário.", log_callback)
        raise 
    except Exception as e:
        logging.error(f"ERRO CRÍTICO NA ANÁLISE DE IOCs: {e}", exc_info=True)
        _log_message("ERRO CRÍTICO. Consulte o arquivo threatdeflect.log para detalhes.", log_callback)
        raise AnalysisError("Uma falha inesperada ocorreu durante a análise de IOCs.") from e


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
        all_repo_results = []
        if progress_callback:
            progress_callback(0, total_repos)

        for repo_url in repo_urls:
            if progress_callback:
                progress_callback(processed_count, total_repos)

            _log_message(f"Iniciando análise para {repo_url}", log_callback)
            cache_manager = CacheManager(repo_url)
            cached_data = cache_manager.get_cached_results()
            
            analyzer = RepositoryAnalyzer(repo_url, api_client, log_callback, cached_data)
            
            try:
                repo_results, current_repo_state = analyzer.run_analysis()
                
                _log_message(f"Atualizando cache para {repo_url}", log_callback)
                cache_manager.update_cache(current_repo_state)
                all_repo_results.append(repo_results)
                _log_message(f"Repositório {os.path.basename(repo_url)} analisado.", log_callback)
                
            except Exception as exc:
                logging.error(f"Erro ao processar o repositório {repo_url}: {exc}", exc_info=True)
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
            _log_message("Gerando Resumo Executivo com IA...", log_callback)
            triage_prompt = build_triage_prompt(all_findings, ", ".join(repo_urls))
            
            available_models = api_client.get_local_models()
            if available_models and "não encontrado" not in available_models[0].lower() and "erro" not in available_models[0].lower():
                model = available_models[0]
                executive_summary = api_client.get_ai_summary(model, triage_prompt)
            else:
                executive_summary = "Não foi possível gerar o Resumo Executivo: Nenhum modelo de IA disponível."

        results = {'repositories': all_repo_results, 'executive_summary': executive_summary}
        reporter = ReportGenerator(repo_results=all_repo_results, executive_summary=executive_summary)
        reporter.generate_excel(str(output_path))
        return results
    except InterruptedException:
        _log_message("Análise de Repositórios cancelada pelo usuário.", log_callback)
        raise
    except Exception as e:
        logging.error(f"ERRO CRÍTICO NA ANÁLISE DE REPOSITÓRIOS: {e}", exc_info=True)
        _log_message("ERRO CRÍTICO. Consulte o arquivo threatdeflect.log para detalhes.", log_callback)
        raise AnalysisError("Uma falha inesperada ocorreu durante a análise de repositórios.") from e


def run_file_analysis(
    file_paths: List[str],
    output_path: Path,
    log_callback: LogCallback = None,
    progress_callback: ProgressCallback = None
) -> Dict[str, Any]:
    
    try:
        api_client = ApiClient()
        total_files = len(file_paths)
        all_file_results = {}
        if progress_callback:
            progress_callback(0, total_files)

        hash_to_filename = {}
        _log_message(f"Calculando hashes para {total_files} arquivos...", log_callback)
        for f_path in file_paths:
            file_hash = calculate_sha256(f_path)
            if file_hash:
                hash_to_filename[file_hash] = os.path.basename(f_path)
            else:
                _log_message(f"Falha ao calcular hash para {f_path}. Arquivo ignorado.", log_callback)
        
        if not hash_to_filename:
            _log_message("Nenhum hash válido foi gerado. Análise encerrada.", log_callback)
            raise NoValidTargetsError("Nenhum arquivo válido ou legível pôde ser processado.")

        processed_count = 0
        total_hashes = len(hash_to_filename)
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_hash: Dict[Future, str] = {
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
                        _log_message(f"Resultados para o arquivo {filename} recebidos.", log_callback)
                    except Exception as exc:
                        logging.error(f"Erro ao processar o arquivo {filename}: {exc}", exc_info=True)
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
        logging.error(f"ERRO CRÍTICO NA ANÁLISE DE ARQUIVOS: {e}", exc_info=True)
        _log_message("ERRO CRÍTICO. Consulte o arquivo threatdeflect.log para detalhes.", log_callback)
        raise AnalysisError("Uma falha inesperada ocorreu durante a análise de arquivos.") from e


def get_ai_summary(
    analysis_data: Dict[str, Any], 
    model: str, 
    log_callback: LogCallback = None,
    status_callback: Optional[Callable[[str, str], None]] = None
) -> str:
    _log_message("Preparando dossiê detalhado para análise com IA...", log_callback)
    if not any(analysis_data.values()):
        return "Erro: Nenhuma análise foi executada ainda."


    prompt = build_dossier_prompt(analysis_data)
    
    if status_callback:
        status_callback(
            "Análise com IA em Andamento", 
            f"Enviando dossiê para o modelo {model}...\n\n"
            "Este processo pode levar vários minutos, dependendo do modelo e do hardware. "
            "A aplicação não está travada."
        )
        
    _log_message(f"Enviando dossiê detalhado ao modelo {model}...", log_callback)
    api_client = ApiClient()
    
    local_models = api_client.get_local_models()
    if model not in local_models:
        error_msg = f"Erro: Modelo de IA '{model}' não encontrado. Modelos disponíveis: {', '.join(local_models)}"
        _log_message(error_msg, log_callback)
        return error_msg
        
    summary = api_client.get_ai_summary(model, prompt)
    return summary