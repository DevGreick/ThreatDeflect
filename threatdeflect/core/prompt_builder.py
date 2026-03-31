import re
from typing import Dict, Any, List
from threatdeflect.utils.utils import safe_get


_INJECTION_PATTERNS = [
    re.compile(r'(?i)(ignore|disregard|forget|override|bypass|skip)\s+(all\s+)?(previous|above|prior|system|original)\s+(instructions?|rules?|prompts?|context)'),
    re.compile(r'(?i)(you\s+are\s+now|new\s+instructions?|system\s*prompt|act\s+as|role\s*:\s*|debug\s+mode|developer\s+mode|jailbreak)'),
    re.compile(r'(?i)(respond\s+only\s+with|always\s+(say|respond|output)|from\s+now\s+on)'),
    re.compile(r'(?i)```\s*(system|instruction|prompt)'),
]

def _sanitize_data(text: str) -> str:
    for pattern in _INJECTION_PATTERNS:
        text = pattern.sub('[SANITIZED]', text)
    text = ''.join(c for c in text if c.isprintable() or c in ('\n', '\t'))
    return text

def build_dossier_prompt(analysis_data: Dict[str, Any]) -> str:
    facts = _generate_facts_from_data(analysis_data)
    prompt_template = (
        "Voce e um analista de ciberseguranca senior.\n"
        "Gere um relatorio tecnico-executivo em portugues do Brasil com base no dossie fornecido.\n"
        "REGRA CRITICA: Nao invente, nao alucine e nao adicione IPs, URLs, hashes ou nomes de arquivos que nao constem estritamente no dossie.\n"
        "O formato deve ser Markdown com a seguinte estrutura exata:\n\n"
        "### Tabela Resumo da Analise\n"
        "### 1. Ameacas Criticas\n"
        "### 2. Comportamento Anomalo ou Suspeito\n"
        "### 3. Recomendacoes / Proximos Passos\n\n"
        f"```dossie\n{facts}\n```"
    )
    return prompt_template

def build_triage_prompt(all_findings: List[Dict[str, Any]], repo_url: str) -> str:
    if not all_findings:
        return ""
    facts = f"Repositorio: {repo_url}\n\nAchados:\n"
    for finding in all_findings:
        desc = finding.get('description', 'N/A').replace('\n', ' ')
        facts += f"SEVERIDADE: {finding.get('severity', 'N/A')} | TIPO: {finding.get('type', 'N/A')} | ARQUIVO: {finding.get('file', 'N/A')} | DESCRICAO: {desc}\n"
    prompt_template = (
        "Voce e um lider de ciberseguranca.\n"
        "Crie um Resumo Executivo conciso priorizando os 3 riscos mais urgentes da lista.\n"
        "REGRA CRITICA: Use apenas os dados listados. Nao invente vulnerabilidades.\n\n"
        f"```dados\n{facts}\n```"
    )
    return prompt_template

def _generate_facts_from_data(analysis_data: Dict[str, Any]) -> str:
    facts = "Dossie:\n\n"
    if repo_data := analysis_data.get('repositories', []):
        facts += f"Repositorios ({len(repo_data)}):\n"
        for repo in repo_data:
            facts += f"URL: {_sanitize_data(str(repo.get('url')))} | Risco: {repo.get('risk_score', 0)}\n"
            if findings := repo.get('findings'):
                for finding in findings:
                    facts += f"[{finding.get('severity', 'N/A')}] {finding.get('type', 'N/A')} no arquivo {finding.get('file', 'N/A')}\n"
            if iocs := repo.get('extracted_iocs'):
                for ioc in iocs:
                    vt_malicious = safe_get(ioc, 'reputation.virustotal.data.attributes.stats.malicious', 0)
                    facts += f"IOC Oculto: {_sanitize_data(str(ioc.get('ioc')))} (Arquivo: {ioc.get('source_file')}, VT: {vt_malicious})\n"
    if ip_data := analysis_data.get('ips', {}):
        facts += f"IPs ({len(ip_data)}):\n"
        for ip, results in ip_data.items():
            vt = safe_get(results, 'virustotal.data.attributes.last_analysis_stats.malicious', 'N/A')
            abuse = safe_get(results, 'abuseipdb.data.abuseConfidenceScore', 'N/A')
            facts += f"IP: {ip} | VT: {vt} | AbuseIPDB: {abuse}%\n"
    if url_data := analysis_data.get('urls', {}):
        facts += f"URLs ({len(url_data)}):\n"
        for url, results in url_data.items():
            vt = safe_get(results, 'virustotal.data.attributes.stats.malicious', 'N/A')
            uh = safe_get(results, 'urlhaus.url_status', 'N/A')
            facts += f"URL: {url} | VT: {vt} | URLHaus: {uh}\n"
    if file_data := analysis_data.get('files', {}):
        facts += f"Arquivos ({len(file_data)}):\n"
        for f_hash, results in file_data.items():
            filename = results.get('filename', 'N/A')
            vt = safe_get(results, 'virustotal.data.attributes.last_analysis_stats.malicious', 'N/A')
            mb = safe_get(results, 'malwarebazaar.data.0.signature', 'N/A')
            facts += f"Hash: {f_hash} | Arquivo: {filename} | VT: {vt} | MB: {mb}\n"
    return facts
