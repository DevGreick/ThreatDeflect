import configparser
import re
from typing import Dict, Any, List
from threatdeflect.utils.utils import safe_get, get_config_path


_LANG_INSTRUCTIONS = {
    'pt_br': {
        'lang_rule': "INSTRUCAO OBRIGATORIA: Responda INTEIRAMENTE em portugues do Brasil. NUNCA use ingles.",
        'role_dossier': "Voce e um analista senior de Threat Intelligence redigindo um relatorio executivo.",
        'tone': "Tom: tecnico, formal, objetivo.",
        'lang_label': "Idioma: portugues do Brasil.",
        'all_text_rule': "TODO o texto deve ser em portugues do Brasil, sem excecao.",
        'role_triage': "Voce e um lider de ciberseguranca redigindo um Resumo Executivo de auditoria de repositorio.",
        'tone_triage': "Tom: tecnico, formal, direto.",
        'no_invent': "Use EXCLUSIVAMENTE dados do dossie. Zero invencao de IPs, URLs, hashes ou achados.",
        'no_invent_triage': "Use EXCLUSIVAMENTE os achados listados. Zero invencao.",
        'prioritize': "Priorize por severidade (CRITICAL > HIGH > MEDIUM > LOW).",
        'each_risk': "Cada risco deve ter: descricao, impacto e acao recomendada.",
        'no_data': "Se nao ha dados suficientes para uma secao, escreva 'Nenhum indicador relevante identificado.'",
        'numbers_rule': "Numeros e metricas devem vir diretamente do dossie.",
        'h_exec': "Resumo Executivo",
        'h_exec_desc': "(2-3 frases: escopo da analise, quantidade de alvos, veredicto geral)",
        'h_risk': "Panorama de Risco",
        'h_risk_table': "| Indicador | Quantidade | Status |",
        'h_risk_table_desc': "(tabela com totais por tipo: IPs, URLs, Hashes, Repositorios e status geral)",
        'h_critical': "Ameacas Criticas",
        'h_critical_desc': "(lista priorizada dos achados CRITICAL/HIGH com contexto tecnico e impacto potencial)",
        'h_suspect': "Indicadores Suspeitos",
        'h_suspect_desc': "(achados MEDIUM/LOW que merecem atencao ou monitoramento)",
        'h_reco': "Recomendacoes",
        'h_reco_desc': "(acoes priorizadas: 1-imediatas, 2-curto prazo, 3-preventivas)",
        'h_triage_exec_desc': "(2-3 frases: repositorio analisado, total de achados, veredicto)",
        'h_triage_risk_table': "| Severidade | Quantidade |",
        'h_triage_risk_desc': "(tabela com contagem por severidade)",
        'h_top_risks': "Top Riscos Identificados",
        'h_top_risks_desc': "(ate 5 riscos mais criticos com contexto, impacto e recomendacao)",
        'h_prio_reco': "Recomendacoes Priorizadas",
        'h_prio_reco_desc': "(1-acoes imediatas, 2-curto prazo, 3-preventivas)",
    },
    'en_us': {
        'lang_rule': "MANDATORY: Respond ENTIRELY in English. NEVER use other languages.",
        'role_dossier': "You are a senior Threat Intelligence analyst writing an executive report.",
        'tone': "Tone: technical, formal, objective.",
        'lang_label': "Language: English.",
        'all_text_rule': "ALL text must be in English, no exceptions.",
        'role_triage': "You are a cybersecurity lead writing an Executive Summary for a repository audit.",
        'tone_triage': "Tone: technical, formal, direct.",
        'no_invent': "Use EXCLUSIVELY data from the dossier. Zero fabrication of IPs, URLs, hashes or findings.",
        'no_invent_triage': "Use EXCLUSIVELY the listed findings. Zero fabrication.",
        'prioritize': "Prioritize by severity (CRITICAL > HIGH > MEDIUM > LOW).",
        'each_risk': "Each risk must include: description, impact and recommended action.",
        'no_data': "If there is not enough data for a section, write 'No relevant indicators identified.'",
        'numbers_rule': "Numbers and metrics must come directly from the dossier.",
        'h_exec': "Executive Summary",
        'h_exec_desc': "(2-3 sentences: analysis scope, number of targets, overall verdict)",
        'h_risk': "Risk Overview",
        'h_risk_table': "| Indicator | Count | Status |",
        'h_risk_table_desc': "(table with totals by type: IPs, URLs, Hashes, Repositories and overall status)",
        'h_critical': "Critical Threats",
        'h_critical_desc': "(prioritized list of CRITICAL/HIGH findings with technical context and potential impact)",
        'h_suspect': "Suspicious Indicators",
        'h_suspect_desc': "(MEDIUM/LOW findings that warrant attention or monitoring)",
        'h_reco': "Recommendations",
        'h_reco_desc': "(prioritized actions: 1-immediate, 2-short term, 3-preventive)",
        'h_triage_exec_desc': "(2-3 sentences: repository analyzed, total findings, verdict)",
        'h_triage_risk_table': "| Severity | Count |",
        'h_triage_risk_desc': "(table with count by severity)",
        'h_top_risks': "Top Identified Risks",
        'h_top_risks_desc': "(up to 5 most critical risks with context, impact and recommendation)",
        'h_prio_reco': "Prioritized Recommendations",
        'h_prio_reco_desc': "(1-immediate actions, 2-short term, 3-preventive)",
    },
}


def _get_lang() -> str:
    try:
        config = configparser.ConfigParser()
        config.read(str(get_config_path()))
        return config.get('General', 'language', fallback='en_us')
    except Exception:
        return 'en_us'


def _get_lang_strings() -> Dict[str, str]:
    lang = _get_lang()
    return _LANG_INSTRUCTIONS.get(lang, _LANG_INSTRUCTIONS['en_us'])


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
    L = _get_lang_strings()
    prompt_template = (
        f"{L['lang_rule']}\n\n"
        f"{L['role_dossier']}\n"
        f"{L['tone']} {L['lang_label']}\n\n"
        "RULES:\n"
        f"- {L['all_text_rule']}\n"
        f"- {L['no_invent']}\n"
        f"- {L['no_data']}\n"
        f"- {L['numbers_rule']}\n\n"
        "FORMAT (strict Markdown):\n\n"
        f"## {L['h_exec']}\n"
        f"{L['h_exec_desc']}\n\n"
        f"### {L['h_risk']}\n"
        f"{L['h_risk_table']}\n"
        f"{L['h_risk_table_desc']}\n\n"
        f"### {L['h_critical']}\n"
        f"{L['h_critical_desc']}\n\n"
        f"### {L['h_suspect']}\n"
        f"{L['h_suspect_desc']}\n\n"
        f"### {L['h_reco']}\n"
        f"{L['h_reco_desc']}\n\n"
        f"```dossie\n{facts}\n```"
    )
    return prompt_template

def build_triage_prompt(all_findings: List[Dict[str, Any]], repo_url: str) -> str:
    if not all_findings:
        return ""

    severity_count: Dict[str, int] = {}
    type_count: Dict[str, int] = {}
    for f in all_findings:
        sev = f.get('severity', 'N/A')
        typ = f.get('type', 'N/A')
        severity_count[sev] = severity_count.get(sev, 0) + 1
        type_count[typ] = type_count.get(typ, 0) + 1

    stats = "Estatisticas:\n"
    for sev, count in sorted(severity_count.items()):
        stats += f"  {sev}: {count}\n"
    stats += "Tipos:\n"
    for typ, count in sorted(type_count.items()):
        stats += f"  {typ}: {count}\n"

    facts = f"Repositorio: {repo_url}\nTotal de achados: {len(all_findings)}\n\n{stats}\nAchados detalhados:\n"
    for finding in all_findings:
        desc = finding.get('description', 'N/A').replace('\n', ' ')
        facts += f"[{finding.get('severity', 'N/A')}] {finding.get('type', 'N/A')} | {finding.get('file', 'N/A')} | {desc}\n"

    L = _get_lang_strings()
    prompt_template = (
        f"{L['lang_rule']}\n\n"
        f"{L['role_triage']}\n"
        f"{L['tone_triage']} {L['lang_label']}\n\n"
        "RULES:\n"
        f"- {L['all_text_rule']}\n"
        f"- {L['no_invent_triage']}\n"
        f"- {L['prioritize']}\n"
        f"- {L['each_risk']}\n\n"
        "FORMAT (strict Markdown):\n\n"
        f"## {L['h_exec']}\n"
        f"{L['h_triage_exec_desc']}\n\n"
        f"### {L['h_risk']}\n"
        f"{L['h_triage_risk_table']}\n"
        f"{L['h_triage_risk_desc']}\n\n"
        f"### {L['h_top_risks']}\n"
        f"{L['h_top_risks_desc']}\n\n"
        f"### {L['h_prio_reco']}\n"
        f"{L['h_prio_reco_desc']}\n\n"
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
                    vt_malicious = safe_get(ioc, 'reputation.virustotal.data.attributes.last_analysis_stats.malicious', 0)
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
            vt = safe_get(results, 'virustotal.data.attributes.last_analysis_stats.malicious', 'N/A')
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
