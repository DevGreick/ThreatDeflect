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

from typing import Dict, Any, List
from threatdeflect.utils.utils import safe_get

def build_dossier_prompt(analysis_data: Dict[str, Any]) -> str:
    """
    Constrói o prompt detalhado para a IA com base nos resultados da análise.
    """
    facts = _generate_facts_from_data(analysis_data)
    
    prompt_template = (
        "Você é um analista de cibersegurança sênior e perito em Threat Intelligence. Sua tarefa é gerar um relatório técnico-executivo, exclusivamente em português do Brasil, com base no dossiê de análise fornecido. O formato de saída deve seguir RIGOROSAMENTE a estrutura e o estilo definidos abaixo. Não adicione seções, explicações ou saudações que não foram solicitadas.\n\n"
        "--- ESTRUTURA OBRIGATÓRIA DO RELATÓRIO ---\n\n"
        "### Tabela Resumo da Análise\n"
        "(Crie uma tabela em markdown resumindo os totais. Preencha com os dados reais do dossiê. Exemplo de formato):\n"
        "| Item | Resultado |\n"
        "|---|---|\n"
        "| Total de Repositórios analisados | 1 |\n"
        "| Total de IPs maliciosos (VT) | 3 |\n"
        "| Total de URLs maliciosas (VT) | 1 |\n"
        "| Achados Críticos (Segredos) | 2 |\n\n"
        "### 1. Ameaças Críticas\n"
        "(Descreva de forma objetiva e técnica os principais riscos identificados, agrupando por tipo: IPs maliciosos, segredos expostos, dependências vulneráveis, etc. Para cada achado, explique o impacto potencial e associe ao artefato. Exemplo: 'O IP 192.210.135.20 foi identificado como servidor de Comando e Controle (C&C) associado a campanhas de ransomware, representando risco de exfiltração de dados.')\n\n"
        "### 2. Comportamento Anômalo ou Suspeito\n"
        "(Detalhe outros comportamentos que, embora não diretamente maliciosos, são suspeitos e merecem investigação. Exemplos: port-scanning identificado no Shodan, uso de hooks perigosos em `package.json`, strings de alta entropia em código-fonte, URLs ofuscadas em Base64.)\n\n"
        "### 3. Recomendações / Próximos Passos\n"
        "(Crie uma tabela em markdown contendo o plano de ação. A tabela deve ter EXATAMENTE as seguintes colunas: `Ação`, `Responsável Sugerido`, `Prazo Sugerido`, `Justificativa / Objetivo`. Popule a tabela com ações claras, realistas e priorizadas. Siga o exemplo abaixo.)\n\n"
        "| Ação | Responsável Sugerido | Prazo Sugerido | Justificativa / Objetivo |\n"
        "|---|---|---|---|\n"
        "| Bloquear todos os IPs maliciosos nas ACLs do firewall (inbound/outbound). | Operações de Rede | Imediato | Prevenir comunicação ativa ou futura com infraestrutura maliciosa. |\n"
        "| Habilitar logging detalhado para todas as conexões de saída para os IPs identificados. | SOC | Imediato | Capturar evidências de comunicação, como tipo de tráfego (HTTP, DNS) e volume de dados. |\n"
        "| Investigar logs de endpoints (ex: EDR, Proxy) que se conectaram aos IPs. | TI/Forense | 48 horas | Identificar hosts potencialmente comprometidos e o escopo da intrusão. |\n\n"
        "> **Observação:** (Adicione uma nota final com considerações importantes ou ressalvas. Exemplo: 'Caso os IPs sejam usados para dependências legítimas, o bloqueio pode impactar a funcionalidade. Avaliar criticamente antes de aplicar um bloqueio permanente.')\n\n"
        f"--- INÍCIO DO DOSSIÊ TÉCNICO ---\n{facts}\n--- FIM DO DOSSIÊ TÉCNICO ---"
    )
    return prompt_template

def build_triage_prompt(all_findings: List[Dict[str, Any]], repo_url: str) -> str:
    """
    Constrói um prompt para a IA priorizar os achados e criar um resumo executivo.
    """
    if not all_findings:
        return ""

    facts = f"Análise do Repositório: {repo_url}\n\nLista de Achados Brutos:\n"
    for finding in all_findings:
        desc = finding.get('description', 'N/A').replace('\n', ' ')
        facts += f"- SEVERIDADE: {finding.get('severity', 'N/A')}, TIPO: {finding.get('type', 'N/A')}, ARQUIVO: {finding.get('file', 'N/A')}, DESCRIÇÃO: {desc}\n"

    prompt_template = (
        "Você é um líder de cibersegurança (Head of Cyber Security) encarregado de comunicar riscos para a gestão.\n"
        "Analise a lista de achados de segurança brutos de uma varredura de código a seguir. Sua tarefa é criar um **Resumo Executivo**.\n\n"
        "**Instruções:**\n"
        "1.  **Priorize:** Identifique os **3 riscos mais urgentes**. Considere o impacto no negócio (vazamento de dados, parada de serviço, comprometimento de contas) e a facilidade de exploração.\n"
        "2.  **Ignore o Ruído:** Ignore achados de baixa severidade ('LOW') ou em arquivos de teste (ex: `test/`, `spec.js`), a menos que representem um risco claro em combinação com outros achados.\n"
        "3.  **Seja Conciso e Direto:** Escreva em parágrafos curtos e em linguagem clara, evitando jargão técnico excessivo.\n"
        "4.  **Formato:** Inicie com um parágrafo de visão geral e depois liste os 3 principais riscos em formato de tópicos (bullet points), explicando o impacto de cada um.\n\n"
        "Exemplo de Resposta:\n"
        "A análise do repositório identificou várias vulnerabilidades críticas que exigem atenção imediata. Os riscos mais significativos envolvem a exposição direta de credenciais de produção e o uso de dependências de software conhecidamente maliciosas, que podem servir como um ponto de entrada para atacantes na nossa infraestrutura.\n\n"
        "- **Risco 1: Chave de Acesso da AWS Exposta:** Uma chave de acesso à nossa conta principal da AWS foi encontrada no arquivo `config/deploy.js`. Isso representa um risco CRÍTICO de acesso não autorizado aos nossos serviços em nuvem, podendo levar a vazamento massivo de dados e custos financeiros elevados.\n"
        "- **Risco 2: ...**\n"
        "- **Risco 3: ...**\n\n"
        f"--- INÍCIO DA LISTA DE ACHADOS BRUTOS ---\n{facts}\n--- FIM DA LISTA DE ACHADOS BRUTOS ---"
    )
    return prompt_template


def _generate_facts_from_data(analysis_data: Dict[str, Any]) -> str:
    facts = "Dossiê de Análise de Ameaças:\n\n"
    if repo_data := analysis_data.get('repositories', []):
        facts += f"**Análise de Repositórios ({len(repo_data)} total):**\n"
        for repo in repo_data:
            facts += f"- Repositório: {repo.get('url')}\n"
            facts += f"  - Nível de Risco Estático: {repo.get('risk_score', 0)}/100\n"
            if findings := repo.get('findings'):
                facts += "  - Achados (Findings):\n"
                for finding in findings:
                    facts += (f"    - [{finding.get('severity', 'N/A')}] {finding.get('description', 'N/A')} (Arquivo: {finding.get('file', 'N/A')})\n")
            if iocs := repo.get('extracted_iocs'):
                facts += "  - IOCs Ocultos (Base64) Encontrados:\n"
                for ioc in iocs:
                    vt_malicious = safe_get(ioc, 'reputation.virustotal.data.attributes.stats.malicious', 0)
                    facts += f"    - URL: '{ioc.get('ioc')}' no arquivo '{ioc.get('source_file')}' (Detecções VT: {vt_malicious})\n"
        facts += "\n"
    if ip_data := analysis_data.get('ips', {}):
        facts += f"**Análise de Endereços IP ({len(ip_data)} total):**\n"
        for ip, results in ip_data.items():
            vt_malicious = safe_get(results, 'virustotal.data.attributes.last_analysis_stats.malicious', 'N/A')
            abuse_score = safe_get(results, 'abuseipdb.data.abuseConfidenceScore', 'N/A')
            facts += f"- IP: {ip} | Detecções VT: {vt_malicious} | Score AbuseIPDB: {abuse_score}%\n"
        facts += "\n"
    if url_data := analysis_data.get('urls', {}):
        facts += f"**Análise de URLs ({len(url_data)} total):**\n"
        for url, results in url_data.items():
            vt_malicious = safe_get(results, 'virustotal.data.attributes.stats.malicious', 'N/A')
            uh_status = safe_get(results, 'urlhaus.url_status', 'N/A')
            facts += f"- URL: {url} | Detecções VT: {vt_malicious} | Status URLHaus: {uh_status}\n"
        facts += "\n"
    if file_data := analysis_data.get('files', {}):
        facts += f"**Análise de Arquivos ({len(file_data)} total):**\n"
        for f_hash, results in file_data.items():
            filename = results.get('filename', 'N/A')
            vt_malicious = safe_get(results, 'virustotal.data.attributes.last_analysis_stats.malicious', 'N/A')
            mb_threat = safe_get(results, 'malwarebazaar.data.0.signature', 'N/A')
            facts += f"- Arquivo: {filename} | Detecções VT: {vt_malicious} | Ameaça (MB): {mb_threat}\n"
        facts += "\n"
    
    return facts