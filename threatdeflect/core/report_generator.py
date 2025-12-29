# ===================================================================
# Módulo de Geração de Relatórios (report_generator.py)
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

import datetime
import hashlib
import logging
import re
from typing import Dict, Any, List, Tuple
from urllib.parse import quote
import xlsxwriter
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from xlsxwriter.format import Format
from xlsxwriter.workbook import Workbook
from xlsxwriter.worksheet import Worksheet

from threatdeflect.utils.utils import defang_ioc, resource_path, safe_get, detect_visual_spoofing


class ReportGenerator:
    """Gera relatórios em Excel e PDF a partir dos resultados da análise."""

    def __init__(self, ip_results: Dict = None, url_results: Dict = None, file_results: Dict = None, repo_results: List = None, executive_summary: str = ""):
        self.ip_results = ip_results or {}
        self.url_results = url_results or {}
        self.file_results = file_results or {}
        self.repo_results = repo_results or []
        self.executive_summary = executive_summary
        self.generation_time = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        all_urls_to_check = set(self.url_results.keys())
        for repo in self.repo_results:
            for ioc in repo.get('extracted_iocs', []):
                all_urls_to_check.add(ioc.get('ioc'))

        self.spoofing_warnings = {
            url: detect_visual_spoofing(url)
            for url in all_urls_to_check
            if url and detect_visual_spoofing(url)
        }

    def _setup_excel_formats(self, workbook: Workbook) -> Dict[str, Format]:
        """Cria e retorna um dicionário de formatos de célula para o Excel."""
        formats = {
            'header': workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#004B8B', 'border': 1, 'align': 'center', 'valign': 'vcenter'}),
            'cell': workbook.add_format({'border': 1, 'valign': 'top'}),
            'wrap': workbook.add_format({'border': 1, 'valign': 'top', 'text_wrap': True}),
            'title': workbook.add_format({'bold': True, 'font_size': 14, 'valign': 'top'}),
            'score_crit': workbook.add_format({'bg_color': '#FF0000', 'font_color': 'white', 'border': 1, 'valign': 'top'}),
            'score_high': workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006', 'border': 1, 'valign': 'top'}),
            'score_med': workbook.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C6500', 'border': 1, 'valign': 'top'}),
            'punycode_warn': workbook.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C6500', 'border': 1, 'valign': 'top', 'text_wrap': True, 'bold': True}),
            'warning_title': workbook.add_format({'bold': True, 'font_size': 12, 'font_color': '#9C0006', 'bg_color': '#FFC7CE'}),
        }
        return formats

    def _write_security_warnings_sheet(self, workbook: Workbook, formats: Dict[str, Format]) -> None:
        """Cria uma aba dedicada para avisos de segurança, como ataques de homograph e RTLO."""
        if not self.spoofing_warnings:
            return

        ws = workbook.add_worksheet("Avisos de Segurança")
        ws.set_column('A:A', 25); ws.set_column('B:B', 95)
        
        ws.merge_range('A1:B1', '⚠️ Avisos de Segurança de Spoofing Visual', formats['warning_title'])
        explanation_format = workbook.add_format({'valign': 'top', 'text_wrap': True, 'border': 1})
        header_format = formats['header']

        row = 2
        if any(v == "Punycode/Cyrillic" for v in self.spoofing_warnings.values()):
            ws.merge_range(f'A{row}:B{row}', 'Risco: Ataque de Homograph (Punycode/Cirílico)', header_format)
            row += 1
            explanation_text = (
                "As URLs abaixo usam caracteres não-padrão (cirílicos) ou Punycode ('xn--'). "
                "Isso pode ser uma tentativa de ataque de homograph, onde uma URL maliciosa se parece com uma legítima para enganar usuários. "
                "Ex: 'microsоft.com' (com 'о' cirílico) vs. 'microsoft.com'."
            )
            ws.set_row(row - 1, 70)
            ws.merge_range(f'A{row}:B{row}', explanation_text, explanation_format)
            row += 1

        if any(v == "RTLO" for v in self.spoofing_warnings.values()):
            ws.merge_range(f'A{row}:B{row}', 'Risco: Ofuscação com Right-to-Left Override (RTLO)', header_format)
            row += 1
            explanation_text_rtlo = (
                "As URLs/nomes de arquivo abaixo usam o caractere de controle Unicode RTLO (U+202E). "
                "Este caractere invisível inverte o texto que o segue, sendo uma técnica comum para mascarar a extensão real de arquivos maliciosos. "
                "Ex: 'fatura_gpj<RTLO>.exe' pode ser exibido como 'fatura_exe.jpg'."
            )
            ws.set_row(row - 1, 70)
            ws.merge_range(f'A{row}:B{row}', explanation_text_rtlo, explanation_format)
            row += 2

        ws.write(f'A{row}', 'Tipo de Alerta', header_format)
        ws.write(f'B{row}', 'URL/IOC Suspeito', header_format)
        row += 1

        for url, warning_type in self.spoofing_warnings.items():
            ws.write(f'A{row}', warning_type, formats['cell'])
            ws.write(f'B{row}', defang_ioc(url), formats['cell'])
            row += 1

    def _write_executive_summary_sheet(self, workbook: Workbook, formats: Dict[str, Format]) -> None:
        """Escreve o Resumo Executivo gerado pela IA em uma nova planilha."""
        ws = workbook.add_worksheet("Resumo Executivo")
        ws.set_column('A:A', 120)
        ws.set_default_row(15)
        
        ws.write('A1', "Resumo Executivo (Análise de Riscos Prioritários por IA)", formats['header'])
        
        summary_format = workbook.add_format({'valign': 'top', 'text_wrap': True})
        
        num_lines = self.executive_summary.count('\n') + 15
        ws.set_row(1, num_lines * 10 if num_lines > 15 else 200)

        ws.write('A2', self.executive_summary, summary_format)

    def _write_repo_summary_sheet(self, workbook: Workbook, formats: Dict[str, Format]) -> None:
        """Escreve uma planilha de resumo para os repositórios analisados."""
        ws = workbook.add_worksheet("Repo - Resumo")
        headers = ["Repositório URL", "Risco"]
        ws.write_row('A1', headers, formats['header'])
        ws.set_column('A:A', 60); ws.set_column('B:B', 15)

        for row_num, res in enumerate(self.repo_results, 2):
            score = res.get('risk_score', 0)
            score_format = formats['score_crit'] if score > 90 else (formats['score_high'] if score > 70 else (formats['score_med'] if score > 40 else formats['cell']))
            ws.write(f'A{row_num}', res.get('url'), formats['cell'])
            ws.write(f'B{row_num}', f"{score}/100", score_format)

    def _write_repo_findings_sheet(self, workbook: Workbook, formats: Dict[str, Format]) -> None:
        """Escreve os achados de segurança dos repositórios em uma planilha."""
        ws = workbook.add_worksheet("Repo - Achados")
        headers = ["Repositório URL", "Severidade", "Descrição", "Tipo do Achado", "Arquivo"]
        ws.write_row('A1', headers, formats['header'])
        ws.set_column('A:A', 60); ws.set_column('B:B', 15); ws.set_column('C:C', 50); ws.set_column('D:D', 30); ws.set_column('E:E', 50)

        row_num = 2
        for res in self.repo_results:
            repo_url = res.get('url')
            if not res.get('findings'):
                ws.write(f'A{row_num}', repo_url, formats['cell'])
                ws.write_row(f'B{row_num}', ["Nenhum achado", "-", "-", "-"], formats['cell'])
                row_num += 1
                continue

            for finding in res.get('findings', []):
                severity = finding.get('severity', 'N/A')
                sev_format = formats['cell']
                if severity == 'CRITICAL': sev_format = formats['score_crit']
                elif severity == 'HIGH': sev_format = formats['score_high']
                elif severity == 'MEDIUM': sev_format = formats['score_med']
                
                ws.write(f'A{row_num}', repo_url, formats['cell'])
                ws.write(f'B{row_num}', severity, sev_format)
                ws.write(f'C{row_num}', finding.get('description'), formats['wrap'])
                ws.write(f'D{row_num}', finding.get('type'), formats['wrap'])
                ws.write(f'E{row_num}', finding.get('file'), formats['wrap'])
                row_num += 1

    def _write_repo_dependencies_sheet(self, workbook: Workbook, formats: Dict[str, Format]) -> None:
        """Escreve as dependências encontradas nos repositórios em uma planilha."""
        ws = workbook.add_worksheet("Repo - Dependências")
        headers = ["Repositório URL", "Arquivo de Dependência", "Pacote"]
        ws.write_row('A1', headers, formats['header'])
        ws.set_column('A:A', 60); ws.set_column('B:B', 30); ws.set_column('C:C', 40)

        row_num = 2; has_deps = False
        for res in self.repo_results:
            if res.get('dependencies'):
                has_deps = True
                repo_url = res.get('url')
                for file, packages in res.get('dependencies', {}).items():
                    for package in packages:
                        ws.write(f'A{row_num}', repo_url, formats['cell'])
                        ws.write(f'B{row_num}', file, formats['cell'])
                        ws.write(f'C{row_num}', package, formats['wrap'])
                        row_num += 1
        if not has_deps:
            ws.write('A2', "Nenhuma dependência encontrada nos repositórios analisados.", formats['cell'])

    def _write_repo_iocs_sheet(self, workbook: Workbook, formats: Dict[str, Format]) -> None:
        """Escreve os IOCs extraídos dos repositórios em uma planilha."""
        ws = workbook.add_worksheet("Repo - IOCs Extraídos")
        headers = ["Repositório URL", "IOC", "Arquivo de Origem", "Detecções VT"]
        ws.write_row('A1', headers, formats['header'])
        ws.set_column('A:A', 60); ws.set_column('B:B', 60); ws.set_column('C:C', 50); ws.set_column('D:D', 15)

        row_num = 2; has_iocs = False
        for res in self.repo_results:
            if res.get('extracted_iocs'):
                has_iocs = True
                repo_url = res.get('url')
                for ioc in res.get('extracted_iocs', []):
                    ioc_string = ioc.get('ioc')
                    vt_malicious = safe_get(ioc, 'reputation.virustotal.data.attributes.stats.malicious')
                    vt_malicious_count = vt_malicious if vt_malicious is not None else "N/A"
                    
                    score_format = formats['cell']
                    if vt_malicious is not None and vt_malicious > 0:
                        score_format = formats['score_high']

                    ws.write(f'A{row_num}', repo_url, formats['cell'])
                    
                    if warning_type := self.spoofing_warnings.get(ioc_string):
                        text_to_write = f"⚠️ ALERTA ({warning_type}): {defang_ioc(ioc_string)}"
                        ws.write(f'B{row_num}', text_to_write, formats['punycode_warn'])
                    else:
                        ws.write(f'B{row_num}', defang_ioc(ioc_string), formats['wrap'])

                    ws.write(f'C{row_num}', ioc.get('source_file'), formats['wrap'])
                    ws.write(f'D{row_num}', vt_malicious_count, score_format)
                    row_num += 1
        if not has_iocs:
            ws.write('A2', "Nenhum IOC extraído dos repositórios analisados.", formats['cell'])

    def _write_ip_sheet(self, workbook: Workbook, formats: Dict[str, Format]) -> None:
        """Escreve os resultados da análise de IP em uma nova planilha."""
        ws = workbook.add_worksheet("Relatório de IPs")
        headers = ["IP", "VT Link", "AbuseIPDB Link", "VT Detecções", "AbuseIPDB Score", "País", "Provedor", "Shodan Portas", "Shodan Organização", "Shodan Hostnames", "Shodan CVEs"]
        ws.write_row('A1', headers, formats['header'])
        ws.set_column('A:A', 20); ws.set_column('B:C', 50); ws.set_column('D:F', 15); ws.set_column('G:G', 30); ws.set_column('H:H', 20); ws.set_column('I:K', 35)

        for row_num, (ip, results) in enumerate(self.ip_results.items(), 2):
            ws.write(f'A{row_num}', defang_ioc(ip), formats['cell'])
            ws.write(f'B{row_num}', f'https://www.virustotal.com/gui/ip-address/{ip}', formats['cell'])
            ws.write(f'C{row_num}', f'https://www.abuseipdb.com/check/{ip}', formats['cell'])
            
            vt_malicious = safe_get(results, 'virustotal.data.attributes.last_analysis_stats.malicious')
            ws.write(f'D{row_num}', vt_malicious if vt_malicious is not None else "Falha", formats['score_high'] if vt_malicious and vt_malicious > 0 else formats['cell'])
            ws.write(f'G{row_num}', safe_get(results, 'virustotal.data.attributes.as_owner', 'N/A'), formats['cell'])
            
            abuse_score = safe_get(results, 'abuseipdb.data.abuseConfidenceScore')
            score_format = formats['score_high'] if abuse_score and abuse_score >= 90 else (formats['score_med'] if abuse_score and abuse_score >= 50 else formats['cell'])
            ws.write(f'E{row_num}', abuse_score if abuse_score is not None else "Falha", score_format)
            ws.write(f'F{row_num}', safe_get(results, 'abuseipdb.data.countryCode', 'N/A'), formats['cell'])

            if shodan := results.get('shodan'):
                if shodan.get('error') == 'Not Found': ws.write_row(f'H{row_num}', ['Não encontrado'] * 4, formats['cell'])
                elif shodan.get('error'): ws.write_row(f'H{row_num}', ['Falha'] * 4, formats['cell'])
                else:
                    ws.write(f'H{row_num}', ", ".join(map(str, shodan.get('ports', []))), formats['wrap'])
                    ws.write(f'I{row_num}', shodan.get('org', 'N/A'), formats['wrap'])
                    ws.write(f'J{row_num}', ", ".join(defang_ioc(h) for h in shodan.get('hostnames', [])), formats['wrap'])
                    ws.write(f'K{row_num}', ", ".join(shodan.get('vulns', [])) or "Nenhuma", formats['wrap'])

    def _write_url_sheet(self, workbook: Workbook, formats: Dict[str, Format]) -> None:
        """Escreve os resultados da análise de URL em uma nova planilha."""
        ws = workbook.add_worksheet("Relatório de URLs")
        headers = ["URL", "VT Link", "VT Detecções", "URLHaus Status", "URLHaus Tags"]
        ws.write_row('A1', headers, formats['header'])
        ws.set_column('A:A', 60); ws.set_column('B:B', 65); ws.set_column('C:E', 25)

        for row_num, (url, results) in enumerate(self.url_results.items(), 2):
            
            vt_id = safe_get(results, 'virustotal.data.id')

            if vt_id and isinstance(vt_id, str) and vt_id.startswith('u-'):
                parts = vt_id.split('-')
                if len(parts) > 1:
                    vt_id = parts[1] 

            if vt_id:
                vt_link = f"https://www.virustotal.com/gui/url/{vt_id}"
            else:
                try:
                    encoded_url = quote(url, safe='')
                    vt_link = f"https://www.virustotal.com/gui/search/{encoded_url}"
                except Exception:
                    vt_link = f"https://www.virustotal.com/gui/domain/{url}"

            vt_malicious = safe_get(results, 'virustotal.data.attributes.last_analysis_stats.malicious')
            
            if vt_malicious is None:
                vt_malicious = safe_get(results, 'virustotal.data.attributes.stats.malicious')

            
            if warning_type := self.spoofing_warnings.get(url):
                text_to_write = f"⚠️ ALERTA ({warning_type}): {defang_ioc(url)}"
                ws.write(f'A{row_num}', text_to_write, formats['punycode_warn'])
            else:
                ws.write(f'A{row_num}', defang_ioc(url), formats['wrap'])
            
            ws.write(f'B{row_num}', vt_link, formats['cell'])
            
            if vt_malicious is not None:
                style = formats['score_high'] if vt_malicious > 0 else formats['cell']
                ws.write(f'C{row_num}', vt_malicious, style)
            else:
                ws.write(f'C{row_num}', "Falha", formats['cell'])
            
            if uh := results.get('urlhaus'):
                status = uh.get('url_status', 'N/A')
                if uh.get('query_status') == 'ok':
                    ws.write(f'D{row_num}', status, formats['score_high'] if status == 'online' else formats['cell'])
                    ws.write(f'E{row_num}', ", ".join(uh.get('tags', [])) or "N/A", formats['cell'])
                elif uh.get('query_status') == 'no_results': 
                    ws.write_row(f'D{row_num}', ['Não encontrado', 'N/A'], formats['cell'])
                else: 
                    ws.write_row(f'D{row_num}', ['Falha', 'N/A'], formats['cell'])

    def _write_file_sheet(self, workbook: Workbook, formats: Dict[str, Format]) -> None:
        """Escreve os resultados da análise de arquivo em uma nova planilha."""
        ws = workbook.add_worksheet("Relatório de Arquivos")
        headers = ["Arquivo Original", "SHA256", "VT Link", "VT Detecções", "MB Nome da Ameaça", "Tipo (TrID)", "Tamanho (Bytes)"]
        ws.write_row('A1', headers, formats['header'])
        ws.set_column('A:A', 30); ws.set_column('B:B', 65); ws.set_column('C:C', 65); ws.set_column('D:G', 20)
        
        for row_num, (f_hash, results) in enumerate(self.file_results.items(), 2):
            ws.write(f'A{row_num}', results.get('filename', 'N/A'), formats['cell'])
            ws.write(f'B{row_num}', f_hash, formats['cell'])
            ws.write(f'C{row_num}', f'https://www.virustotal.com/gui/file/{f_hash}', formats['cell'])
            
            vt_malicious = safe_get(results, 'virustotal.data.attributes.last_analysis_stats.malicious')
            if safe_get(results, 'virustotal.error') == 'Not Found':
                ws.write(f'D{row_num}', 'Não encontrado', formats['cell'])
                ws.write_row(f'F{row_num}', ['N/A'] * 2, formats['cell'])
            elif vt_malicious is not None:
                ws.write(f'D{row_num}', vt_malicious, formats['score_high'] if vt_malicious > 0 else formats['cell'])
                ws.write(f'F{row_num}', safe_get(results, 'virustotal.data.attributes.trid.0.file_type', 'N/A'), formats['wrap'])
                ws.write(f'G{row_num}', safe_get(results, 'virustotal.data.attributes.size', 'N/A'), formats['wrap'])
            else:
                ws.write(f'D{row_num}', 'Falha', formats['cell'])
                ws.write_row(f'F{row_num}', ['N/A'] * 2, formats['cell'])

            mb_status = safe_get(results, 'malwarebazaar.query_status')
            if mb_status == 'ok':
                threat_name = safe_get(results, 'malwarebazaar.data.0.signature')
                ws.write(f'E{row_num}', threat_name, formats['score_high'] if threat_name else formats['cell'])
            elif mb_status == 'hash_not_found': ws.write(f'E{row_num}', 'Não encontrado', formats['cell'])
            else: ws.write(f'E{row_num}', 'Falha', formats['cell'])

    def generate_excel(self, filepath: str) -> None:
        """Gera um relatório Excel completo com múltiplas planilhas."""
        try:
            with xlsxwriter.Workbook(filepath) as workbook:
                formats = self._setup_excel_formats(workbook)
                
                if self.executive_summary:
                    self._write_executive_summary_sheet(workbook, formats)
                
                self._write_security_warnings_sheet(workbook, formats)

                if self.repo_results:
                    self._write_repo_summary_sheet(workbook, formats)
                    self._write_repo_findings_sheet(workbook, formats)
                    self._write_repo_dependencies_sheet(workbook, formats)
                    self._write_repo_iocs_sheet(workbook, formats)
                
                if self.ip_results: self._write_ip_sheet(workbook, formats)
                if self.url_results: self._write_url_sheet(workbook, formats)
                if self.file_results: self._write_file_sheet(workbook, formats)
        except Exception as e:
            logging.error(f"Falha ao escrever o arquivo XLSX: {e}", exc_info=True)
            raise

    def _draw_footer(self, canvas: Any, doc: Any) -> None:
        """Desenha o rodapé em cada página do PDF."""
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.grey)
        canvas.line(doc.leftMargin, 0.7 * inch, doc.width + doc.leftMargin, 0.7 * inch)
        canvas.drawString(doc.leftMargin, 0.5 * inch, "Relatório ThreatDeflect - CONFIDENCIAL")
        canvas.drawRightString(doc.width + doc.leftMargin, 0.5 * inch, f"Página {canvas.getPageNumber()} | Gerado em: {self.generation_time}")
        canvas.restoreState()

    def _setup_pdf_styles(self) -> Tuple[str, str, Dict[str, ParagraphStyle]]:
        """Registra fontes e cria estilos de parágrafo para o PDF."""
        font_name = 'DejaVuSans'
        font_name_bold = 'DejaVuSans-Bold'
        try:
            pdfmetrics.registerFont(TTFont(font_name, resource_path('DejaVuSans.ttf')))
            pdfmetrics.registerFont(TTFont(font_name_bold, resource_path('DejaVuSans-Bold.ttf')))
            pdfmetrics.registerFontFamily(font_name, normal=font_name, bold=font_name_bold)
        except Exception:
            logging.error("FALHA CRÍTICA: Fontes DejaVuSans não encontradas. O PDF pode ser gerado com caracteres incorretos.")
            font_name, font_name_bold = 'Helvetica', 'Helvetica-Bold'
        
        styles = getSampleStyleSheet()
        styles['Normal'].fontName = font_name
        styles['BodyText'].fontName = font_name
        styles['h1'].fontName = font_name_bold
        styles['h2'].fontName = font_name_bold
        styles['h3'].fontName = font_name_bold
        
        styles.add(ParagraphStyle(name='Justify', parent=styles['Normal'], alignment=TA_JUSTIFY))
        styles.add(ParagraphStyle(name='TableCell', parent=styles['Normal'], fontSize=8, leading=10))
        styles.add(ParagraphStyle(name='TableCellBold', fontName=font_name_bold, fontSize=8, leading=10, textColor=colors.white))

        return font_name, font_name_bold, styles

    def _build_ai_summary_story(self, summary_text: str, styles: Dict) -> List:
        """Converte o texto do resumo da IA (incluindo markdown) em objetos do ReportLab."""
        story = []
        if not summary_text or summary_text.strip().lower().startswith(("erro:", "falha:", "não foi possível")):
            error_style = ParagraphStyle(name='ErrorStyle', parent=styles['Normal'], textColor=colors.red)
            story.append(Paragraph(summary_text or "A IA não retornou uma resposta.", error_style))
            return story

        lines = summary_text.replace('<br>', '<br/>').split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('|') and line.endswith('|'):
                table_data, table_lines = [], []
                while i < len(lines) and lines[i].strip().startswith('|'):
                    table_lines.append(lines[i].strip())
                    i += 1
                for idx, t_line in enumerate(table_lines):
                    if re.match(r'^[|: -]+$', t_line): continue
                    style = styles['TableCellBold'] if idx == 0 else styles['TableCell']
                    cells = [Paragraph(re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', cell.strip()), style) for cell in t_line.strip('|').split('|')]
                    table_data.append(cells)
                if table_data:
                    pdf_table = Table(table_data, hAlign='LEFT', repeatRows=1)
                    pdf_table.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.navy), ('GRID', (0,0), (-1,-1), 1, colors.black)]))
                    story.append(pdf_table)
                    story.append(Spacer(1, 0.2 * inch))
                continue

            line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
            if line.startswith('### '): story.append(Paragraph(line.lstrip('# ').strip(), styles['h3']))
            elif line.startswith('## '): story.append(Paragraph(line.lstrip('# ').strip(), styles['h2']))
            elif line.startswith(('-', '•')) or re.match(r'^[0-9]+\.', line):
                p_text = f"•&nbsp;&nbsp;{re.sub(r'^[0-9-•.]+\s*', '', line)}"
                story.append(Paragraph(p_text, styles['Justify']))
            elif line: story.append(Paragraph(line, styles['Justify']))
            else: story.append(Spacer(1, 0.1 * inch))
            i += 1
        return story

    def _build_ioc_tables_story(self, styles: Dict, font_name_bold: str) -> List:
        """Constrói as tabelas detalhadas de IOCs para o relatório PDF."""
        story = []
        style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.navy), ('TEXTCOLOR',(0,0),(-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'), ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('FONTNAME', (0,0), (-1,0), font_name_bold), ('FONTSIZE', (0,0), (-1,0), 9),
            ('BOTTOMPADDING', (0,0), (-1,0), 10), ('BACKGROUND', (0,1), (-1,-1), colors.whitesmoke),
            ('GRID', (0,0), (-1,-1), 1, colors.lightgrey), ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.whitesmoke, (0.9,0.9,0.9)])
        ])

        if self.ip_results:
            story.extend([Paragraph("<b>IPs Analisados</b>", styles['h3']), Spacer(1, 0.1*inch)])
            header = [Paragraph(h, styles['TableCellBold']) for h in ['IP', 'VT Det.', 'Abuse Score', 'País', 'Provedor']]
            data = [header] + [[
                Paragraph(defang_ioc(ip), styles['TableCell']),
                Paragraph(str(safe_get(res, 'virustotal.data.attributes.last_analysis_stats.malicious', 'N/A')), styles['TableCell']),
                Paragraph(str(safe_get(res, 'abuseipdb.data.abuseConfidenceScore', 'N/A')), styles['TableCell']),
                Paragraph(safe_get(res, 'abuseipdb.data.countryCode', 'N/A'), styles['TableCell']),
                Paragraph(safe_get(res, 'virustotal.data.attributes.as_owner', 'N/A'), styles['TableCell'])
            ] for ip, res in self.ip_results.items()]
            table = Table(data, colWidths=[1.2*inch, 0.6*inch, 0.8*inch, 0.5*inch, 3*inch], hAlign='LEFT'); table.setStyle(style)
            story.extend([table, Spacer(1, 0.2*inch)])

        if self.url_results:
            story.extend([Paragraph("<b>URLs Analisadas</b>", styles['h3']), Spacer(1, 0.1*inch)])
            header = [Paragraph(h, styles['TableCellBold']) for h in ['URL', 'VT Det.', 'URLHaus']]
            data = [header]
            for url, res in self.url_results.items():
                url_text = defang_ioc(url)
                if warning_type := self.spoofing_warnings.get(url):
                    url_text = f"⚠️ ({warning_type}) {url_text}"
                
                row = [
                    Paragraph(url_text, styles['TableCell']),
                    Paragraph(str(safe_get(res, 'virustotal.data.attributes.stats.malicious', 'N/A')), styles['TableCell']),
                    Paragraph(safe_get(res, 'urlhaus.url_status', 'N/A'), styles['TableCell'])
                ]
                data.append(row)
            
            table = Table(data, colWidths=[5.4*inch, 0.7*inch, 0.9*inch], hAlign='LEFT'); table.setStyle(style)
            story.extend([table, Spacer(1, 0.2*inch)])

        if self.file_results:
            story.extend([Paragraph("<b>Arquivos Analisados</b>", styles['h3']), Spacer(1, 0.1*inch)])
            header = [Paragraph(h, styles['TableCellBold']) for h in ['Arquivo', 'SHA256', 'VT Det.', 'Ameaça (MB)']]
            data = [header] + [[
                Paragraph(defang_ioc(res.get('filename', 'N/A')), styles['TableCell']),
                Paragraph(f'{f_hash[:20]}...', styles['TableCell']),
                Paragraph(str(safe_get(res, 'virustotal.data.attributes.last_analysis_stats.malicious', 'N/A')), styles['TableCell']),
                Paragraph(safe_get(res, 'malwarebazaar.data.0.signature', 'N/A'), styles['TableCell'])
            ] for f_hash, res in self.file_results.items()]
            table = Table(data, colWidths=[2.3*inch, 2.3*inch, 0.7*inch, 1.7*inch], hAlign='LEFT'); table.setStyle(style)
            story.extend([table, Spacer(1, 0.2*inch)])
        
        return story
    def _build_security_warnings_story(self, styles: Dict) -> List:
    
        """Constrói uma seção de aviso de segurança para o PDF se URLs suspeitas forem encontradas."""
        if not self.spoofing_warnings:
            return []

        story = [
            PageBreak(),
            Paragraph("⚠️ Avisos de Segurança Importantes", styles['h2']),
            Spacer(1, 0.2 * inch),
        ]

        if any(v == "Punycode/Cyrillic" for v in self.spoofing_warnings.values()):
            story.extend([
                Paragraph("<b>Risco Potencial de Ataque de Homograph (Punycode/Cirílico)</b>", styles['h3']),
                Paragraph("As URLs abaixo usam caracteres não-padrão (cirílicos) ou Punycode ('xn--'). Esta é uma técnica comum para criar URLs maliciosas que se parecem com domínios legítimos.", styles['Justify']),
                Spacer(1, 0.1 * inch)
            ])

        if any(v == "RTLO" for v in self.spoofing_warnings.values()):
            story.extend([
                Paragraph("<b>Risco Potencial de Ofuscação com Right-to-Left Override (RTLO)</b>", styles['h3']),
                Paragraph("As URLs/nomes de arquivo abaixo usam o caractere de controle Unicode RTLO (U+202E), que inverte o texto para mascarar a extensão real de um arquivo (ex: 'fatura_exe.jpg' pode ser um '.exe').", styles['Justify']),
                Spacer(1, 0.1 * inch)
            ])
        
        for url, warning_type in self.spoofing_warnings.items():
            story.append(Paragraph(f"•&nbsp;&nbsp;<b>[{warning_type}]</b>: {defang_ioc(url)}", styles['Normal']))
            
        story.append(Spacer(1, 0.3 * inch))
        return story

    def generate_pdf_summary(self, filepath: str, summary_text: str) -> None:
        """Gera um resumo em PDF incluindo a análise da IA e as tabelas de IOCs."""
        try:
            doc = SimpleDocTemplate(filepath, topMargin=0.5 * inch, bottomMargin=0.8 * inch)
            _, font_name_bold, styles = self._setup_pdf_styles()
            
            story = []
            title = Paragraph("<b>Análise Técnica Resumida – Multi-API</b>", styles['h1'])
            title.alignment = TA_CENTER
            story.extend([title, Spacer(1, 0.2 * inch)])

            story.extend([Paragraph("<b>Resumo da Análise (IA)</b>", styles['h2']), Spacer(1, 0.1 * inch)])
            story.extend(self._build_ai_summary_story(summary_text, styles))
            
            story.extend(self._build_security_warnings_story(styles))
            
            story.extend([PageBreak(), Paragraph("<b>Relatório Detalhado de Indicadores Analisados</b>", styles['h2']), Spacer(1, 0.1 * inch)])

            if self.repo_results:
                story.extend(self._build_repo_table_story(styles, font_name_bold))
            else:
                story.extend(self._build_ioc_tables_story(styles, font_name_bold))

            doc.build(story, onFirstPage=self._draw_footer, onLaterPages=self._draw_footer)
        except Exception as e:
            logging.error(f"Falha ao gerar o relatório em PDF: {e}", exc_info=True)
            raise
            
    def _build_repo_table_story(self, styles: Dict, font_name_bold: str) -> List:
        """Constrói a tabela de Repositórios para o relatório PDF, com um achado por linha."""
        story = []
        style = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.navy), ('TEXTCOLOR',(0,0),(-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'), ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,0), (-1,0), font_name_bold), ('FONTSIZE', (0,0), (-1,0), 9),
            ('BOTTOMPADDING', (0,0), (-1,0), 10), ('BACKGROUND', (0,1), (-1,-1), colors.whitesmoke),
            ('GRID', (0,0), (-1,-1), 1, colors.lightgrey)
        ])

        if not self.repo_results:
            return story

        story.extend([Paragraph("<b>Repositórios Analisados - Achados de Segurança</b>", styles['h3']), Spacer(1, 0.1*inch)])
        header = [Paragraph(h, styles['TableCellBold']) for h in ['Repositório', 'Risco', 'Severidade', 'Descrição do Achado', 'Arquivo']]
        
        table_data = [header]
        
        for res in self.repo_results:
            repo_url = res.get('url', 'N/A')
            risk_score = f"<b>{res.get('risk_score', 0)}/100</b>"
            findings_list = res.get('findings', [])

            if not findings_list:
                row = [
                    Paragraph(defang_ioc(repo_url), styles['TableCell']),
                    Paragraph(risk_score, styles['TableCell']),
                    Paragraph("Nenhum achado", styles['TableCell']),
                    Paragraph("-", styles['TableCell']),
                    Paragraph("-", styles['TableCell'])
                ]
                table_data.append(row)
                continue

            for finding in findings_list:
                severity = finding.get('severity', 'N/A')
                severity_color_map = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "#B8860B"}
                severity_color = severity_color_map.get(severity, "black")

                row = [
                    Paragraph(defang_ioc(repo_url), styles['TableCell']),
                    Paragraph(risk_score, styles['TableCell']),
                    Paragraph(f"<font color='{severity_color}'>{severity}</font>", styles['TableCell']),
                    Paragraph(finding.get('description', 'N/A'), styles['TableCell']),
                    Paragraph(f"<i>{finding.get('file', 'N/A')}</i>", styles['TableCell'])
                ]
                table_data.append(row)

        table = Table(table_data, colWidths=[2.0*inch, 0.6*inch, 0.8*inch, 2.3*inch, 1.3*inch], hAlign='LEFT', repeatRows=1)
        table.setStyle(style)
        story.extend([table, Spacer(1, 0.2*inch)])
            
        return story