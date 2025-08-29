# ThreatSpy
# Copyright (C) 2025  seczeror <seczeror.ocelot245@passmail.net>
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
import xlsxwriter
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from xlsxwriter.format import Format
from xlsxwriter.workbook import Workbook
from xlsxwriter.worksheet import Worksheet
from utils import defang_ioc, resource_path, safe_get


class ReportGenerator:
    """Gera relatórios em Excel e PDF a partir dos resultados da análise."""

    def __init__(self, ip_results: Dict, url_results: Dict, file_results: Dict = None, repo_results: List = None):
        self.ip_results = ip_results or {}
        self.url_results = url_results or {}
        self.file_results = file_results or {}
        self.repo_results = repo_results or []
        self.generation_time = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    # --- Geração de Excel ---

    def _setup_excel_formats(self, workbook: Workbook) -> Dict[str, Format]:
        """Cria e retorna um dicionário de formatos de célula para o Excel."""
        formats = {
            'header': workbook.add_format({'bold': True, 'font_color': 'white', 'bg_color': '#004B8B', 'border': 1, 'align': 'center', 'valign': 'vcenter'}),
            'cell': workbook.add_format({'border': 1, 'valign': 'top'}),
            'wrap': workbook.add_format({'border': 1, 'valign': 'top', 'text_wrap': True}),
            'score_crit': workbook.add_format({'bg_color': '#FF0000', 'font_color': 'white', 'border': 1, 'valign': 'top'}),
            'score_high': workbook.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006', 'border': 1, 'valign': 'top'}),
            'score_med': workbook.add_format({'bg_color': '#FFEB9C', 'font_color': '#9C6500', 'border': 1, 'valign': 'top'})
        }
        return formats

    def _write_repo_sheet(self, workbook: Workbook, formats: Dict[str, Format]) -> None:
        """Escreve os resultados da análise de repositório em uma nova planilha."""
        ws = workbook.add_worksheet("Relatório de Repositório")
        headers = ["Repositório URL", "Risco", "Achados Críticos", "Dependências", "IOCs Extraídos"]
        ws.write_row('A1', headers, formats['header'])
        ws.set_column('A:A', 50); ws.set_column('B:B', 10); ws.set_column('C:E', 45)

        for row_num, res in enumerate(self.repo_results, 2):
            score = res.get('risk_score', 0)
            score_format = formats['score_crit'] if score > 90 else (formats['score_high'] if score > 70 else (formats['score_med'] if score > 40 else formats['cell']))
            
            findings_str = "\n".join([f"[{f.get('severity')}] {f.get('description')} (em: {f.get('file')})" for f in res.get('findings', [])])
            deps_str = "\n".join([f"{file}: {', '.join(pkgs)}" for file, pkgs in res.get('dependencies', {}).items()])
            iocs_list = [f"- {defang_ioc(i.get('ioc'))} (VT: {safe_get(i, 'reputation.virustotal.data.attributes.stats.malicious', 0)})" for i in res.get('extracted_iocs', [])]

            ws.write(f'A{row_num}', res.get('url'), formats['cell'])
            ws.write(f'B{row_num}', f"{score}/100", score_format)
            ws.write(f'C{row_num}', findings_str or "Nenhum achado.", formats['wrap'])
            ws.write(f'D{row_num}', deps_str or "Nenhuma", formats['wrap'])
            ws.write(f'E{row_num}', "\n".join(iocs_list) or "Nenhum", formats['wrap'])

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
            ws.write(f'D{row_num}', vt_malicious if vt_malicious is not None else "Falha", formats['score_high'] if vt_malicious else formats['cell'])
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
            final_url = safe_get(results, 'virustotal.meta.url_info.url', url)
            url_hash = hashlib.sha256(final_url.encode('utf-8')).hexdigest()
            vt_malicious = safe_get(results, 'virustotal.data.attributes.stats.malicious')
            
            ws.write(f'A{row_num}', defang_ioc(url), formats['wrap'])
            ws.write(f'B{row_num}', f"https://www.virustotal.com/gui/url/{url_hash}", formats['cell'])
            ws.write(f'C{row_num}', vt_malicious if vt_malicious is not None else "Falha", formats['score_high'] if vt_malicious else formats['cell'])
            
            if uh := results.get('urlhaus'):
                if uh.get('query_status') == 'ok':
                    status = uh.get('url_status', 'not_found')
                    ws.write(f'D{row_num}', status, formats['score_high'] if status == 'online' else formats['cell'])
                    ws.write(f'E{row_num}', ", ".join(uh.get('tags', [])) or "N/A", formats['cell'])
                elif uh.get('query_status') == 'no_results': ws.write_row(f'D{row_num}', ['Não encontrado', 'N/A'], formats['cell'])
                else: ws.write_row(f'D{row_num}', ['Falha', 'N/A'], formats['cell'])

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
                if self.repo_results: self._write_repo_sheet(workbook, formats)
                if self.ip_results: self._write_ip_sheet(workbook, formats)
                if self.url_results: self._write_url_sheet(workbook, formats)
                if self.file_results: self._write_file_sheet(workbook, formats)
        except Exception as e:
            logging.error(f"Falha ao escrever o arquivo XLSX: {e}", exc_info=True)
            raise

    # --- Geração de PDF ---

    def _draw_footer(self, canvas: Any, doc: Any) -> None:
        """Desenha o rodapé em cada página do PDF."""
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.grey)
        canvas.line(doc.leftMargin, 0.7 * inch, doc.width + doc.leftMargin, 0.7 * inch)
        canvas.drawString(doc.leftMargin, 0.5 * inch, "Relatório ThreatSpy - CONFIDENCIAL")
        canvas.drawRightString(doc.width + doc.leftMargin, 0.5 * inch, f"Página {canvas.getPageNumber()} | Gerado em: {self.generation_time}")
        canvas.restoreState()

    def _setup_pdf_styles(self) -> Tuple[str, str, Dict[str, ParagraphStyle]]:
        """Registra fontes e cria estilos de parágrafo para o PDF."""
        font_name = 'DejaVuSans'
        font_name_bold = 'DejaVuSans-Bold'
        try:
            # Garante que a fonte que suporta Unicode (UTF-8) seja registrada
            pdfmetrics.registerFont(TTFont(font_name, resource_path('DejaVuSans.ttf')))
            pdfmetrics.registerFont(TTFont(font_name_bold, resource_path('DejaVuSans-Bold.ttf')))
            pdfmetrics.registerFontFamily(font_name, normal=font_name, bold=font_name_bold)
        except Exception:
            logging.error("FALHA CRÍTICA: Fontes DejaVuSans (DejaVuSans.ttf) não encontradas. O PDF pode ser gerado com caracteres incorretos. Garanta que os arquivos de fonte estejam na pasta do executável.")
            # Fallback para uma fonte padrão, mesmo que possa falhar com caracteres especiais
            font_name, font_name_bold = 'Helvetica', 'Helvetica-Bold'
        
        styles = getSampleStyleSheet()
        # Aplica a fonte correta a todos os estilos para garantir consistência
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
                # Garante que o marcador de lista seja renderizado corretamente
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
            data = [header] + [[
                Paragraph(defang_ioc(url), styles['TableCell']),
                Paragraph(str(safe_get(res, 'virustotal.data.attributes.stats.malicious', 'N/A')), styles['TableCell']),
                Paragraph(safe_get(res, 'urlhaus.url_status', 'N/A'), styles['TableCell'])
            ] for url, res in self.url_results.items()]
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
            
            story.extend([Spacer(1, 0.2 * inch), Paragraph("<b>Relatório Detalhado de Indicadores Analisados</b>", styles['h2']), Spacer(1, 0.1 * inch)])
            story.extend(self._build_ioc_tables_story(styles, font_name_bold))

            doc.build(story, onFirstPage=self._draw_footer, onLaterPages=self._draw_footer)
        except Exception as e:
            logging.error(f"Falha ao gerar o relatório em PDF: {e}", exc_info=True)
            raise
