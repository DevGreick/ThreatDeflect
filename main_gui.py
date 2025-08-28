# ThreatSpy
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

import sys
import os
import time
import logging
import configparser
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

import keyring
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon, QFont, QPixmap, QPalette, QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QPlainTextEdit, QLabel, QTabWidget, QComboBox,
    QFileDialog, QMessageBox, QProgressDialog, QDialog, QLineEdit,
    QFormLayout, QTextEdit, QStatusBar
)

from api_client import ApiClient
from report_generator import ReportGenerator
from repository_analyzer import RepositoryAnalyzer
from utils import (
    parse_targets, calculate_sha256, resource_path, parse_repo_urls,
    is_file_writable, safe_get, get_config_path
)


def setup_logging() -> None:
    log_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(message)s'
    )
    log_file_path = Path.home() / 'threatspy.log'
    file_handler = logging.FileHandler(log_file_path, mode='a', encoding='utf-8')
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


class AnalysisWorker(QThread):
    finished = Signal(bool, str)
    log_message = Signal(str)
    progress_update = Signal(int, int)
    
    def __init__(self, text_to_analyze: str, filepath: str) -> None:
        super().__init__()
        self.text_to_analyze = text_to_analyze
        self.filepath = filepath
        self.results: Optional[Dict[str, Any]] = None

    def run(self) -> None:
        try:
            api_client = ApiClient()
            ips, urls = parse_targets(self.text_to_analyze)
            if not ips and not urls:
                self.finished.emit(False, "NO_TARGETS")
                return

            all_ip_results, all_url_results = {}, {}
            total_targets = len(ips) + len(urls)
            processed_count = 0
            self.progress_update.emit(0, total_targets)

            with ThreadPoolExecutor(max_workers=10) as executor:
                self.log_message.emit(f"Enviando {len(ips)} IPs para análise paralela...")
                future_to_ip = {executor.submit(api_client.check_ip_multi, ip): ip for ip in ips}
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        all_ip_results[ip] = future.result()
                        self.log_message.emit(f"Resultados para o IP {ip} recebidos.")
                    except Exception as exc:
                        logging.error(f"Erro ao processar o IP {ip}: {exc}", exc_info=True)
                    processed_count += 1
                    self.progress_update.emit(processed_count, total_targets)

                self.log_message.emit(f"Enviando {len(urls)} URLs para análise paralela...")
                future_to_url = {executor.submit(api_client.check_url_multi, url): url for url in urls}
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        all_url_results[url] = future.result()
                        self.log_message.emit(f"Resultados para a URL {url} recebidos.")
                    except Exception as exc:
                        logging.error(f"Erro ao processar a URL {url}: {exc}", exc_info=True)
                    processed_count += 1
                    self.progress_update.emit(processed_count, total_targets)

            self.results = {'ips': all_ip_results, 'urls': all_url_results}
            reporter = ReportGenerator(all_ip_results, all_url_results)
            reporter.generate_excel(self.filepath)
            self.finished.emit(True, self.filepath)
        except Exception as e:
            logging.error(f"ERRO CRÍTICO NA THREAD DE ANÁLISE DE IOCs: {e}", exc_info=True)
            self.log_message.emit("ERRO CRÍTICO. Veja threatspy.log para detalhes.")
            self.finished.emit(False, "")


class FileAnalysisWorker(QThread):
    finished = Signal(bool, str)
    log_message = Signal(str)
    progress_update = Signal(int, int)
    
    def __init__(self, filepaths: List[str], save_path: str) -> None:
        super().__init__()
        self.filepaths = filepaths
        self.save_path = save_path
        self.results: Optional[Dict[str, Any]] = None

    def run(self) -> None:
        try:
            api_client = ApiClient()
            total_files = len(self.filepaths)
            processed_count = 0
            all_file_results = {}
            self.progress_update.emit(0, total_files)

            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_hash = {}
                for fpath in self.filepaths:
                    if self.isInterruptionRequested(): return
                    filename = os.path.basename(fpath)
                    self.log_message.emit(f"Enfileirando: {filename}")
                    file_hash = calculate_sha256(fpath)
                    if file_hash:
                        future = executor.submit(api_client.check_file_multi, file_hash, filename)
                        future_to_hash[future] = file_hash
                    else:
                        processed_count += 1
                        self.progress_update.emit(processed_count, total_files)

                self.log_message.emit(f"Enviando {len(future_to_hash)} arquivos para análise...")
                for future in as_completed(future_to_hash):
                    if self.isInterruptionRequested(): return
                    file_hash = future_to_hash[future]
                    try:
                        result_data = future.result()
                        all_file_results[file_hash] = result_data
                        filename = result_data.get('filename', 'arquivo')
                        self.log_message.emit(f"Resultados para {filename} recebidos.")
                    except Exception as exc:
                        logging.error(f"Erro ao processar o hash {file_hash}: {exc}", exc_info=True)
                    processed_count += 1
                    self.progress_update.emit(processed_count, total_files)

            self.results = {'files': all_file_results}
            reporter = ReportGenerator({}, {}, all_file_results)
            reporter.generate_excel(self.save_path)
            self.finished.emit(True, self.save_path)
        except Exception as e:
            logging.error(f"ERRO CRÍTICO NA ANÁLISE DE ARQUIVOS: {e}", exc_info=True)
            self.log_message.emit("ERRO CRÍTICO. Veja threatspy.log para detalhes.")
            self.finished.emit(False, "")


class RepoAnalysisWorker(QThread):
    finished = Signal(bool, str)
    log_message = Signal(str)
    progress_update = Signal(int, int)

    def __init__(self, repo_urls: List[str], save_path: str) -> None:
        super().__init__()
        self.repo_urls = repo_urls
        self.save_path = save_path
        self.results: Optional[Dict[str, Any]] = None

    def run(self) -> None:
        try:
            api_client = ApiClient()
            total_repos = len(self.repo_urls)
            processed_count = 0
            all_repo_results = []
            
            # self.progress_update.emit(0, total_repos) 

            def status_callback(message: str) -> None:
                self.log_message.emit(message)

            with ThreadPoolExecutor(max_workers=5) as executor:
                analyzers = {
                    url: RepositoryAnalyzer(url, api_client, status_callback)
                    for url in self.repo_urls
                }
                future_to_url = {
                    executor.submit(analyzer.run_analysis): url
                    for url, analyzer in analyzers.items()
                }

                for future in as_completed(future_to_url):
                    if self.isInterruptionRequested(): return
                    url = future_to_url[future]
                    try:
                        repo_results = future.result()
                        all_repo_results.append(repo_results)
                        self.log_message.emit(f"Repositório {os.path.basename(url)} analisado.")
                    except Exception as exc:
                        logging.error(f"Erro ao processar o repositório {url}: {exc}", exc_info=True)
                    processed_count += 1
                    self.progress_update.emit(processed_count, total_repos)

            self.results = {'repositories': all_repo_results}
            reporter = ReportGenerator({}, {}, {}, all_repo_results)
            reporter.generate_excel(self.save_path)
            self.finished.emit(True, self.save_path)
        except Exception as e:
            logging.error(f"ERRO CRÍTICO NA ANÁLISE DE REPOSITÓRIO: {e}", exc_info=True)
            self.log_message.emit("ERRO CRÍTICO. Veja threatspy.log para detalhes.")
            self.finished.emit(False, "")


class AISummaryWorker(QThread):
    finished = Signal(str)
    log_message = Signal(str)

    def __init__(self, analysis_data: Dict[str, Any], model: str) -> None:
        super().__init__()
        self.analysis_data = analysis_data
        self.model = model

    def run(self) -> None:
        self.log_message.emit("Preparando dossiê detalhado para análise da IA...")
        if not any(self.analysis_data.values()):
            self.finished.emit("Erro: Nenhuma análise foi realizada ainda.")
            return
        facts = "Dossiê de Análise de Ameaças:\n\n"
        if repo_data := self.analysis_data.get('repositories', []):
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
        if ip_data := self.analysis_data.get('ips', {}):
            facts += f"**Análise de Endereços IP ({len(ip_data)} total):**\n"
            for ip, results in ip_data.items():
                vt_malicious = safe_get(results, 'virustotal.data.attributes.last_analysis_stats.malicious', 'N/A')
                abuse_score = safe_get(results, 'abuseipdb.data.abuseConfidenceScore', 'N/A')
                facts += f"- IP: {ip} | Detecções VT: {vt_malicious} | Score AbuseIPDB: {abuse_score}%\n"
            facts += "\n"
        if url_data := self.analysis_data.get('urls', {}):
            facts += f"**Análise de URLs ({len(url_data)} total):**\n"
            for url, results in url_data.items():
                vt_malicious = safe_get(results, 'virustotal.data.attributes.stats.malicious', 'N/A')
                uh_status = safe_get(results, 'urlhaus.url_status', 'N/A')
                facts += f"- URL: {url} | Detecções VT: {vt_malicious} | Status URLHaus: {uh_status}\n"
            facts += "\n"
        if file_data := self.analysis_data.get('files', {}):
            facts += f"**Análise de Arquivos ({len(file_data)} total):**\n"
            for f_hash, results in file_data.items():
                filename = results.get('filename', 'N/A')
                vt_malicious = safe_get(results, 'virustotal.data.attributes.last_analysis_stats.malicious', 'N/A')
                mb_threat = safe_get(results, 'malwarebazaar.data.0.signature', 'N/A')
                facts += f"- Arquivo: {filename} | Detecções VT: {vt_malicious} | Ameaça (MB): {mb_threat}\n"
            facts += "\n"
        
        prompt = (
            "Você é um analista de cibersegurança sênior. **Responda exclusivamente em português do Brasil.** "
            "Sua tarefa é gerar um relatório executivo detalhado e acionável com base no dossiê técnico abaixo.\n\n"
            "**ESTRUTURA OBRIGATÓRIA DO RELATÓRIO:**\n\n"
            "### Análise Geral e Nível de Risco\n"
            "(Um parágrafo conciso resumindo os achados mais críticos e avaliando o nível de risco geral como BAIXO, MÉDIO, ALTO ou CRÍTICO).\n\n"
            "### Tabela Resumo dos Achados\n"
            "(Crie uma tabela em markdown resumindo os achados mais importantes, seguindo este formato de exemplo. Preencha com os dados reais do dossiê):\n"
            "| Risco | Categoria | Descrição Breve | Artefato Principal |\n"
            "|---|---|---|---|\n"
            "| Crítico | Segredo Exposto | Token GitHub com permissões de escrita | `.bash_history` |\n"
            "| Alto | URL Maliciosa | URL de C2 conhecida encontrada em Base64 | `malicious-c2.com/gate.php` |\n\n"
            "### Detalhamento dos Achados Críticos\n"
            "(Use subseções para cada categoria (Repositórios, IPs, URLs, Arquivos) e explique o impacto técnico de cada item. Por exemplo, o que um invasor poderia fazer com uma chave AWS exposta).\n\n"
            "### Plano de Ação e Recomendações\n"
            "(Crie uma lista numerada e priorizada de ações de remediação. Seja específico e direto. Ex: '1. Revogar imediatamente a chave AWS (AKIA...) encontrada no arquivo .env. 2. Remover o arquivo .bash_history do histórico do git...').\n\n"
            "### Recomendações de Prevenção a Longo Prazo\n"
            "(Sugira 2 ou 3 medidas para evitar problemas semelhantes, como a implementação de git-secrets, revisões de código focadas em segurança e uso de cofres de segredos).\n\n"
            f"--- INÍCIO DO DOSSIÊ TÉCNICO ---\n{facts}\n--- FIM DO DOSSIÊ TÉCNICO ---"
        )
        
        self.log_message.emit(f"Enviando dossiê detalhado para o modelo {self.model}...")
        summary = ApiClient().get_ai_summary(self.model, prompt)
        self.finished.emit(summary)


class SettingsDialog(QDialog):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Configurações de APIs")
        self.setModal(True)
        self.setMinimumWidth(450)
        main_layout = QVBoxLayout(self)
        tab_widget = QTabWidget()
        link_style = "color:#5698f5; text-decoration: none;"
        self.vt_key_entry = QLineEdit()
        self.abuse_key_entry = QLineEdit()
        self.urlhaus_key_entry = QLineEdit()
        self.shodan_key_entry = QLineEdit()
        self.mb_key_entry = QLineEdit()
        self.github_key_entry = QLineEdit()
        self.gitlab_key_entry = QLineEdit()
        self.ollama_endpoint_entry = QLineEdit()
        tab_widget.addTab(self.create_ollama_tab(), "Ollama")
        tab_widget.addTab(self.create_api_tab("VirusTotal", "https://www.virustotal.com/gui/join-us", self.vt_key_entry, link_style), "VirusTotal")
        tab_widget.addTab(self.create_api_tab("AbuseIPDB", "https://www.abuseipdb.com/register", self.abuse_key_entry, link_style), "AbuseIPDB")
        tab_widget.addTab(self.create_api_tab("URLHaus", "https://urlhaus.abuse.ch/api/", self.urlhaus_key_entry, link_style), "URLHaus")
        tab_widget.addTab(self.create_api_tab("Shodan", "https://account.shodan.io/register", self.shodan_key_entry, link_style), "Shodan")
        tab_widget.addTab(self.create_api_tab("MalwareBazaar", "https://bazaar.abuse.ch/account/", self.mb_key_entry, link_style), "MalwareBazaar")
        tab_widget.addTab(self.create_api_tab("GitHub", "https://github.com/settings/tokens", self.github_key_entry, link_style), "GitHub")
        tab_widget.addTab(self.create_api_tab("GitLab", "https://gitlab.com/-/profile/personal_access_tokens", self.gitlab_key_entry, link_style), "GitLab")
        main_layout.addWidget(tab_widget)
        save_btn = QPushButton("Salvar Configurações")
        save_btn.setFixedHeight(35)
        save_btn.clicked.connect(self.save_settings)
        main_layout.addWidget(save_btn)
        self.load_settings()
    def create_api_tab(self, title: str, url: str, line_edit_widget: QLineEdit, link_style: str) -> QWidget:
        tab_widget = QWidget()
        layout = QFormLayout(tab_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        link = QLabel(f"<a href='{url}' style='{link_style}'>Obter Chave de API</a>")
        link.setOpenExternalLinks(True)
        line_edit_widget.setEchoMode(QLineEdit.Password)
        layout.addRow(link)
        layout.addRow("Chave da API:", line_edit_widget)
        return tab_widget
    def create_ollama_tab(self) -> QWidget:
        tab_widget = QWidget()
        layout = QFormLayout(tab_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        ollama_layout = QHBoxLayout()
        test_btn = QPushButton("Testar Conexão")
        test_btn.clicked.connect(self.test_ollama_connection)
        ollama_layout.addWidget(self.ollama_endpoint_entry)
        ollama_layout.addWidget(test_btn)
        layout.addRow("Endpoint:", ollama_layout)
        return tab_widget
    def test_ollama_connection(self) -> None:
        endpoint = self.ollama_endpoint_entry.text().strip()
        if not endpoint:
            QMessageBox.warning(self, "Teste de Conexão", "O campo de endpoint está vazio.")
            return
        api_client = ApiClient()
        api_client.ai_endpoint = endpoint
        models = api_client.get_local_models()
        if models and "não encontrado" not in models[0].lower() and "erro" not in models[0].lower():
            QMessageBox.information(self, "Teste de Conexão", "Sucesso! Conexão com Ollama estabelecida.")
        else:
            message = models[0] if models else "Verifique o endpoint."
            QMessageBox.critical(self, "Teste de Conexão", f"Falha na conexão com o Ollama em '{endpoint}'.\n\n{message}")
    def load_settings(self) -> None:
        keys_services = {"virustotal_api_key": self.vt_key_entry, "abuseipdb_api_key": self.abuse_key_entry, "urlhaus_api_key": self.urlhaus_key_entry, "shodan_api_key": self.shodan_key_entry, "malwarebazaar_api_key": self.mb_key_entry, "github_api_key": self.github_key_entry, "gitlab_api_key": self.gitlab_key_entry}
        for key_name, widget in keys_services.items():
            if key := keyring.get_password("vtotalscan", key_name):
                widget.setText(key)
        config = configparser.ConfigParser()
        config.read(get_config_path())
        self.ollama_endpoint_entry.setText(config.get('AI', 'endpoint', fallback="http://localhost:11434/api/generate"))
    def save_settings(self) -> None:
        try:
            keys_to_save = {"virustotal_api_key": self.vt_key_entry, "abuseipdb_api_key": self.abuse_key_entry, "urlhaus_api_key": self.urlhaus_key_entry, "shodan_api_key": self.shodan_key_entry, "malwarebazaar_api_key": self.mb_key_entry, "github_api_key": self.github_key_entry, "gitlab_api_key": self.gitlab_key_entry}
            for key_name, widget in keys_to_save.items():
                if key_text := widget.text().strip():
                    keyring.set_password("vtotalscan", key_name, key_text)
            config_path = get_config_path()
            config = configparser.ConfigParser()
            config.read(config_path)
            if not config.has_section('AI'): config.add_section('AI')
            config.set('AI', 'endpoint', self.ollama_endpoint_entry.text().strip())
            with open(config_path, 'w') as configfile: config.write(configfile)
            QMessageBox.information(self, "Sucesso", "Configurações salvas!")
            self.accept()
        except Exception as e:
            logging.error(f"Não foi possível salvar as configurações: {e}", exc_info=True)
            QMessageBox.critical(self, "Erro ao Salvar", f"Não foi possível salvar as configurações:\n{e}")


class ApiUsageWorker(QThread):
    finished = Signal(dict)

    def run(self) -> None:
        try:
            api_client = ApiClient()
            usage_data = api_client.get_api_usage_stats()
            self.finished.emit(usage_data)
        except Exception as e:
            logging.error(f"Erro ao buscar uso das APIs: {e}", exc_info=True)
            self.finished.emit({})


class VtotalscanGUI(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.last_ioc_results: Optional[Dict[str, Any]] = None
        self.last_file_results: Optional[Dict[str, Any]] = None
        self.last_repo_results: Optional[Dict[str, Any]] = None
        self.setWindowTitle("ThreatSpy by SecZeroR")
        #self.setFixedSize(700, 950)
        try:
            self.setWindowIcon(QIcon(resource_path("spy2.ico")))
        except Exception as e:
            logging.error(f"Erro ao carregar ícone: {e}")
        self._setup_ui()
        self.load_models_async()
        self.check_api_key_on_startup()
        self._update_api_usage()
    
    def _setup_ui(self) -> None:
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        header_layout = QHBoxLayout()
        logo_label = QLabel()
        pixmap = QPixmap(resource_path("spy2-1.png")).scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(pixmap)
        btn_update_usage = QPushButton("Atualizar Uso")
        btn_update_usage.clicked.connect(self._update_api_usage)
        btn_config = QPushButton("Configurações")
        btn_config.setIcon(QIcon(resource_path("gear.png")))
        btn_config.clicked.connect(self.open_settings_window)
        header_layout.addWidget(logo_label)
        header_layout.addStretch()
        header_layout.addWidget(btn_update_usage)
        header_layout.addWidget(btn_config)
        main_layout.addLayout(header_layout)
        self.tab_view_main = QTabWidget()
        main_layout.addWidget(self.tab_view_main, 1)
        ioc_tab = self._create_ioc_tab()
        self.tab_view_main.addTab(ioc_tab, "Análise de IOCs")
        repo_tab = self._create_repo_tab()
        self.tab_view_main.addTab(repo_tab, "Análise de Repositório")
        self.tab_view_results = QTabWidget()
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.ai_summary_box = QTextEdit()
        self.ai_summary_box.setReadOnly(True)
        self.tab_view_results.addTab(self.log_console, "Console de Atividade")
        self.tab_view_results.addTab(self.ai_summary_box, "Resumo Gerado por IA")
        main_layout.addWidget(self.tab_view_results, 2)
        ai_controls_layout = self._create_ai_controls()
        main_layout.addLayout(ai_controls_layout)
        self.setStatusBar(QStatusBar(self))

    def _create_repo_tab(self) -> QWidget:
        repo_tab = QWidget()
        repo_layout = QVBoxLayout(repo_tab)
        repo_label = QLabel("Insira as URLs dos Repositórios (uma por linha)")
        repo_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.repo_url_input = QPlainTextEdit()
        self.repo_url_input.setPlaceholderText("https://github.com/owner/repo\nowner/repo (assume GitHub)\nhttps://gitlab.com/owner/repo")
        repo_action_layout = QHBoxLayout()
        btn_load_repos = QPushButton("Importar de Arquivo")
        btn_load_repos.clicked.connect(self.select_repo_file)
        btn_clear_repos = QPushButton("Limpar")
        btn_clear_repos.clicked.connect(self.clear_repo_input)
        repo_action_layout.addWidget(btn_load_repos)
        repo_action_layout.addWidget(btn_clear_repos)
        repo_action_layout.addStretch()
        self.btn_scan_repo = QPushButton("Analisar Repositórios")
        self.btn_scan_repo.setStyleSheet("background-color: #2980b9; color: white; font-weight: bold;")
        self.btn_scan_repo.setFixedHeight(40)
        self.btn_scan_repo.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.btn_scan_repo.clicked.connect(self.start_repo_analysis)
        repo_layout.addWidget(repo_label)
        repo_layout.addWidget(self.repo_url_input, 1)
        repo_layout.addLayout(repo_action_layout)
        repo_layout.addWidget(self.btn_scan_repo)
        return repo_tab

    def _create_ioc_tab(self) -> QWidget:
        ioc_tab = QWidget()
        ioc_layout = QVBoxLayout(ioc_tab)
        input_label = QLabel("Insira os Alvos (IPs ou URLs, um por linha)")
        input_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.text_area = QTextEdit()
        self.text_area.setPlaceholderText("8.8.8.8\n185.172.128.150\ngoogle.com\nhttps://some-random-domain.net/path")
        action_bar_layout = QHBoxLayout()
        btn_load = QPushButton("Importar Alvos de Arquivo")
        btn_load.clicked.connect(self.select_file)
        btn_scan_files = QPushButton("Verificar Reputação de Arquivos")
        btn_scan_files.clicked.connect(self.start_file_analysis)
        btn_clear = QPushButton("Limpar")
        btn_clear.clicked.connect(self.clear_text)
        action_bar_layout.addWidget(btn_load)
        action_bar_layout.addWidget(btn_scan_files)
        action_bar_layout.addWidget(btn_clear)
        self.btn_scan_iocs = QPushButton("Analisar Alvos")
        self.btn_scan_iocs.setStyleSheet("background-color: #03A062; color: white; font-weight: bold;")
        self.btn_scan_iocs.setFixedHeight(40)
        self.btn_scan_iocs.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.btn_scan_iocs.clicked.connect(self.start_ioc_analysis)
        ioc_layout.addWidget(input_label)
        ioc_layout.addWidget(self.text_area, 1)
        ioc_layout.addLayout(action_bar_layout)
        ioc_layout.addWidget(self.btn_scan_iocs)
        return ioc_tab

    def _create_ai_controls(self) -> QHBoxLayout:
        ai_controls_layout = QHBoxLayout()
        ai_label = QLabel("Modelo IA:")
        ai_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.selected_model = QComboBox()
        self.selected_model.addItem("Carregando...")
        self.selected_model.setEnabled(False)
        self.btn_ai_summary = QPushButton("Gerar Resumo em Texto")
        self.btn_ai_summary.setStyleSheet("background-color: #7f8c8d; color: white;")
        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary.clicked.connect(lambda: self._initiate_ai_summary(generate_pdf=False))
        self.btn_ai_summary_pdf = QPushButton("Gerar Resumo em PDF")
        self.btn_ai_summary_pdf.setStyleSheet("background-color: #7f8c8d; color: white;")
        self.btn_ai_summary_pdf.setEnabled(False)
        self.btn_ai_summary_pdf.clicked.connect(lambda: self._initiate_ai_summary(generate_pdf=True))
        ai_controls_layout.addWidget(ai_label)
        ai_controls_layout.addWidget(self.selected_model, 1)
        ai_controls_layout.addWidget(self.btn_ai_summary)
        ai_controls_layout.addWidget(self.btn_ai_summary_pdf)
        return ai_controls_layout
    
    def _update_api_usage(self) -> None:
        self.statusBar().showMessage("Atualizando uso das APIs...")
        self.usage_thread = ApiUsageWorker()
        self.usage_thread.finished.connect(self.on_api_usage_updated)
        self.usage_thread.start()

    def on_api_usage_updated(self, usage_data: Dict[str, Any]) -> None:
        vt_stats = usage_data.get('virustotal', {})
        shodan_stats = usage_data.get('shodan', {})
        github_stats = usage_data.get('github', {})
        
        status_parts = []
        if 'error' not in vt_stats:
            status_parts.append(f"VT: {vt_stats.get('daily_used', 'N/A')}/{vt_stats.get('daily_allowed', 'N/A')} (diário)")
        
        if 'error' not in shodan_stats:
            status_parts.append(f"Shodan: {shodan_stats.get('remaining', 'N/A')} restantes")
            
        if 'error' not in github_stats:
            resets_at = github_stats.get('resets_at', 'N/A')
            status_parts.append(f"GitHub: {github_stats.get('remaining', 'N/A')}/{github_stats.get('limit', 'N/A')} (Reseta às {resets_at})")

        if not status_parts:
            self.statusBar().showMessage("Não foi possível buscar dados de uso. Verifique as chaves de API.")
        else:
            self.statusBar().showMessage(" | ".join(status_parts))

    def open_settings_window(self) -> None:
        if SettingsDialog(self).exec():
            self.load_models_async()
            self._update_api_usage()

    def check_api_key_on_startup(self) -> None:
        if not keyring.get_password("vtotalscan", "virustotal_api_key"):
            self.log("Nenhuma chave de API do VirusTotal encontrada.")
            QMessageBox.warning(self, "Configuração Necessária", "A chave da API do VirusTotal não foi encontrada. Configure-a para continuar.")
            self.open_settings_window()

    def load_models_async(self) -> None:
        threading.Thread(target=self.populate_model_menu, daemon=True).start()

    def populate_model_menu(self) -> None:
        models = ApiClient().get_local_models()
        self.selected_model.clear()
        if models and "não encontrado" not in models[0].lower() and "erro" not in models[0].lower():
            self.selected_model.addItems(models)
            self.selected_model.setEnabled(True)
        else:
            self.selected_model.addItem(models[0] if models else "Nenhum modelo")
            self.selected_model.setEnabled(False)

    def select_file(self) -> None:
        filepath, _ = QFileDialog.getOpenFileName(self, "Selecionar arquivo de texto com alvos", "", "Arquivos de Texto (*.txt);;Todos os Arquivos (*)")
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    self.text_area.setPlainText(f.read())
                self.log(f"Conteúdo de '{os.path.basename(filepath)}' carregado.")
            except Exception as e:
                logging.error(f"Não foi possível ler o arquivo: {filepath} - {e}", exc_info=True)
                QMessageBox.critical(self, "Erro", f"Não foi possível ler o arquivo:\n{e}")

    def select_repo_file(self) -> None:
        filepath, _ = QFileDialog.getOpenFileName(self, "Selecionar arquivo de texto com URLs", "", "Arquivos de Texto (*.txt);;Todos os Arquivos (*)")
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    self.repo_url_input.setPlainText(f.read())
                self.log(f"Conteúdo de '{os.path.basename(filepath)}' carregado.")
            except Exception as e:
                logging.error(f"Não foi possível ler o arquivo: {filepath} - {e}", exc_info=True)
                QMessageBox.critical(self, "Erro", f"Não foi possível ler o arquivo:\n{e}")

    def clear_text(self) -> None:
        self.text_area.clear()
        self.log("Área de alvos limpa.")

    def clear_repo_input(self) -> None:
        self.repo_url_input.clear()
        self.log("Área de repositórios limpa.")

    def log(self, message: str) -> None:
        timestamp = time.strftime('%H:%M:%S')
        self.log_console.append(f"[{timestamp}] >> {message}")

    def _reset_results(self) -> None:
        self.last_ioc_results, self.last_file_results, self.last_repo_results = None, None, None
        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary_pdf.setEnabled(False)
        
    def start_repo_analysis(self) -> None:
        self._reset_results()
        input_text = self.repo_url_input.toPlainText()
        repo_urls, invalid_lines, duplicate_lines = parse_repo_urls(input_text)
        if duplicate_lines: QMessageBox.information(self, "Entradas Duplicadas", f"URLs duplicadas ignoradas:\n\n" + "\n".join(duplicate_lines))
        if invalid_lines: QMessageBox.warning(self, "Entradas Inválidas", f"Entradas ignoradas por não serem URLs válidas:\n\n" + "\n".join(invalid_lines))
        if not repo_urls:
            self.log("Nenhuma URL de repositório válida.")
            QMessageBox.warning(self, "Nenhum Alvo", "Forneça URLs válidas.")
            return
        save_path, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório", "Analise_Repositorios.xlsx", "Arquivos Excel (*.xlsx)")
        if not save_path:
            self.log("Operação cancelada.")
            return
        if not is_file_writable(save_path):
            QMessageBox.critical(self, "Erro de Permissão", f"Não é possível escrever em:\n{save_path}")
            self.log("Falha ao escrever no relatório.")
            return
        self.log(f"Análise de {len(repo_urls)} repositório(s) iniciada...")
        self.progress_dialog = QProgressDialog("Analisando repositórios... (Isso pode levar vários minutos)", "Cancelar", 0, 0, self)
        self.progress_dialog.setWindowTitle("Analisando Repositórios")
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.repo_thread = RepoAnalysisWorker(repo_urls, save_path)
        self.progress_dialog.canceled.connect(self.repo_thread.requestInterruption)
        self.repo_thread.log_message.connect(self.log)
        self.repo_thread.log_message.connect(self.update_repo_progress_text)
        self.repo_thread.progress_update.connect(self.update_progress_dialog)
        self.repo_thread.finished.connect(self.on_analysis_finished)
        self.repo_thread.finished.connect(self.repo_thread.deleteLater)
        self.repo_thread.start()
        self.progress_dialog.show()

    def start_ioc_analysis(self) -> None:
        self._reset_results()
        filepath, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório Excel", "Analise_IOCs.xlsx", "Arquivos Excel (*.xlsx)")
        if not filepath:
            self.log("Operação cancelada.")
            return
        if not is_file_writable(filepath):
            QMessageBox.critical(self, "Erro de Permissão", f"Não é possível escrever em:\n{filepath}")
            self.log("Falha ao escrever no relatório.")
            return
        ips, urls = parse_targets(self.text_area.toPlainText())
        total_targets = len(ips) + len(urls)
        self.progress_dialog = QProgressDialog(f"Analisando 0 de {total_targets}...", "Cancelar", 0, total_targets, self)
        self.progress_dialog.setWindowTitle("Analisando IOCs")
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.analysis_thread = AnalysisWorker(self.text_area.toPlainText(), filepath)
        self.progress_dialog.canceled.connect(self.analysis_thread.requestInterruption)
        self.analysis_thread.log_message.connect(self.log)
        self.analysis_thread.progress_update.connect(self.update_progress_dialog)
        self.analysis_thread.finished.connect(self.on_analysis_finished)
        self.analysis_thread.finished.connect(self.analysis_thread.deleteLater)
        self.analysis_thread.start()
        self.progress_dialog.show()

    def start_file_analysis(self) -> None:
        self._reset_results()
        filepaths, _ = QFileDialog.getOpenFileNames(self, "Selecionar Arquivos", "", "Todos os Arquivos (*)")
        if not filepaths:
            self.log("Nenhum arquivo selecionado.")
            return
        save_path, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório", "Analise_Arquivos.xlsx", "Arquivos Excel (*.xlsx)")
        if not save_path:
            self.log("Operação cancelada.")
            return
        if not is_file_writable(save_path):
            QMessageBox.critical(self, "Erro de Permissão", f"Não é possível escrever em:\n{save_path}")
            self.log("Falha ao escrever no relatório.")
            return
        self.progress_dialog = QProgressDialog(f"Analisando 0 de {len(filepaths)}...", "Cancelar", 0, len(filepaths), self)
        self.progress_dialog.setWindowTitle("Analisando Arquivos")
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.file_thread = FileAnalysisWorker(filepaths, save_path)
        self.progress_dialog.canceled.connect(self.file_thread.requestInterruption)
        self.file_thread.log_message.connect(self.log)
        self.file_thread.progress_update.connect(self.update_progress_dialog)
        self.file_thread.finished.connect(self.on_analysis_finished)
        self.file_thread.finished.connect(self.file_thread.deleteLater)
        self.file_thread.start()
        self.progress_dialog.show()
    
    def update_progress_dialog(self, current: int, total: int) -> None:
        if hasattr(self, 'progress_dialog') and self.progress_dialog.isVisible():
            self.progress_dialog.setMaximum(total)
            self.progress_dialog.setValue(current)
            sender = self.sender()
            is_repo_worker = hasattr(self, 'repo_thread') and isinstance(sender, RepoAnalysisWorker)
            if is_repo_worker:
                self.progress_dialog.setLabelText(f"Analisando repositórios... Concluído: {current} de {total}")
            else:
                self.progress_dialog.setLabelText(f"Progresso: {current} de {total}...")

    def update_repo_progress_text(self, message: str) -> None:
        if hasattr(self, 'repo_thread') and self.sender() == self.repo_thread:
            if hasattr(self, 'progress_dialog') and self.progress_dialog.isVisible():
                current_text = self.progress_dialog.labelText().split('\n')[0]
                self.progress_dialog.setLabelText(f"{current_text}\n{message}")

    def on_analysis_finished(self, success: bool, filepath: str) -> None:
        if hasattr(self, 'progress_dialog'):
            self.progress_dialog.close()
        if success:
            self._update_api_usage()
        sender_thread = self.sender()
        if not success and filepath == "NO_TARGETS":
            QMessageBox.warning(self, "Aviso", "Nenhum IP ou URL válido foi encontrado.")
            self.log("Nenhum alvo válido.")
        elif success and filepath:
            if isinstance(sender_thread, AnalysisWorker): self.last_ioc_results = sender_thread.results
            elif isinstance(sender_thread, FileAnalysisWorker): self.last_file_results = sender_thread.results
            elif isinstance(sender_thread, RepoAnalysisWorker): self.last_repo_results = sender_thread.results
            if self.last_ioc_results or self.last_file_results or self.last_repo_results:
                self.btn_ai_summary.setEnabled(True)
                self.btn_ai_summary_pdf.setEnabled(True)
            self.log(f"Relatório salvo em: {filepath}")
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Concluído")
            msg_box.setTextFormat(Qt.RichText)
            msg_box.setText(f"<p>Análise concluída!</p><p>Relatório salvo em:</p><p><a href='{Path(filepath).as_uri()}'>{filepath}</a></p>")
            msg_box.exec()
        else:
            self.log("A análise falhou ou foi cancelada.")

    def _initiate_ai_summary(self, generate_pdf: bool) -> None:
        if not (self.last_ioc_results or self.last_file_results or self.last_repo_results):
            QMessageBox.warning(self, "Aviso", "Realize uma análise primeiro.")
            return
        selected_model_text = self.selected_model.currentText()
        if "Erro:" in selected_model_text or "não encontrado" in selected_model_text:
            QMessageBox.warning(self, "Configuração de IA Inválida", "Verifique as Configurações.")
            return
        filepath = ""
        if generate_pdf:
            filepath, _ = QFileDialog.getSaveFileName(self, "Salvar Resumo em PDF", "Resumo_IA.pdf", "Arquivos PDF (*.pdf)")
            if not filepath:
                self.log("Operação cancelada.")
                return
        combined_results = { "ips": self.last_ioc_results.get('ips', {}) if self.last_ioc_results else {}, "urls": self.last_ioc_results.get('urls', {}) if self.last_ioc_results else {}, "files": self.last_file_results.get('files', {}) if self.last_file_results else {}, "repositories": self.last_repo_results.get('repositories', []) if self.last_repo_results else [] }
        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary_pdf.setEnabled(False)
        self.ai_summary_box.setPlainText("Analisando com IA..." if not generate_pdf else "Gerando PDF com IA...")
        self.ai_thread = AISummaryWorker(combined_results, selected_model_text)
        self.ai_thread.log_message.connect(self.log)
        if generate_pdf:
            self.ai_thread.finished.connect(lambda summary: self.on_ai_finished_pdf(summary, filepath))
        else:
            self.ai_thread.finished.connect(self.on_ai_finished_text)
        self.ai_thread.finished.connect(self.ai_thread.deleteLater)
        self.ai_thread.start()

    def on_ai_finished_text(self, summary: str) -> None:
        self.ai_summary_box.setPlainText(summary)
        self.tab_view_results.setCurrentIndex(1)
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary_pdf.setEnabled(True)

    def on_ai_finished_pdf(self, summary: str, filepath: str) -> None:
        try:
            reporter = ReportGenerator(self.last_ioc_results.get('ips', {}) if self.last_ioc_results else {}, self.last_ioc_results.get('urls', {}) if self.last_ioc_results else {}, self.last_file_results.get('files', {}) if self.last_file_results else {}, self.last_repo_results.get('repositories', []) if self.last_repo_results else [])
            reporter.generate_pdf_summary(filepath, summary)
            self.log(f"Resumo PDF salvo em: {filepath}")
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Concluído")
            msg_box.setTextFormat(Qt.RichText)
            msg_box.setText(f"<p>PDF gerado!</p><p>Salvo em:</p><p><a href='{Path(filepath).as_uri()}'>{filepath}</a></p>")
            msg_box.exec()
            self.ai_summary_box.setPlainText(summary)
            self.tab_view_results.setCurrentIndex(1)
        except Exception as e:
            logging.error(f"Falha ao gerar o relatório em PDF: {e}", exc_info=True)
            QMessageBox.critical(self, "Erro", f"Ocorreu um erro ao gerar o relatório em PDF:\n{e}")
        finally:
            self.btn_ai_summary.setEnabled(True)
            self.btn_ai_summary_pdf.setEnabled(True)

if __name__ == "__main__":
    setup_logging()
    logging.info("Aplicação ThreatSpy iniciada.")
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(45, 45, 45)); palette.setColor(QPalette.WindowText, Qt.white); palette.setColor(QPalette.Base, QColor(25, 25, 25)); palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53)); palette.setColor(QPalette.ToolTipBase, Qt.white); palette.setColor(QPalette.ToolTipText, Qt.white); palette.setColor(QPalette.Text, Qt.white); palette.setColor(QPalette.Button, QColor(53, 53, 53)); palette.setColor(QPalette.ButtonText, Qt.white); palette.setColor(QPalette.BrightText, Qt.red); palette.setColor(QPalette.Link, QColor(42, 130, 218)); palette.setColor(QPalette.Highlight, QColor(42, 130, 218)); palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)
    gui = VtotalscanGUI()
    gui.show()
    sys.exit(app.exec())
