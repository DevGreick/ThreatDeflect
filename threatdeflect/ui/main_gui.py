# threatdeflect/ui/main_gui.py

import sys
import os
import time
import logging
import configparser
import threading # ALTERAÇÃO: Adicionado o import que faltava.
import re
import tempfile
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List

import keyring
import requests
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon, QFont, QPixmap, QPalette, QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QPlainTextEdit, QLabel, QTabWidget, QComboBox,
    QFileDialog, QMessageBox, QProgressDialog, QDialog, QLineEdit,
    QFormLayout, QTextEdit, QStatusBar, QProgressBar, QStackedWidget
)

if sys.platform == "win32":
    import ctypes

from threatdeflect.api.api_client import ApiClient
from threatdeflect.core.report_generator import ReportGenerator
from threatdeflect.core import engine
from threatdeflect.core.engine import AnalysisError, NoValidTargetsError, InterruptedException
from threatdeflect.ui.translations import T
from threatdeflect.core.cache_manager import clear_all_caches
from threatdeflect.utils.utils import (
    parse_targets, calculate_sha256, resource_path, parse_repo_urls,
    is_file_writable, safe_get, get_config_path, create_updater_script,
    get_log_path
)

__version__ = "2.0.0"


def setup_logging() -> None:
    log_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(message)s'
    )
    log_file_path = get_log_path()
    file_handler = logging.FileHandler(log_file_path, mode='a', encoding='utf-8')
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
    root_logger.addHandler(file_handler)


class DownloadWorker(QThread):
    progress = Signal(int, int)
    finished = Signal(bool, str, str)

    def __init__(self, url: str, asset_name: str) -> None:
        super().__init__()
        self.url = url
        self.asset_name = asset_name

    def run(self) -> None:
        try:
            response = requests.get(self.url, stream=True, timeout=30)
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0
            temp_dir = tempfile.gettempdir()
            download_path = os.path.join(temp_dir, self.asset_name)

            with open(download_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if self.isInterruptionRequested():
                        self.finished.emit(False, "", "Download cancelado.")
                        return
                    f.write(chunk)
                    downloaded_size += len(chunk)
                    self.progress.emit(downloaded_size, total_size)
            
            self.finished.emit(True, download_path, "")
        except requests.RequestException as e:
            logging.error(f"Erro no download da atualizacao: {e}", exc_info=True)
            self.finished.emit(False, "", f"Erro de rede: {e}")
        except Exception as e:
            logging.error(f"Erro inesperado no download: {e}", exc_info=True)
            self.finished.emit(False, "", f"Erro inesperado: {e}")


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
            if self.isInterruptionRequested(): return
            
            self.results = engine.run_ioc_analysis(
                targets_text=self.text_to_analyze,
                output_path=Path(self.filepath),
                log_callback=self.log_message.emit,
                progress_callback=self.handle_progress
            )
            self.finished.emit(True, self.filepath)
        except InterruptedException:
            self.log_message.emit("Análise de IOCs cancelada pelo usuário.")
            self.finished.emit(False, "CANCELLED")
        except NoValidTargetsError:
            self.finished.emit(False, "NO_TARGETS")
        except AnalysisError as e:
            logging.error(f"AnalysisWorker falhou: {e}", exc_info=True)
            self.finished.emit(False, str(e))
    
    def handle_progress(self, current: int, total: int):
        if self.isInterruptionRequested():
            raise InterruptedException("Cancelamento solicitado pelo usuário.")
        self.progress_update.emit(current, total)
    

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
            if self.isInterruptionRequested(): return

            self.results = engine.run_repo_analysis(
                repo_urls=self.repo_urls,
                output_path=Path(self.save_path),
                log_callback=self.log_message.emit,
                progress_callback=self.handle_progress
            )
            self.finished.emit(True, self.save_path)
        except InterruptedException:
            self.log_message.emit("Análise de repositórios cancelada pelo usuário.")
            self.finished.emit(False, "CANCELLED")
        except AnalysisError as e:
            logging.error(f"RepoAnalysisWorker falhou: {e}", exc_info=True)
            self.finished.emit(False, str(e))

    def handle_progress(self, current: int, total: int):
        if self.isInterruptionRequested():
            raise InterruptedException("Cancelamento solicitado pelo usuário.")
        self.progress_update.emit(current, total)


class FileAnalysisWorker(QThread):
    finished = Signal(bool, str)
    log_message = Signal(str)
    progress_update = Signal(int, int)

    def __init__(self, file_paths: List[str], save_path: str) -> None:
        super().__init__()
        self.file_paths = file_paths
        self.save_path = save_path
        self.results: Optional[Dict[str, Any]] = None

    def run(self) -> None:
        try:
            if self.isInterruptionRequested(): return

            self.results = engine.run_file_analysis(
                file_paths=self.file_paths,
                output_path=Path(self.save_path),
                log_callback=self.log_message.emit,
                progress_callback=self.handle_progress
            )
            self.finished.emit(True, self.save_path)
        except InterruptedException:
            self.log_message.emit("Análise de arquivos cancelada pelo usuário.")
            self.finished.emit(False, "CANCELLED")
        except NoValidTargetsError:
            self.finished.emit(False, "NO_VALID_FILES")
        except AnalysisError as e:
            logging.error(f"FileAnalysisWorker falhou: {e}", exc_info=True)
            self.finished.emit(False, str(e))

    def handle_progress(self, current: int, total: int):
        if self.isInterruptionRequested():
            raise InterruptedException("Cancelamento solicitado pelo usuário.")
        self.progress_update.emit(current, total)
        

class AISummaryWorker(QThread):
    finished = Signal(str)
    log_message = Signal(str)
    status_popup = Signal(str, str)
    
    def __init__(self, analysis_data: Dict[str, Any], model: str) -> None:
        super().__init__()
        self.analysis_data = analysis_data
        self.model = model

    def run(self) -> None:
        summary = engine.get_ai_summary(
            analysis_data=self.analysis_data,
            model=self.model,
            log_callback=self.log_message.emit,
            status_callback=self.status_popup.emit
        )
        self.finished.emit(summary)


class SettingsDialog(QDialog):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(T("settings_title"))
        self.setModal(True)
        self.setMinimumWidth(500)
        self.language_changed = False
        
        main_layout = QVBoxLayout(self)
        self.tab_widget = QTabWidget()
        
        self.tab_widget.addTab(self._create_general_tab(), T("general_tab"))
        
        link_style = "color:#5698f5; text-decoration: none;"
        self.vt_key_entry = QLineEdit()
        self.abuse_key_entry = QLineEdit()
        self.urlhaus_key_entry = QLineEdit()
        self.shodan_key_entry = QLineEdit()
        self.mb_key_entry = QLineEdit()
        self.github_key_entry = QLineEdit()
        self.gitlab_key_entry = QLineEdit()
        self.ollama_endpoint_entry = QLineEdit()
        
        api_keys_tab = QWidget()
        api_keys_layout = QVBoxLayout(api_keys_tab)
        api_tab_widget = QTabWidget()
        api_tab_widget.addTab(self.create_api_tab("VirusTotal", "https://www.virustotal.com/gui/join-us", self.vt_key_entry, link_style), "VirusTotal")
        api_tab_widget.addTab(self.create_api_tab("AbuseIPDB", "https://www.abuseipdb.com/register", self.abuse_key_entry, link_style), "AbuseIPDB")
        api_tab_widget.addTab(self.create_api_tab("URLHaus", "https://urlhaus.abuse.ch/api/", self.urlhaus_key_entry, link_style), "URLHaus")
        api_tab_widget.addTab(self.create_api_tab("Shodan", "https://account.shodan.io/register", self.shodan_key_entry, link_style), "Shodan")
        api_tab_widget.addTab(self.create_api_tab("MalwareBazaar", "https://bazaar.abuse.ch/account/", self.mb_key_entry, link_style), "MalwareBazaar")
        api_tab_widget.addTab(self.create_api_tab("GitHub", "https://github.com/settings/tokens", self.github_key_entry, link_style), "GitHub")
        api_tab_widget.addTab(self.create_api_tab("GitLab", "https://gitlab.com/-/profile/personal_access_tokens", self.gitlab_key_entry, link_style), "GitLab")
        api_keys_layout.addWidget(api_tab_widget)
        self.tab_widget.addTab(api_keys_tab, T("api_keys_tab"))
        
        self.tab_widget.addTab(self.create_ollama_tab(), "Ollama")
        
        self.tab_widget.addTab(self._create_about_tab(), T("about_tab"))
        
        main_layout.addWidget(self.tab_widget)
        
        buttons_layout = QHBoxLayout()
        save_btn = QPushButton(T("save_close_button"))
        save_btn.setFixedHeight(35)
        save_btn.clicked.connect(self.save_settings)
        close_btn = QPushButton(T("close_button"))
        close_btn.clicked.connect(self.accept)
        buttons_layout.addStretch()
        buttons_layout.addWidget(close_btn)
        buttons_layout.addWidget(save_btn)
        
        main_layout.addLayout(buttons_layout)
        
        self.load_settings()

    def _create_general_tab(self) -> QWidget:
        general_tab = QWidget()
        layout = QFormLayout(general_tab)
        layout.setContentsMargins(15, 15, 15, 15)
        
        log_path_layout = QHBoxLayout()
        self.log_path_entry = QLineEdit()
        btn_browse_log = QPushButton(T("browse_button"))
        btn_browse_log.clicked.connect(self._select_log_path)
        log_path_layout.addWidget(self.log_path_entry)
        log_path_layout.addWidget(btn_browse_log)
        layout.addRow(T("log_path_label"), log_path_layout)
        
        self.language_combo = QComboBox()
        self.language_combo.addItem("Português (Brasil)", "pt_br")
        self.language_combo.addItem("English (US)", "en_us")
        layout.addRow(T("language_label"), self.language_combo)
        
        layout.addRow(QWidget()) 

        btn_clear_cache = QPushButton("Limpar Cache de Análise")
        btn_clear_cache.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold;")
        btn_clear_cache.setToolTip("Remove todos os resultados salvos de análises de repositórios para forçar uma nova análise completa.")
        btn_clear_cache.clicked.connect(self._prompt_and_clear_cache)
        
        layout.addRow(QLabel("Ações de Manutenção:"), btn_clear_cache)
        
        return general_tab

    def _prompt_and_clear_cache(self) -> None:
        reply = QMessageBox.question(self,
                                     "Confirmar Limpeza de Cache",
                                     "Isso removerá permanentemente TODOS os resultados de análises de repositórios salvos em cache. Análises futuras para os mesmos repositórios serão completas e, portanto, mais lentas.\n\nDeseja continuar?",
                                     QMessageBox.Yes | QMessageBox.No,
                                     QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.setCursor(Qt.WaitCursor)
            success, message = clear_all_caches()
            self.unsetCursor()
            
            if success:
                QMessageBox.information(self, "Sucesso", "O cache foi limpo com sucesso.")
            else:
                QMessageBox.critical(self, "Erro", f"Não foi possível limpar o cache:\n{message}")

    def _create_about_tab(self) -> QWidget:
        about_tab = QWidget()
        layout = QVBoxLayout(about_tab)
        layout.setContentsMargins(15, 15, 15, 15)
        
        about_text = """
        <p><b>ThreatDeflect v{version}</b></p>
        <p>Esta é uma ferramenta open source distribuída sob a licença <b>GPLv3</b>.</p>
        <p><b>Repositório:</b> <a href="https://github.com/DevGreick/ThreatDeflect">github.com/DevGreick/ThreatSpy</a></p>
        <p><b>Autor:</b> @seczeror</p>
        <hr>
        <h4>Uso Responsável e Privacidade</h4>
        <p>• Para realizar as análises, esta ferramenta <b>envia os dados fornecidos</b> (IPs, URLs, hashes) para APIs de terceiros (ex: VirusTotal).</p>
        <p>• <b>Não submeta informações confidenciais ou internas.</b> A responsabilidade pela segurança dos dados submetidos é sua.</p>
        <p>• O desenvolvedor não se responsabiliza por qualquer vazamento de dados decorrente do uso da ferramenta.</p>
        """.format(version=__version__)

        label = QLabel(about_text)
        label.setWordWrap(True)
        label.setOpenExternalLinks(True)
        label.setTextFormat(Qt.RichText)
        layout.addWidget(label)
        layout.addStretch()
        return about_tab

    def _select_log_path(self):
        caminho_sugerido = self.log_path_entry.text() or str(get_log_path())
        filepath, _ = QFileDialog.getSaveFileName(
            self, 
            T("log_path_label"),
            caminho_sugerido,
            "Log Files (*.log);;All Files (*)"
        )
        if filepath:
            self.log_path_entry.setText(filepath)

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

        self.log_path_entry.setText(config.get('General', 'log_path', fallback=str(get_log_path())))
        self.ollama_endpoint_entry.setText(config.get('AI', 'endpoint', fallback="http://localhost:11434/api/generate"))

        lang_code = config.get('General', 'language', fallback='pt_br')
        index = self.language_combo.findData(lang_code)
        if index != -1:
            self.language_combo.setCurrentIndex(index)

    def save_settings(self) -> None:
        try:
            config_path = get_config_path()
            config = configparser.ConfigParser()
            config.read(config_path)

            if not config.has_section('General'): config.add_section('General')
            
            old_lang = config.get('General', 'language', fallback='pt_br')
            new_lang = self.language_combo.currentData()
            if old_lang != new_lang:
                self.language_changed = True
            config.set('General', 'language', new_lang)

            new_log_path = self.log_path_entry.text().strip()
            old_log_path = config.get('General', 'log_path', fallback=str(get_log_path()))
            log_path_changed = Path(new_log_path).resolve() != Path(old_log_path).resolve()
            config.set('General', 'log_path', new_log_path)
            
            if not config.has_section('AI'): config.add_section('AI')
            config.set('AI', 'endpoint', self.ollama_endpoint_entry.text().strip())

            keys_to_save = {"virustotal_api_key": self.vt_key_entry, "abuseipdb_api_key": self.abuse_key_entry, "urlhaus_api_key": self.urlhaus_key_entry, "shodan_api_key": self.shodan_key_entry, "malwarebazaar_api_key": self.mb_key_entry, "github_api_key": self.github_key_entry, "gitlab_api_key": self.gitlab_key_entry}
            for key_name, widget in keys_to_save.items():
                if key_text := widget.text().strip():
                    keyring.set_password("vtotalscan", key_name, key_text)

            with open(config_path, 'w') as configfile:
                config.write(configfile)

            QMessageBox.information(self, "Sucesso", "Configurações salvas!")
            
            if log_path_changed:
                QMessageBox.information(self, "Reinicialização Necessária", "O novo caminho do arquivo de log será aplicado após reiniciar a aplicação.")
            
            if self.language_changed:
                QMessageBox.information(self, T("reboot_required_title"), T("language_changed_text"))

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


class ReleaseWorker(QThread):
    finished = Signal(dict)
    def run(self) -> None:
        try:
            api_client = ApiClient()
            release_info = api_client.get_latest_release_info()
            self.finished.emit(release_info)
        except Exception as e:
            logging.error(f"Erro ao buscar informações de release: {e}", exc_info=True)
            self.finished.emit({"error": "Falha ao buscar release."})


class VtotalscanGUI(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.last_ioc_results: Optional[Dict[str, Any]] = None
        self.last_file_results: Optional[Dict[str, Any]] = None
        self.last_repo_results: Optional[Dict[str, Any]] = None
        self.update_info: Dict[str, Any] = {}
        
        self.STYLE_AI_BUTTON_INACTIVE = "background-color: #7f8c8d; color: white;"
        self.STYLE_AI_BUTTON_ACTIVE = "background-color: #1f618d; color: white; font-weight: bold;"

        self.setWindowTitle(T("window_title"))
        
        try:
            self.setWindowIcon(QIcon(resource_path("spy2.ico")))
        except Exception as e:
            logging.error(f"Erro ao carregar ícone: {e}")
        self._setup_ui()
        self.load_models_async()
        self.load_release_notes_async()
        self.check_api_key_on_startup()
        self._update_api_usage()
        log_path = get_log_path()
        self.log(f"Arquivo de log sendo salvo em: {log_path}")

    def _set_ui_for_analysis(self, is_running: bool) -> None:
        self.btn_scan_iocs.setEnabled(not is_running)
        self.btn_scan_repo.setEnabled(not is_running)
        self.btn_scan_files.setEnabled(not is_running)
        self.tab_view_main.tabBar().setEnabled(not is_running)
        if is_running:
            self.btn_ai_summary.setEnabled(False)
            self.btn_ai_summary_pdf.setEnabled(False)

    def show_status_popup(self, title: str, message: str) -> None:
        QMessageBox.information(self, title, message)

    def _setup_ui(self) -> None:
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        header_layout = QHBoxLayout()
        logo_label = QLabel()
        pixmap = QPixmap(resource_path("spy2-1.png")).scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(pixmap)
        btn_update_usage = QPushButton(T("update_usage_button"))
        btn_update_usage.clicked.connect(self._update_api_usage)
        btn_config = QPushButton(T("settings_button"))
        btn_config.setObjectName("btn_config")
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
        self.tab_view_main.addTab(ioc_tab, T("ioc_analysis_tab"))
        repo_tab = self._create_repo_tab()
        self.tab_view_main.addTab(repo_tab, T("repo_analysis_tab"))
        
        self.tab_view_results = QTabWidget()
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.ai_summary_box = QTextEdit()
        self.ai_summary_box.setReadOnly(True)
        
        self.update_tab_container = QWidget()
        self.update_tab_layout = QVBoxLayout(self.update_tab_container)
        self.update_tab_layout.setContentsMargins(0, 0, 0, 0)
        
        self.release_notes_box = QTextEdit()
        self.release_notes_box.setReadOnly(True)
        self.update_tab_layout.addWidget(self.release_notes_box)

        self.tab_view_results.addTab(self.log_console, T("activity_console_tab"))
        self.tab_view_results.addTab(self.ai_summary_box, T("ai_summary_tab"))
        self.tab_view_results.addTab(self.update_tab_container, T("updates_tab"))
        
        main_layout.addWidget(self.tab_view_results, 2)
        ai_controls_layout = self._create_ai_controls()
        main_layout.addLayout(ai_controls_layout)
        self.setStatusBar(QStatusBar(self))

    def _create_repo_tab(self) -> QWidget:
        repo_tab = QWidget()
        repo_layout = QVBoxLayout(repo_tab)
        repo_label = QLabel(T("repo_input_label"))
        repo_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.repo_url_input = QPlainTextEdit()
        self.repo_url_input.setPlaceholderText("https://github.com/owner/repo\nowner/repo (assume GitHub)\nhttps://gitlab.com/owner/repo")
        repo_action_layout = QHBoxLayout()
        btn_load_repos = QPushButton(T("import_repos_button"))
        btn_load_repos.clicked.connect(self.select_repo_file)
        btn_clear_repos = QPushButton(T("clear_repos_button"))
        btn_clear_repos.clicked.connect(self.clear_repo_input)
        repo_action_layout.addWidget(btn_load_repos)
        repo_action_layout.addWidget(btn_clear_repos)
        repo_action_layout.addStretch()
        
        scan_repo_button_container = QWidget()
        scan_repo_layout = QVBoxLayout(scan_repo_button_container)
        scan_repo_layout.setContentsMargins(0,0,0,0)
        self.btn_scan_repo = QPushButton(T("analyze_repos_button"))
        self.btn_scan_repo.setStyleSheet("background-color: #2980b9; color: white; font-weight: bold;")
        self.btn_scan_repo.setFixedHeight(40)
        self.btn_scan_repo.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.btn_scan_repo.clicked.connect(self.start_repo_analysis)
        scan_repo_layout.addWidget(self.btn_scan_repo)
        
        self.progress_repo_container = QWidget()
        self.progress_repo_container.setVisible(False)
        progress_repo_layout = QHBoxLayout(self.progress_repo_container)
        progress_repo_layout.setContentsMargins(0,0,0,0)
        
        self.repo_progress_bar = QProgressBar()
        self.repo_progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid grey; border-radius: 5px; text-align: center; height: 25px;
            }
            QProgressBar::chunk {
                background-color: #2980b9; width: 10px; border-radius: 5px;
            }
        """)
        
        self.btn_cancel_repo_scan = QPushButton(T("cancel_button"))
        self.btn_cancel_repo_scan.setFixedHeight(30)
        
        progress_repo_layout.addWidget(self.repo_progress_bar)
        progress_repo_layout.addWidget(self.btn_cancel_repo_scan)

        self.repo_action_stack = QStackedWidget()
        self.repo_action_stack.addWidget(scan_repo_button_container)
        self.repo_action_stack.addWidget(self.progress_repo_container)
        
        repo_layout.addWidget(repo_label)
        repo_layout.addWidget(self.repo_url_input, 1)
        repo_layout.addLayout(repo_action_layout)
        repo_layout.addWidget(self.repo_action_stack)
        
        return repo_tab

    def _create_ioc_tab(self) -> QWidget:
        ioc_tab = QWidget()
        ioc_layout = QVBoxLayout(ioc_tab)
        input_label = QLabel(T("ioc_input_label"))
        input_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.text_area = QPlainTextEdit()
        self.text_area.setPlaceholderText("8.8.8.8\n185.172.128.150\ngoogle.com\nhttps://some-random-domain.net/path")
        action_bar_layout = QHBoxLayout()
        btn_load = QPushButton(T("import_targets_button"))
        btn_load.clicked.connect(self.select_file)
        
        self.btn_scan_files = QPushButton(T("check_file_reputation_button"))
        self.btn_scan_files.clicked.connect(self.start_file_analysis)
        
        btn_clear = QPushButton(T("clear_button"))
        btn_clear.clicked.connect(self.clear_text)
        action_bar_layout.addWidget(btn_load)
        action_bar_layout.addWidget(self.btn_scan_files)
        action_bar_layout.addWidget(btn_clear)

        scan_ioc_button_container = QWidget()
        scan_ioc_layout = QVBoxLayout(scan_ioc_button_container)
        scan_ioc_layout.setContentsMargins(0,0,0,0)
        self.btn_scan_iocs = QPushButton(T("analyze_targets_button"))
        self.btn_scan_iocs.setStyleSheet("background-color: #03A062; color: white; font-weight: bold;")
        self.btn_scan_iocs.setFixedHeight(40)
        self.btn_scan_iocs.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.btn_scan_iocs.clicked.connect(self.start_ioc_analysis)
        scan_ioc_layout.addWidget(self.btn_scan_iocs)

        self.progress_ioc_container = QWidget()
        self.progress_ioc_container.setVisible(False)
        progress_ioc_layout = QHBoxLayout(self.progress_ioc_container)
        progress_ioc_layout.setContentsMargins(0,0,0,0)

        self.ioc_progress_bar = QProgressBar()
        self.ioc_progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid grey; border-radius: 5px; text-align: center; height: 25px;
            }
            QProgressBar::chunk {
                background-color: #03A062; width: 10px; border-radius: 5px;
            }
        """)

        self.btn_cancel_ioc_scan = QPushButton(T("cancel_button"))
        self.btn_cancel_ioc_scan.setFixedHeight(30)

        progress_ioc_layout.addWidget(self.ioc_progress_bar)
        progress_ioc_layout.addWidget(self.btn_cancel_ioc_scan)

        self.ioc_action_stack = QStackedWidget()
        self.ioc_action_stack.addWidget(scan_ioc_button_container)
        self.ioc_action_stack.addWidget(self.progress_ioc_container)

        ioc_layout.addWidget(input_label)
        ioc_layout.addWidget(self.text_area, 1)
        ioc_layout.addLayout(action_bar_layout)
        ioc_layout.addWidget(self.ioc_action_stack)
        return ioc_tab

    def _create_ai_controls(self) -> QHBoxLayout:
        ai_controls_layout = QHBoxLayout()
        ai_label = QLabel(T("ai_model_label"))
        ai_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.selected_model = QComboBox()
        self.selected_model.addItem("Carregando...")
        self.selected_model.setEnabled(False)
        self.btn_ai_summary = QPushButton(T("generate_text_summary_button"))
        self.btn_ai_summary.setStyleSheet(self.STYLE_AI_BUTTON_INACTIVE)
        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary.clicked.connect(lambda: self._initiate_ai_summary(generate_pdf=False))
        self.btn_ai_summary_pdf = QPushButton(T("generate_pdf_summary_button"))
        self.btn_ai_summary_pdf.setStyleSheet(self.STYLE_AI_BUTTON_INACTIVE)
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
        self.statusBar().showMessage(" | ".join(status_parts) or "Não foi possível buscar dados de uso. Verifique as chaves de API.")

    def open_settings_window(self) -> None:
        if SettingsDialog(self).exec():
            self.load_models_async()
            self._update_api_usage()

    def load_release_notes_async(self) -> None:
        self.release_notes_box.setPlainText("Buscando últimas atualizações...")
        self.release_thread = ReleaseWorker()
        self.release_thread.finished.connect(self.on_release_info_fetched)
        self.release_thread.start()

    def on_release_info_fetched(self, release_info: Dict[str, Any]) -> None:
        if hasattr(self, 'update_notification_widget'):
            self.update_notification_widget.deleteLater()

        if "error" in release_info:
            self.release_notes_box.setHtml(f"<b>Não foi possível carregar as notas da versão:</b><br>{release_info['error']}")
            return

        latest_version_str = re.sub(r'[^0-9.]', '', release_info.get("tag_name", "0.0.0"))
        try:
            latest_version = tuple(map(int, latest_version_str.split('.'))) if latest_version_str else (0,)
            current_version = tuple(map(int, __version__.split('.')))
        except (ValueError, TypeError):
            latest_version, current_version = (0,), (0,)

        if latest_version > current_version:
            platform_identifier = ".exe" if sys.platform == "win32" else ".dmg" if sys.platform == "darwin" else ".appimage"
            asset = next((a for a in release_info.get("assets", []) if a.get("name", "").lower().endswith(platform_identifier)), None)
            self.update_info = {"url": asset.get("browser_download_url") if asset else None, "asset_name": asset.get("name") if asset else None}
            
            self.update_notification_widget = QWidget()
            self.update_notification_widget.setStyleSheet("background-color: #2c3e50; border-radius: 5px;")
            layout = QVBoxLayout(self.update_notification_widget)
            title = QLabel(f"Nova versão {latest_version_str} disponível!")
            title.setStyleSheet("color: #2ecc71; font-size: 16px; font-weight: bold;"); title.setAlignment(Qt.AlignCenter)
            subtitle = QLabel(f"Sua versão atual é a {__version__}."); subtitle.setStyleSheet("color: white;"); subtitle.setAlignment(Qt.AlignCenter)
            self.btn_update_now = QPushButton("Atualizar Agora")
            self.btn_update_now.setStyleSheet("background-color: #2ecc71; color: white; padding: 10px; font-weight: bold;")
            if not self.update_info["url"]:
                self.btn_update_now.setText(f"Executável para {sys.platform} não encontrado")
                self.btn_update_now.setEnabled(False)
            else:
                self.btn_update_now.clicked.connect(self.start_update_process)
            layout.addWidget(title); layout.addWidget(subtitle); layout.addWidget(self.btn_update_now)
            self.update_tab_layout.insertWidget(0, self.update_notification_widget)
        else:
            self.update_notification_widget = QWidget()
            self.update_notification_widget.setStyleSheet("background-color: #27ae60; border-radius: 5px; padding: 10px;")
            layout = QHBoxLayout(self.update_notification_widget)
            label = QLabel("Seu ThreatDeflect está atualizado!"); label.setStyleSheet("color: white; font-weight: bold;"); label.setAlignment(Qt.AlignCenter)
            layout.addWidget(label)
            self.update_tab_layout.insertWidget(0, self.update_notification_widget)
        
        line = QWidget(); line.setFixedHeight(1); line.setStyleSheet("background-color: #7f8c8d;")
        self.update_tab_layout.insertWidget(1, line)
        
        body = release_info.get('body', 'Conteúdo não disponível.').replace('\r\n', '<br>')
        body = re.sub(r'###\s*(.*)', r'<h3>\1</h3>', body)
        release_html = f"<h2>Notas da Versão: {release_info.get('name')}</h2>{body}"
        self.release_notes_box.setHtml(release_html)
    
    def start_update_process(self) -> None:
        url, asset_name = self.update_info.get("url"), self.update_info.get("asset_name")
        if not url or not asset_name:
            QMessageBox.critical(self, "Erro", "URL de atualização não encontrada.")
            return

        self.btn_update_now.setEnabled(False); self.btn_update_now.setText("Baixando...")
        self.download_progress = QProgressDialog("Baixando atualização...", "Cancelar", 0, 100, self)
        self.download_progress.setWindowTitle("Atualização em Progresso"); self.download_progress.setWindowModality(Qt.WindowModal); self.download_progress.show()

        self.download_worker = DownloadWorker(url, asset_name)
        self.download_progress.canceled.connect(self.download_worker.requestInterruption)
        self.download_worker.progress.connect(lambda d, t: self.download_progress.setValue(int(d / t * 100) if t > 0 else 0))
        self.download_worker.finished.connect(self.on_download_finished)
        self.download_worker.start()

    def on_download_finished(self, success: bool, downloaded_path: str, error_message: str) -> None:
        self.download_progress.close()
        self.btn_update_now.setEnabled(True); self.btn_update_now.setText("Atualizar Agora")

        if not success:
            QMessageBox.critical(self, "Falha no Download", f"Não foi possível baixar a atualização:\n{error_message}")
            return

        if QMessageBox.question(self, "Pronto para Atualizar", "Download concluído! O ThreatDeflect será fechado para aplicar a atualização. Deseja continuar?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
            updater_script_path = create_updater_script(downloaded_path, sys.executable, os.getpid())
            if not updater_script_path:
                QMessageBox.critical(self, "Erro Crítico", "Não foi possível criar o script de atualização.")
                return
            try:
                subprocess.Popen([updater_script_path], shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0)
                QApplication.instance().quit()
            except Exception as e:
                logging.error(f"Falha ao executar o script de atualizacao: {e}", exc_info=True)
                QMessageBox.critical(self, "Erro ao Atualizar", f"Não foi possível iniciar o atualizador:\n{e}")

    def check_api_key_on_startup(self) -> None:
        if not keyring.get_password("vtotalscan", "virustotal_api_key"):
            self.log("Nenhuma chave de API do VirusTotal encontrada.")
            if QMessageBox.warning(self, "Configuração Necessária", "A chave da API do VirusTotal não foi encontrada. Configure-a para continuar.", QMessageBox.Ok | QMessageBox.Cancel) == QMessageBox.Ok:
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
        filepath, _ = QFileDialog.getOpenFileName(self, T("import_targets_button"), "", "Arquivos de Texto (*.txt);;Todos os Arquivos (*)")
        if filepath:
            try:
                # Tenta ler o arquivo com tratamento para possíveis erros de codificação
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    self.text_area.setPlainText(f.read())
                self.log(f"Conteúdo de '{os.path.basename(filepath)}' carregado.")
            except OSError as e:
                # Captura erros de sistema operacional como o [Errno 22]
                logging.error(f"Erro de OS ao tentar ler o arquivo {filepath}: {e}", exc_info=True)
                QMessageBox.critical(self, "Erro de Arquivo", f"Não foi possível ler o arquivo selecionado.\n\n'{filepath}'\n\nEle parece ser um atalho ou um link especial, e não um arquivo de texto simples. Por favor, selecione um arquivo '.txt'.")
            except Exception as e:
                logging.error(f"Não foi possível ler o arquivo {filepath}: {e}", exc_info=True)
                QMessageBox.critical(self, "Erro", f"Não foi possível ler o arquivo:\n{e}")

    def select_repo_file(self) -> None:
        filepath, _ = QFileDialog.getOpenFileName(self, T("import_repos_button"), "", "Arquivos de Texto (*.txt);;Todos os Arquivos (*)")
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    self.repo_url_input.setPlainText(f.read())
                self.log(f"Conteúdo de '{os.path.basename(filepath)}' carregado.")
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Não foi possível ler o arquivo:\n{e}")

    def clear_text(self) -> None:
        self.text_area.clear()
        self.log("Área de alvos limpa.")

    def clear_repo_input(self) -> None:
        self.repo_url_input.clear()
        self.log("Área de repositórios limpa.")

    def log(self, message: str) -> None:
        self.log_console.append(f"[{time.strftime('%H:%M:%S')}] >> {message}")

    def _reset_results(self) -> None:
        self.last_ioc_results, self.last_file_results, self.last_repo_results = None, None, None
        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary_pdf.setEnabled(False)
        self.btn_ai_summary.setStyleSheet(self.STYLE_AI_BUTTON_INACTIVE)
        self.btn_ai_summary_pdf.setStyleSheet(self.STYLE_AI_BUTTON_INACTIVE)

    def start_repo_analysis(self) -> None:
        self._set_ui_for_analysis(True)
        self._reset_results()
        repo_urls, invalid, duplicates = parse_repo_urls(self.repo_url_input.toPlainText())
        if duplicates: QMessageBox.information(self, "Entradas Duplicadas", f"URLs duplicadas ignoradas:\n" + "\n".join(duplicates))
        if invalid: QMessageBox.warning(self, "Entradas Inválidas", f"Entradas ignoradas por não serem URLs válidas:\n" + "\n".join(invalid))
        if not repo_urls:
            QMessageBox.warning(self, "Nenhum Alvo", "Forneça URLs válidas.")
            self._set_ui_for_analysis(False)
            return
        save_path, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório", "Analise_Repositorios.xlsx", "Arquivos Excel (*.xlsx)")
        if not save_path:
            self._set_ui_for_analysis(False)
            return
        if not is_file_writable(save_path):
            QMessageBox.critical(self, "Erro de Permissão", f"Não é possível escrever em:\n{save_path}")
            self._set_ui_for_analysis(False)
            return

        self.log(f"Análise de {len(repo_urls)} repositório(s) iniciada...")

        self.repo_action_stack.setCurrentWidget(self.progress_repo_container)
        self.repo_progress_bar.setRange(0, 0)
        self.repo_progress_bar.setFormat("Analisando repositórios...")
        
        self.repo_thread = RepoAnalysisWorker(repo_urls, save_path)
        self.btn_cancel_repo_scan.clicked.connect(self.repo_thread.requestInterruption)
        self.repo_thread.log_message.connect(self.log)
        self.repo_thread.finished.connect(self.on_analysis_finished)
        self.repo_thread.start()

    def start_ioc_analysis(self) -> None:
        self._set_ui_for_analysis(True)
        self._reset_results()
        filepath, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório Excel", "Analise_IOCs.xlsx", "Arquivos Excel (*.xlsx)")
        if not filepath:
            self._set_ui_for_analysis(False)
            return
        if not is_file_writable(filepath):
            QMessageBox.critical(self, "Erro de Permissão", f"Não é possível escrever em:\n{filepath}")
            self._set_ui_for_analysis(False)
            return
        
        ips, urls = parse_targets(self.text_area.toPlainText())
        total_targets = len(ips) + len(urls)
        
        self.ioc_action_stack.setCurrentWidget(self.progress_ioc_container)
        self.ioc_progress_bar.setRange(0, total_targets)
        self.ioc_progress_bar.setValue(0)
        self.ioc_progress_bar.setFormat(f"%v / %m ({'%p'}%)")

        self.analysis_thread = AnalysisWorker(self.text_area.toPlainText(), filepath)
        self.btn_cancel_ioc_scan.clicked.connect(self.analysis_thread.requestInterruption)
        self.analysis_thread.log_message.connect(self.log)
        self.analysis_thread.progress_update.connect(self._update_progress)
        self.analysis_thread.finished.connect(self.on_analysis_finished)
        self.analysis_thread.start()

    def start_file_analysis(self) -> None:
        self._set_ui_for_analysis(True)
        self._reset_results()
        file_paths, _ = QFileDialog.getOpenFileNames(self, T("check_file_reputation_button"))
        if not file_paths:
            self._set_ui_for_analysis(False)
            return

        valid_files = [p for p in file_paths if os.path.isfile(p)]
        invalid_entries = [p for p in file_paths if not os.path.isfile(p)]

        if invalid_entries:
            QMessageBox.warning(self, "Itens Inválidos", 
                                f"Os seguintes itens não são arquivos locais válidos e foram ignorados:\n\n" + 
                                "\n".join(invalid_entries))

        if not valid_files:
            self.log("Nenhum arquivo local válido foi selecionado para análise.")
            self._set_ui_for_analysis(False)
            return
        
        save_path, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório de Arquivos", "Analise_Arquivos.xlsx", "Arquivos Excel (*.xlsx)")
        if not save_path:
            self._set_ui_for_analysis(False)
            return
        if not is_file_writable(save_path):
            QMessageBox.critical(self, "Erro de Permissão", f"Não é possível escrever em:\n{save_path}")
            self._set_ui_for_analysis(False)
            return

        self.log(f"Análise de {len(valid_files)} arquivo(s) iniciada...")
        
        self.ioc_action_stack.setCurrentWidget(self.progress_ioc_container)
        self.ioc_progress_bar.setRange(0, 0)
        self.ioc_progress_bar.setFormat("Analisando arquivos...")

        self.file_thread = FileAnalysisWorker(valid_files, save_path)
        self.btn_cancel_ioc_scan.clicked.connect(self.file_thread.requestInterruption)
        self.file_thread.log_message.connect(self.log)
        self.file_thread.finished.connect(self.on_analysis_finished)
        self.file_thread.start()
        
    def _update_progress(self, current: int, total: int) -> None:
        sender = self.sender()
        if self.ioc_progress_bar.maximum() == 0 and total > 0:
            self.ioc_progress_bar.setRange(0, total)
            self.ioc_progress_bar.setFormat(f"%v / %m ({'%p'}%)")
            
        if isinstance(sender, AnalysisWorker) or isinstance(sender, FileAnalysisWorker):
            self.ioc_progress_bar.setMaximum(total)
            self.ioc_progress_bar.setValue(current)

    def on_analysis_finished(self, success: bool, filepath_or_error: str) -> None:
        sender_thread = self.sender()
        results = getattr(sender_thread, 'results', None)

        if isinstance(sender_thread, RepoAnalysisWorker):
            self.repo_action_stack.setCurrentWidget(self.repo_action_stack.widget(0))
            try: self.btn_cancel_repo_scan.clicked.disconnect()
            except RuntimeError: pass
        else:
            self.ioc_action_stack.setCurrentWidget(self.ioc_action_stack.widget(0))
            try: self.btn_cancel_ioc_scan.clicked.disconnect()
            except RuntimeError: pass
        
        if filepath_or_error == "CANCELLED":
            pass
        elif success:
            self._update_api_usage()
            
            if results:
                if 'ips' in results or 'urls' in results: self.last_ioc_results = results
                elif 'repositories' in results: self.last_repo_results = results
                elif 'files' in results: self.last_file_results = results
            
            if any([self.last_ioc_results, self.last_file_results, self.last_repo_results]):
                self.btn_ai_summary.setEnabled(True)
                self.btn_ai_summary_pdf.setEnabled(True)
                self.btn_ai_summary.setStyleSheet(self.STYLE_AI_BUTTON_ACTIVE)
                self.btn_ai_summary_pdf.setStyleSheet(self.STYLE_AI_BUTTON_ACTIVE)

            self.log(f"Relatório salvo em: {filepath_or_error}")

            msg_box = QMessageBox(self)
            msg_box.setWindowTitle(T("analysis_finished_title"))
            msg_box.setTextFormat(Qt.RichText)
            report_path = Path(filepath_or_error)
            msg_box.setText(T("analysis_finished_text").format(
                report_path=report_path.as_uri(),
                report_path_text=report_path
            ))
            msg_box.exec()
        else: 
            if filepath_or_error == "NO_TARGETS":
                QMessageBox.warning(self, "Aviso", "Nenhum IP ou URL válido foi encontrado.")
                self.log("Nenhum alvo válido.")
            elif filepath_or_error == "NO_VALID_FILES":
                QMessageBox.warning(self, "Aviso", "Nenhum arquivo válido ou legível foi processado.")
                self.log("Nenhum arquivo válido para análise.")
            else:
                self.log(f"A análise falhou: {filepath_or_error}")
                QMessageBox.critical(self, "Erro na Análise", f"Ocorreu um erro: {filepath_or_error}")
        
        self._set_ui_for_analysis(False)
                

    def _initiate_ai_summary(self, generate_pdf: bool) -> None:
        if not any([self.last_ioc_results, self.last_file_results, self.last_repo_results]):
            QMessageBox.warning(self, "Aviso", "Realize uma análise primeiro."); return
            
        selected_model_text = self.selected_model.currentText()
        if "Erro:" in selected_model_text or "não encontrado" in selected_model_text:
            QMessageBox.warning(self, "Configuração de IA Inválida", "Verifique as Configurações."); return
            
        filepath = ""
        if generate_pdf:
            filepath, _ = QFileDialog.getSaveFileName(self, "Salvar Resumo em PDF", "Resumo_IA.pdf", "Arquivos PDF (*.pdf)")
            if not filepath: return
                
        combined_results = {
            "ips": self.last_ioc_results.get('ips', {}) if self.last_ioc_results else {},
            "urls": self.last_ioc_results.get('urls', {}) if self.last_ioc_results else {},
            "files": self.last_file_results.get('files', {}) if self.last_file_results else {},
            "repositories": self.last_repo_results.get('repositories', []) if self.last_repo_results else []
        }
        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary_pdf.setEnabled(False)
        self.btn_ai_summary.setStyleSheet(self.STYLE_AI_BUTTON_INACTIVE)
        self.btn_ai_summary_pdf.setStyleSheet(self.STYLE_AI_BUTTON_INACTIVE)
        
        self.ai_summary_box.setPlainText("Analisando com IA..." if not generate_pdf else "Gerando PDF com IA...")
        
        self.ai_thread = AISummaryWorker(combined_results, selected_model_text)
        self.ai_thread.log_message.connect(self.log)
        self.ai_thread.status_popup.connect(self.show_status_popup)

        if generate_pdf:
            self.ai_thread.finished.connect(lambda summary: self.on_ai_finished_pdf(summary, filepath))
        else:
            self.ai_thread.finished.connect(self.on_ai_finished_text)
        self.ai_thread.start()

    def on_ai_finished_text(self, summary: str) -> None:
        self.ai_summary_box.setPlainText(summary)
        self.tab_view_results.setCurrentIndex(1)
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary_pdf.setEnabled(True)
        self.btn_ai_summary.setStyleSheet(self.STYLE_AI_BUTTON_ACTIVE)
        self.btn_ai_summary_pdf.setStyleSheet(self.STYLE_AI_BUTTON_ACTIVE)

    def on_ai_finished_pdf(self, summary: str, filepath: str) -> None:
        try:
            reporter = ReportGenerator(
                ip_results=self.last_ioc_results.get('ips', {}) if self.last_ioc_results else {},
                url_results=self.last_ioc_results.get('urls', {}) if self.last_ioc_results else {},
                file_results=self.last_file_results.get('files', {}) if self.last_file_results else {},
                repo_results=self.last_repo_results.get('repositories', []) if self.last_repo_results else []
            )
            reporter.generate_pdf_summary(filepath, summary)
            self.log(f"Resumo PDF salvo em: {filepath}")
            msg_box = QMessageBox(self); msg_box.setWindowTitle(T("analysis_finished_title"))
            msg_box.setTextFormat(Qt.RichText)
            msg_box.setText(f"<p>PDF gerado!</p><p>Salvo em:<br><a href='{Path(filepath).as_uri()}'>{filepath}</a></p>")
            msg_box.exec()
            self.ai_summary_box.setPlainText(summary)
            self.tab_view_results.setCurrentIndex(1)
        except Exception as e:
            logging.error(f"Falha ao gerar o relatório em PDF: {e}", exc_info=True)
            QMessageBox.critical(self, "Erro", f"Ocorreu um erro ao gerar o relatório em PDF:\n{e}")
        finally:
            self.btn_ai_summary.setEnabled(True)
            self.btn_ai_summary_pdf.setEnabled(True)
            self.btn_ai_summary.setStyleSheet(self.STYLE_AI_BUTTON_ACTIVE)
            self.btn_ai_summary_pdf.setStyleSheet(self.STYLE_AI_BUTTON_ACTIVE)

def main():
    """Função principal para iniciar a aplicação GUI."""
    setup_logging()
    logging.info("Aplicação ThreatDeflect (GUI) iniciada.")

    if sys.platform == "win32":
        myappid = 'DevGreick.ThreatDeflect.1.0'
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

    app = QApplication(sys.argv)
    
    app.setWindowIcon(QIcon(resource_path("spy2.ico")))

    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(45, 45, 45)); palette.setColor(QPalette.WindowText, Qt.white); palette.setColor(QPalette.Base, QColor(25, 25, 25)); palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53)); palette.setColor(QPalette.ToolTipBase, Qt.white); palette.setColor(QPalette.ToolTipText, Qt.white); palette.setColor(QPalette.Text, Qt.white); palette.setColor(QPalette.Button, QColor(53, 53, 53)); palette.setColor(QPalette.ButtonText, Qt.white); palette.setColor(QPalette.BrightText, Qt.red); palette.setColor(QPalette.Link, QColor(42, 130, 218)); palette.setColor(QPalette.Highlight, QColor(42, 130, 218)); palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)
    gui = VtotalscanGUI()
    gui.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
