# tests/test_main_gui.py

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from PySide6.QtCore import Qt, QObject, Signal
from PySide6.QtWidgets import QApplication, QMessageBox, QPushButton

from threatdeflect.ui.main_gui import VtotalscanGUI, SettingsDialog
from threatdeflect.ui.translations import T

pytest_plugins = ["pytest-qt"]

@pytest.fixture
def app(qtbot, monkeypatch):
    """
    Fixture principal para a aplicação GUI. Cria a janela e desativa todas as
    funções de inicialização que rodam em segundo plano para isolar os testes da UI.
    """
    monkeypatch.setattr(VtotalscanGUI, 'load_models_async', lambda self: None)
    monkeypatch.setattr(VtotalscanGUI, 'load_release_notes_async', lambda self: None)
    monkeypatch.setattr(VtotalscanGUI, 'check_api_key_on_startup', lambda self: None)
    monkeypatch.setattr(VtotalscanGUI, '_update_api_usage', lambda self: None)
    
    window = VtotalscanGUI()
    qtbot.addWidget(window)
    window.show()
    yield window

@patch('threatdeflect.ui.main_gui.AnalysisWorker')
def test_start_ioc_analysis_flow(MockAnalysisWorker, qtbot, app, monkeypatch, tmp_path):
    """Testa se o AnalysisWorker correto é criado e iniciado ao clicar no botão."""
    mock_worker_instance = MagicMock()
    MockAnalysisWorker.return_value = mock_worker_instance
    
    safe_report_path = tmp_path / "report.xlsx"
    monkeypatch.setattr('PySide6.QtWidgets.QFileDialog.getSaveFileName', lambda *args, **kwargs: (str(safe_report_path), None))

    app.text_area.setPlainText("8.8.8.8")
    qtbot.mouseClick(app.btn_scan_iocs, Qt.LeftButton)

    MockAnalysisWorker.assert_called_once_with("8.8.8.8", str(safe_report_path))
    mock_worker_instance.start.assert_called_once()

@patch('threatdeflect.ui.main_gui.RepoAnalysisWorker')
def test_start_repo_analysis_flow(MockRepoAnalysisWorker, qtbot, app, monkeypatch, tmp_path):
    """Testa se o RepoAnalysisWorker correto é criado e iniciado ao clicar no botão."""
    mock_worker_instance = MagicMock()
    MockRepoAnalysisWorker.return_value = mock_worker_instance
    
    safe_report_path = tmp_path / "report.xlsx"
    monkeypatch.setattr('PySide6.QtWidgets.QFileDialog.getSaveFileName', lambda *args, **kwargs: (str(safe_report_path), None))

    app.repo_url_input.setPlainText("https://github.com/user/repo")
    qtbot.mouseClick(app.btn_scan_repo, Qt.LeftButton)

    MockRepoAnalysisWorker.assert_called_once_with(["https://github.com/user/repo"], str(safe_report_path))
    mock_worker_instance.start.assert_called_once()

@patch('threatdeflect.ui.main_gui.FileAnalysisWorker')
def test_start_file_analysis_button_flow(MockFileAnalysisWorker, qtbot, app, monkeypatch, tmp_path):
    """Testa se o FileAnalysisWorker correto é criado e iniciado ao clicar no botão."""
    mock_worker_instance = MagicMock()
    MockFileAnalysisWorker.return_value = mock_worker_instance

    mock_selected_files = ['C:\\fake_path\\malware.exe']
    mock_save_path = tmp_path / "report.xlsx"
    
    monkeypatch.setattr('PySide6.QtWidgets.QFileDialog.getOpenFileNames', lambda *args, **kwargs: (mock_selected_files, None))
    monkeypatch.setattr('PySide6.QtWidgets.QFileDialog.getSaveFileName', lambda *args, **kwargs: (str(mock_save_path), None))
    monkeypatch.setattr('os.path.isfile', lambda path: True)
    
    qtbot.mouseClick(app.btn_scan_files, Qt.LeftButton)
    
    MockFileAnalysisWorker.assert_called_once_with(mock_selected_files, str(mock_save_path))
    mock_worker_instance.start.assert_called_once()

@patch('threatdeflect.ui.main_gui.RepoAnalysisWorker')
def test_cancel_button_requests_interruption(MockRepoWorker, qtbot, app, monkeypatch, tmp_path):
    """Testa se clicar no botão 'Cancelar' chama o método 'requestInterruption' do worker."""
    mock_worker_instance = MockRepoWorker.return_value
    monkeypatch.setattr('PySide6.QtWidgets.QFileDialog.getSaveFileName', lambda *a, **k: (str(tmp_path / "report.xlsx"), None))
    
    app.repo_url_input.setPlainText("user/repo")
    qtbot.mouseClick(app.btn_scan_repo, Qt.LeftButton)

    qtbot.mouseClick(app.btn_cancel_repo_scan, Qt.LeftButton)
    mock_worker_instance.requestInterruption.assert_called_once()

@patch('threatdeflect.ui.main_gui.clear_all_caches')
@patch('PySide6.QtWidgets.QMessageBox.question')
def test_clear_cache_button_flow(mock_question, mock_clear_caches, qtbot):
    """Testa se o botão 'Limpar Cache' na tela de configurações funciona como esperado."""
    mock_question.return_value = QMessageBox.Yes
    mock_clear_caches.return_value = (True, "/fake/cache/path")
    
    dialog = SettingsDialog()
    qtbot.addWidget(dialog)
    
    clear_cache_button = None
    for child in dialog.findChildren(QPushButton):
        if "Limpar Cache" in child.text():
            clear_cache_button = child
            break
    
    assert clear_cache_button is not None, "Botão 'Limpar Cache' não encontrado na janela de configurações"

    qtbot.mouseClick(clear_cache_button, Qt.LeftButton)
    
    mock_question.assert_called_once()
    mock_clear_caches.assert_called_once()