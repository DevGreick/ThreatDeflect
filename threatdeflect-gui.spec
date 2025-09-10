# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

# Define o diretório de assets de forma relativa
assets_dir = Path('threatdeflect/assets')

# Define o caminho do ícone com base no sistema operacional
if sys.platform == 'darwin':
    icon_path = assets_dir / 'spy2.icns'
elif sys.platform == 'win32':
    icon_path = assets_dir / 'spy2.ico'
else:
    icon_path = assets_dir / 'spy2.png'

a = Analysis(
    ['threatdeflect/ui/main_gui.py'],
    # --- CORREÇÃO APLICADA ---
    # Adiciona o diretório atual ('.') ao pathex para ajudar a encontrar o módulo 'threatdeflect'.
    pathex=['.'],
    binaries=[],
    # Adiciona TODOS os dados necessários com caminhos relativos.
    datas=[
        ('threatdeflect/assets', 'threatdeflect/assets'),
        ('threatdeflect/core/rules.yaml', 'threatdeflect/core')
    ],
    # --- FIM DA CORREÇÃO ---
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='threatdeflect-gui',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icon_path)
)

if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='threatdeflect-gui.app',
        icon=str(icon_path),
        bundle_identifier=None,
    )