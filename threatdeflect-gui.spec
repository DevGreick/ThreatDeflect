# -*- mode: python ; coding: utf-8 -*-
import sys
import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_dynamic_libs

# --- CONFIGURAÇÃO DE CAMINHOS ---
BASE_DIR = Path(os.getcwd())
ASSETS_DIR = BASE_DIR / 'threatdeflect' / 'assets'
RUST_TARGET_DIR = BASE_DIR / 'rust_core' / 'target' / 'release'

# --- DETECÇÃO DO SISTEMA E PARTICULARIDADES ---
is_win = sys.platform.startswith('win')
is_mac = sys.platform.startswith('darwin')
is_linux = sys.platform.startswith('linux')

# 1. Definição do Ícone
if is_win:
    icon_file = ASSETS_DIR / 'spy2.ico'
elif is_mac:
    icon_file = ASSETS_DIR / 'spy2.icns'
else:
    icon_file = ASSETS_DIR / 'spy2.png'

# 2. Localização do Motor Rust Compilado (A "Mágica")
# O PyInstaller precisa pegar o binário nativo e colocar na pasta raiz interna
binaries = []

if is_win:
    # No Windows, o Rust gera .dll, mas o Python espera .pyd ou .dll
    rust_bin_source = RUST_TARGET_DIR / 'threatdeflect_rs.dll'
    if not rust_bin_source.exists():
        # Fallback: Tenta achar .pyd se foi renomeado pelo maturin
        rust_bin_source = RUST_TARGET_DIR / 'threatdeflect_rs.pyd'
    
    # Destino: '.' (raiz do executável)
    if rust_bin_source.exists():
        binaries.append((str(rust_bin_source), '.'))
        
elif is_linux:
    # No Linux, é libthreatdeflect_rs.so, mas o Python importa como threatdeflect_rs
    rust_bin_source = RUST_TARGET_DIR / 'libthreatdeflect_rs.so'
    if rust_bin_source.exists():
        # Importante: O destino deve manter o nome que o Python espera importar
        binaries.append((str(rust_bin_source), '.'))

elif is_mac:
    # No Mac, é .dylib, mas renomeamos para .so para o Python carregar
    rust_bin_source = RUST_TARGET_DIR / 'libthreatdeflect_rs.dylib'
    if rust_bin_source.exists():
        binaries.append((str(rust_bin_source), '.'))

# Se não achou o binário na pasta target, tenta coletar do ambiente virtual
if not binaries:
    print("AVISO: Binário Rust não encontrado em target/release. Tentando coletar do venv...")
    # Isso tenta achar o pacote instalado via pip/uv
    # Nota: Pode precisar de ajustes manuais dependendo do nome exato no site-packages

# --- ANÁLISE DO PYINSTALLER ---
a = Analysis(
    ['threatdeflect/ui/main_gui.py'],
    pathex=[str(BASE_DIR)],
    binaries=binaries,
    datas=[
        # ORIGEM (No seu PC)              # DESTINO (Dentro do EXE - Raiz)
        ('threatdeflect/assets',          'assets'), 
        ('threatdeflect/core/rules.yaml', 'core')
    ],
    hiddenimports=[
        'threatdeflect_rs', # Força o PyInstaller a ver nosso módulo Rust
        'PIL',              # Pillow (frequentemente precisa de ajuda)
        'PIL._tkinter_finder'
    ],
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
    [],
    name='ThreatDeflect',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False, # False = Sem janela preta de terminal (Modo GUI)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icon_file)
)

# --- PACOTE DE APLICATIVO (APENAS MAC) ---
if is_mac:
    app = BUNDLE(
        exe,
        name='ThreatDeflect.app',
        icon=str(icon_file),
        bundle_identifier='com.devgreick.threatdeflect',
        info_plist={
            'NSHighResolutionCapable': 'True'
        },
    )
