# -*- mode: python ; coding: utf-8 -*-
import sys
import os
from pathlib import Path

# --- CONFIGURACAO DE CAMINHOS ---
BASE_DIR = Path(os.getcwd())
ASSETS_DIR = BASE_DIR / 'threatdeflect' / 'assets'
RUST_TARGET_DIR = BASE_DIR / 'rust_core' / 'target' / 'release'

# --- DETECCAO DO SISTEMA ---
is_win = sys.platform.startswith('win')
is_mac = sys.platform.startswith('darwin')
is_linux = sys.platform.startswith('linux')

# 1. Icone
if is_win:
    icon_file = ASSETS_DIR / 'spy2.ico'
elif is_mac:
    icon_file = ASSETS_DIR / 'spy2.icns'
else:
    icon_file = None

if icon_file and not icon_file.exists():
    print(f"AVISO: Ícone {icon_file} não encontrado. Build continuará sem ícone.")
    icon_file = None

# 2. Motor Rust Compilado
binaries = []

if is_win:
    rust_bin_source = RUST_TARGET_DIR / 'threatdeflect_rs.dll'
    if not rust_bin_source.exists():
        rust_bin_source = RUST_TARGET_DIR / 'threatdeflect_rs.pyd'
    if rust_bin_source.exists():
        binaries.append((str(rust_bin_source), '.'))

elif is_linux:
    rust_bin_source = RUST_TARGET_DIR / 'libthreatdeflect_rs.so'
    if rust_bin_source.exists():
        binaries.append((str(rust_bin_source), '.'))

elif is_mac:
    rust_bin_source = RUST_TARGET_DIR / 'libthreatdeflect_rs.dylib'
    if rust_bin_source.exists():
        binaries.append((str(rust_bin_source), '.'))

if not binaries:
    print("AVISO: Binario Rust nao encontrado em target/release. Build continuara sem motor Rust.")

# --- ANALISE DO PYINSTALLER ---
a = Analysis(
    ['threatdeflect/cli/main.py'],
    pathex=[str(BASE_DIR)],
    binaries=binaries,
    datas=[
        ('threatdeflect/assets/lang', 'assets/lang'),
        ('threatdeflect/core/rules.yaml', 'core'),
    ],
    hiddenimports=[
        'threatdeflect_rs',
        'click',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'PySide6', 'PyQt5', 'PyQt6', 'tkinter',
        'matplotlib', 'numpy', 'pandas', 'scipy',
        'PIL', 'cv2',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe_name = 'ThreatDeflect-CLI'
if is_win:
    exe_name = 'ThreatDeflect-CLI'
elif is_mac:
    exe_name = 'ThreatDeflect-CLI-macOS'
else:
    exe_name = 'ThreatDeflect-CLI-Linux'

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=exe_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icon_file) if icon_file else None,
)
