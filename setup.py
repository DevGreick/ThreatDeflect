# ===================================================================
# Script de Configuração (Modo setuptools)
# ===================================================================
# ThreatDeflect
# Copyright (C) 2025 DevGreick <seczeror.ocelot245@passmail.net>
#
# Este script utiliza setuptools para tornar o projeto instalável via pip
# e para registrar os pontos de entrada (comandos de console).

from setuptools import setup, find_packages

# Lista de dependências necessárias para o projeto rodar.
# O pip irá instalá-las automaticamente.
install_requires = [
    "requests",
    "keyring",
    "PySide6",
    "typer[all]",
    "rich",
    "xlsxwriter",
    "reportlab",
    "PyYAML",
    "urllib3"
]

# Configuração principal do pacote
setup(
    name="threatdeflect",
    version="2.0.0",
    description="Ferramenta de análise de ameaças com interfaces GUI e CLI.",
    author="DevGreick",
    author_email="seczeror.ocelot245@passmail.net",
    
    # Encontra automaticamente todos os pacotes (pastas com __init__.py) no projeto.
    packages=find_packages(),
    
    # Lista de dependências de runtime.
    install_requires=install_requires,
    
    # Garante que arquivos não-.py (como assets, rules.yaml) sejam incluídos.
    include_package_data=True,
    package_data={
        # Inclui todos os arquivos dentro da pasta 'assets' do pacote 'threatdeflect'
        'threatdeflect': ['assets/*.*', 'assets/lang/*.*', 'core/rules.yaml'],
    },

    # Define os comandos que serão criados no ambiente ao instalar o pacote.
    entry_points={
        "console_scripts": [
            "threatdeflect-gui = threatdeflect.ui.main_gui:main",
            "threatdeflect = threatdeflect.cli.main:app",
        ]
    },
)
