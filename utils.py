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

import hashlib
import ipaddress
import logging
import os
import re
import sys
from pathlib import Path
from typing import List, Set, Tuple, Any, Dict, Optional


def get_config_path() -> Path:
    """Retorna o caminho absoluto para o arquivo de configuração, compatível com múltiplos OS."""
    app_name = "ThreatSpy"
    if sys.platform == "win32":
        config_dir = Path(os.getenv('APPDATA', '')) / app_name
    elif sys.platform == "darwin":
        config_dir = Path.home() / "Library" / "Application Support" / app_name
    else: # Linux e outros
        config_dir = Path.home() / ".config" / app_name
    
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "API_KEY.ini"


def resource_path(relative_path: str) -> str:
    """ Obtém o caminho absoluto para o recurso, para dev e PyInstaller """
    try:
        # PyInstaller cria uma pasta temporária e armazena o caminho em _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


def is_file_writable(filepath: str) -> bool:
    """ Verifica se um arquivo pode ser escrito. """
    try:
        f = open(filepath, 'a')
        f.close()
        # Se o arquivo não existia, a abertura em modo 'a' o cria. Removemos para não deixar lixo.
        if not os.path.exists(filepath):
             os.remove(filepath)
        return True
    except (IOError, OSError):
        return False


def parse_repo_urls(text: str) -> Tuple[List[str], List[str], List[str]]:
    """Analisa um texto e extrai URLs de repositório GitHub/GitLab válidas."""
    seen_urls: Set[str] = set()
    valid_urls: List[str] = []
    invalid_lines: List[str] = []
    duplicate_lines: List[str] = []
    
    full_url_pattern = re.compile(r'^(?:https?:\/\/)?(?:www\.)?(github\.com|gitlab\.com)\/([\w.-]+\/[\w.-]+(?:[\/\w.-])*)', re.IGNORECASE)
    shorthand_pattern = re.compile(r'^([\w.-]+\/[\w.-]+)$')

    for line in text.splitlines():
        if not (line := line.strip()):
            continue
        
        normalized_url = ""
        if full_match := full_url_pattern.match(line):
            domain = full_match.group(1).lower()
            repo_path = full_match.group(2).removesuffix('.git')
            normalized_url = f"https://{domain}/{repo_path}"
        elif shorthand_match := shorthand_pattern.match(line):
            normalized_url = f"https://github.com/{shorthand_match.group(1)}"
        else:
            invalid_lines.append(line)
            continue
        
        if normalized_url.lower() in seen_urls:
            duplicate_lines.append(line)
        else:
            valid_urls.append(normalized_url)
            seen_urls.add(normalized_url.lower())
            
    return sorted(valid_urls), invalid_lines, sorted(list(set(duplicate_lines)))


def parse_targets(text: str) -> Tuple[List[str], List[str]]:
    """Analisa um texto e extrai IPs e URLs válidos."""
    valid_ips: Set[str] = set()
    valid_urls: Set[str] = set()
    
    hostname_pattern = re.compile(r'((([a-z0-9])|([a-z0-9][a-z0-9\-]{0,61}[a-z0-9]))\.)*(([a-z0-9])|([a-z0-9][a-z0-9\-]{0,61}[a-z0-9]))')

    for line in text.splitlines():
        if not (line := line.strip().lower()):
            continue
        try:
            ipaddress.ip_address(line)
            valid_ips.add(line)
        except ValueError:
            domain_part = re.sub(r'^[a-z]+://', '', line).split('/')[0]
            if domain_part and hostname_pattern.fullmatch(domain_part):
                line = line.rstrip('/')
                valid_urls.add('http://' + line if not re.match(r'^[a-z]+://', line) else line)
            else:
                logging.warning(f"Entrada ignorada (não é IP ou domínio válido): '{line}'")

    return sorted(list(valid_ips)), sorted(list(valid_urls))


def calculate_sha256(filepath: str) -> Optional[str]:
    """Calcula o hash SHA256 de um arquivo."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except IOError as e:
        logging.error(f"Erro ao ler o arquivo {filepath}: {e}")
        return None


def defang_ioc(ioc_string: str) -> str:
    """Converte um IOC para um formato "defanged" para exibição segura."""
    if not ioc_string:
        return ""
    return ioc_string.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')


def safe_get(data: Dict[str, Any], path: str, default: Any = None) -> Any:
    """Extrai um valor de um dicionário aninhado usando uma string de caminho."""
    if not isinstance(data, dict):
        return default
    keys = path.split('.')
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, list):
            try:
                current = current[int(key)]
            except (ValueError, IndexError):
                return default
        else:
            return default
        if current is None:
            return default
    return current
