import hashlib
import ipaddress
import logging
import os
import re
import sys
import tempfile
import time
import configparser
from pathlib import Path
from typing import List, Set, Tuple, Any, Dict, Optional
from urllib.parse import urlparse

def get_config_path() -> Path:
    app_name = "ThreatDeflect"
    config_dir: Path

    if sys.platform == "win32":
        appdata = Path(os.getenv('APPDATA', ''))
        config_dir = appdata.joinpath(app_name)
    elif sys.platform == "darwin":
        home = Path.home()
        config_dir = home.joinpath("Library", "Application Support", app_name)
    else:
        home = Path.home()
        config_dir = home.joinpath(".config", app_name)
    
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir.joinpath("settings.ini")

def get_log_path() -> Path:
    config_path = get_config_path()
    default_log_path = Path.home() / 'threatdeflect.log'

    if config_path.exists():
        config = configparser.ConfigParser()
        config.read(config_path)
        if log_path_str := config.get('General', 'log_path', fallback=None):
            log_path = Path(log_path_str)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            return log_path

    return default_log_path

import sys
from pathlib import Path

def resource_path(relative_path: str) -> str:
    """
    Localiza recursos (imagens, configs) tanto em DEV quanto no EXE (PyInstaller).
    Busca automaticamente nas pastas 'assets' e 'core'.
    """
    try:
        base_path = Path(sys._MEIPASS)
    except AttributeError:
        base_path = Path(__file__).resolve().parent.parent

    target_path = base_path.joinpath("assets", relative_path)
    if target_path.exists():
        return str(target_path)

    fallback_path = base_path.joinpath("core", relative_path)
    if fallback_path.exists():
        return str(fallback_path)
    
    return str(target_path)

def is_file_writable(filepath: str) -> bool:
    path = Path(filepath)
    try:
        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        
        path.touch()
        path.unlink()
        return True
    except (IOError, OSError):
        if path.exists():
            try:
                with open(path, 'a'):
                    pass
                return True
            except (IOError, OSError):
                return False
        return False

def create_updater_script(new_asset_path: str, current_executable_path: str, app_pid: int) -> Optional[str]:
    script_content = ""
    script_extension = ""
    temp_dir = tempfile.gettempdir()

    if sys.platform == "win32":
        script_extension = ".bat"
        script_content = f"""
@echo off
echo Aguardando o ThreatDeflect (PID: {app_pid}) fechar...
tasklist /FI "PID eq {app_pid}" | find ":" > nul
if errorlevel 1 (
    echo Processo encerrado.
) else (
    timeout /t 5 /nobreak > nul
)
echo Atualizando o executavel...
move /Y "{new_asset_path}" "{current_executable_path}"
echo Lancando nova versao...
start "" "{current_executable_path}"
echo Limpando...
(goto) 2>nul & del "%~f0"
"""
    else:
        script_extension = ".sh"
        script_content = f"""
#!/bin/sh
echo "Aguardando o ThreatDeflect (PID: {app_pid}) fechar..."
while kill -0 {app_pid} 2>/dev/null; do
    sleep 1
done
echo "Atualizando o executavel..."
mv -f "{new_asset_path}" "{current_executable_path}"
chmod +x "{current_executable_path}"
echo "Lancando nova versao..."
nohup "{current_executable_path}" &
echo "Limpando..."
rm -- "$0"
"""
    try:
        updater_path = os.path.join(temp_dir, f"updater_{int(time.time())}{script_extension}")
        with open(updater_path, "w", encoding='utf-8') as f:
            f.write(script_content)
        
        if sys.platform != "win32":
            os.chmod(updater_path, 0o755)
            
        return updater_path
    except Exception as e:
        logging.error(f"Falha ao criar script de atualizacao: {e}")
        return None

def parse_repo_urls(text: str) -> Tuple[List[str], List[str], List[str]]:
    seen_urls: Set[str] = set()
    valid_urls: List[str] = []
    invalid_lines: List[str] = []
    duplicate_lines: List[str] = []
    
    full_url_pattern = re.compile(r'^(?:https?:\/\/)?(?:www\.)?(github\.com|gitlab\.com)\/([\w.-]+\/[\w.-]+(?:[\/\w.-])*)', re.IGNORECASE)
    shorthand_pattern = re.compile(r'^([\w.-]+\/[\w.-]+)$')

    for line in text.splitlines():
        processed_line = line.split('#')[0].strip()
        if not processed_line:
            continue
        
        normalized_url = ""
        if full_match := full_url_pattern.match(processed_line):
            domain = full_match.group(1).lower()
            repo_path = full_match.group(2).removesuffix('.git')
            normalized_url = f"https://{domain}/{repo_path}"
        elif shorthand_match := shorthand_pattern.match(processed_line):
            normalized_url = f"https://github.com/{shorthand_match.group(1)}"
        else:
            invalid_lines.append(processed_line)
            continue
        
        if normalized_url.lower() in seen_urls:
            duplicate_lines.append(processed_line)
        else:
            valid_urls.append(normalized_url)
            seen_urls.add(normalized_url.lower())
            
    return sorted(valid_urls), invalid_lines, sorted(list(set(duplicate_lines)))

def parse_targets(text: str) -> Tuple[List[str], List[str]]:
    valid_ips: Set[str] = set()
    valid_urls: Set[str] = set()
    
    hostname_pattern = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

    for line in text.splitlines():
        processed_line = line.split('#')[0].strip()
        if not processed_line:
            continue

        try:
            ipaddress.ip_address(processed_line)
            valid_ips.add(processed_line)
            continue
        except ValueError:
            pass

        url_to_parse = processed_line
        if '://' not in url_to_parse:
            url_to_parse = 'https://' + url_to_parse

        try:
            parsed = urlparse(url_to_parse)
            if parsed.scheme and parsed.hostname and hostname_pattern.fullmatch(parsed.hostname):
                valid_urls.add(url_to_parse)
            else:
                logging.warning(f"Entrada ignorada (formato de URL inválido): '{processed_line}'")
        except Exception as e:
            logging.warning(f"Erro ao analisar a linha '{processed_line}' como URL: {e}")

    return sorted(list(valid_ips)), sorted(list(valid_urls))

def calculate_sha256(filepath: str) -> Optional[str]:
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
    if not ioc_string:
        return ""
    if "xn--" in ioc_string or '\u202e' in ioc_string:
        return ioc_string.replace('http://', 'hxxp://').replace('https://', 'hxxps://')
    return ioc_string.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')

def safe_get(data: Dict[str, Any], path: str, default: Any = None) -> Any:
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

def detect_visual_spoofing(text: str) -> Optional[str]:
    if not isinstance(text, str):
        return None
        
    text_lower = text.lower()
    
    if '\u202e' in text_lower:
        return "RTLO"
    
    if "xn--" in text_lower:
        return "Punycode/Cyrillic"
        
    for char in text:
        if 0x0400 <= ord(char) <= 0x04FF:
            return "Punycode/Cyrillic"
            
    return None