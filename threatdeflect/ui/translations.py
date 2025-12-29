# threatdeflect/ui/translations.py

import json
import os
import configparser
import logging
import locale 
from pathlib import Path
from typing import Dict, Any

from threatdeflect.utils.utils import get_config_path, resource_path


FALLBACK_TRANSLATIONS = {
    "pt_br": {
        "window_title": "ThreatDeflect v3.0",
        "file_menu": "Arquivo",
        "risk_unverified": "⚠️ RISCO NÃO VERIFICADO",
        "manual_check_prefix": "[CHECAGEM MANUAL]",
        "ai_limit_reached": "Limite de IA atingido. Priorizamos os itens de maior risco.",
        "ioc_limit_reached": "Limite de IOCs atingido. Analisando amostra estatística.",
        "performance_limit_title": "Limite de Performance",
        "scan_repo_button": "Analisar Repositório",
        "scan_ioc_button": "Analisar Alvos",
        "settings_title": "Configurações",
        "general_tab": "Geral",
        "api_keys_tab": "Chaves de API",
        "about_tab": "Sobre"
    },
    "en_us": {
        "window_title": "ThreatDeflect v3.0",
        "file_menu": "File",
        "risk_unverified": "⚠️ UNVERIFIED RISK",
        "manual_check_prefix": "[MANUAL CHECK]",
        "ai_limit_reached": "AI limit reached. Prioritizing highest risk items.",
        "ioc_limit_reached": "IOC limit reached. Analyzing statistical sample.",
        "performance_limit_title": "Performance Limit",
        "scan_repo_button": "Analyze Repository",
        "scan_ioc_button": "Analyze Targets",
        "settings_title": "Settings",
        "general_tab": "General",
        "api_keys_tab": "API Keys",
        "about_tab": "About"
    }
}

class Translator:
    def __init__(self):
        self.language = self._load_language_preference()
        self.translations = self._load_translations()

    
    def _load_language_preference(self) -> str:
        """
        Carrega a preferência de idioma.
        1. Tenta ler do settings.ini.
        2. Se não houver, detecta o idioma do SO.
        3. Se falhar, usa 'en_us' como padrão.
        """
        config = configparser.ConfigParser()
        config_path = get_config_path()
        config.read(config_path)

        
        if config.has_option('General', 'language'):
            return config.get('General', 'language', fallback='en_us')

        
        try:
            system_lang_code, _ = locale.getdefaultlocale()
            if system_lang_code and system_lang_code.lower().startswith('pt'):
                detected_lang = 'pt_br'
            else:
                detected_lang = 'en_us'
            
            logging.info(f"Nenhuma configuração de idioma encontrada. Detectado idioma do sistema: {detected_lang}")
            
            if not config.has_section('General'):
                config.add_section('General')
            config.set('General', 'language', detected_lang)
            with open(config_path, 'w') as configfile:
                config.write(configfile)
                
            return detected_lang

        except Exception as e:
            logging.warning(f"Não foi possível detectar o idioma do sistema: {e}. Usando 'en_us' como padrão.")
            return 'en_us'
   

    def _load_translations(self) -> Dict[str, str]:
        """Carrega o arquivo JSON de tradução correspondente ao idioma selecionado."""
        try:
            json_path_str = resource_path(os.path.join('lang', f'{self.language}.json'))
            with open(json_path_str, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                fallback = FALLBACK_TRANSLATIONS.get(self.language, FALLBACK_TRANSLATIONS['en_us'])
                return {**fallback, **loaded}
        except (FileNotFoundError, json.JSONDecodeError):
            logging.error(f"Arquivo de tradução para '{self.language}' não encontrado ou inválido. Usando fallback interno.")
            return FALLBACK_TRANSLATIONS.get(self.language, FALLBACK_TRANSLATIONS['en_us'])

    def get(self, key: str) -> str:
        """Retorna o texto traduzido para uma chave específica."""
        val = self.translations.get(key)
        if val:
            return val
            
        fallback_dict = FALLBACK_TRANSLATIONS.get(self.language, FALLBACK_TRANSLATIONS['en_us'])
        return fallback_dict.get(key, f"_{key}_")

translator = Translator()

def T(key: str, **kwargs: Any) -> str:
    """
    Função de atalho para tradução.
    Retorna o texto traduzido e o formata com quaisquer argumentos fornecidos.
    """
    translated_text = translator.get(key)
    if kwargs:
        try:
            return translated_text.format(**kwargs)
        except KeyError as e:
            logging.warning(f"Erro de formatação na chave '{key}'. Placeholder ausente: {e}. Texto: '{translated_text}'")
            return translated_text
    return translated_text
