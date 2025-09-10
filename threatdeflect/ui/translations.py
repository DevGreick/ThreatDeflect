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
    "pt_br": {"window_title": "ThreatDeflect", "file_menu": "Arquivo"},
    "en_us": {"window_title": "ThreatDeflect", "file_menu": "File"}
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
            
            # 3. Salva o idioma detectado para as próximas execuções
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
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logging.error(f"Arquivo de tradução para '{self.language}' não encontrado ou inválido. Usando fallback.")
            return FALLBACK_TRANSLATIONS.get(self.language, FALLBACK_TRANSLATIONS['en_us'])

    def get(self, key: str) -> str:
        """Retorna o texto traduzido para uma chave específica."""
        return self.translations.get(key, f"_{key}_")

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