# threatdeflect/core/cache_manager.py

import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, Any, Tuple
import shutil

from threatdeflect.utils.utils import get_config_path

class CacheManager:
    """Gerencia o cache de resultados da análise de repositórios em um banco de dados SQLite."""

    def __init__(self, repo_url: str):
        self.repo_url = repo_url
        self.db_path = self._get_cache_db_path()
        self._conn = None
        self._ensure_db_and_table()

    def _get_cache_db_path(self) -> Path:
        """Determina o caminho do banco de dados de cache."""
        config_dir = get_config_path().parent
        cache_dir = config_dir / ".threatdeflect_cache"
        cache_dir.mkdir(exist_ok=True)
        
        repo_id = "".join(filter(str.isalnum, self.repo_url))
        return cache_dir / f"{repo_id}.sqlite"

    def _connect(self) -> sqlite3.Connection:
        """Estabelece a conexão com o banco de dados."""
        if self._conn is None:
            try:
                self._conn = sqlite3.connect(self.db_path)
            except sqlite3.Error as e:
                logging.error(f"Erro ao conectar ao banco de dados de cache {self.db_path}: {e}")
                raise
        return self._conn

    def _ensure_db_and_table(self) -> None:
        """Garante que a tabela de cache exista no banco de dados."""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_cache (
                file_path TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL,
                analysis_data TEXT NOT NULL
            )
            """)
            conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Erro ao criar a tabela de cache: {e}")

    def get_cached_results(self) -> Dict[str, Dict[str, Any]]:
        """Recupera todos os resultados em cache para o repositório."""
        cached_data = {}
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("SELECT file_path, content_hash, analysis_data FROM file_cache")
            for row in cursor.fetchall():
                file_path, content_hash, data_json = row
                cached_data[file_path] = {
                    'hash': content_hash,
                    'data': json.loads(data_json)
                }
        except (sqlite3.Error, json.JSONDecodeError) as e:
            logging.error(f"Erro ao ler o cache: {e}. O cache será ignorado.")
            self.update_cache({})
            return {}
        return cached_data

    def update_cache(self, repo_state: Dict[str, Dict[str, Any]]) -> None:
        """Atualiza o cache com o estado mais recente do repositório e seus achados."""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM file_cache")

            rows_to_insert = []
            for file_path, data in repo_state.items():
                data_json = json.dumps(data.get('data', {}))
                rows_to_insert.append((file_path, data['hash'], data_json))
            
            cursor.executemany(
                "INSERT OR REPLACE INTO file_cache (file_path, content_hash, analysis_data) VALUES (?, ?, ?)",
                rows_to_insert
            )
            conn.commit()
        except (sqlite3.Error, json.JSONDecodeError) as e:
            logging.error(f"Erro ao atualizar o cache: {e}")

    def close(self) -> None:
        """Fecha a conexão com o banco de dados."""
        if self._conn:
            self._conn.close()
            self._conn = None


def clear_all_caches() -> Tuple[bool, str]:
    """
    Deleta de forma segura todo o diretório de cache da aplicação.
    """
    try:
        config_dir = get_config_path().parent
        cache_dir = config_dir / ".threatdeflect_cache"
        
        if cache_dir.exists() and cache_dir.is_dir():
            shutil.rmtree(cache_dir)
            cache_dir.mkdir(exist_ok=True)
            logging.info(f"Diretório de cache removido com sucesso: {cache_dir}")
            return True, str(cache_dir)
        else:
            logging.info("Nenhum diretório de cache encontrado para limpar.")
            return True, "Nenhum cache para limpar."
            
    except Exception as e:
        logging.error(f"Falha ao tentar limpar o diretório de cache: {e}", exc_info=True)
        return False, str(e)