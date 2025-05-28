import logging
import os.path
import sqlite3
import sys
import tempfile
from abc import ABC
from typing import List, Optional, Tuple, Any, Generator

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider

logger = logging.getLogger(__name__)


class Sqlite3Scanner(AbstractScanner, ABC):
    """Implements SQLite3 database scanning"""

    @staticmethod
    def __walk(sqlite3db) -> Generator[Tuple[str, Any], None, None]:
        sqlite3db.row_factory = sqlite3.Row
        cursor = sqlite3db.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        for table in cursor.fetchall():
            table_name = table[0]
            try:
                cursor.execute(f"SELECT * FROM {table_name}")
                for row in cursor:
                    yield table_name, dict(row)
            except sqlite3.DatabaseError as exc:
                print(f"Error reading table {table_name}: {exc}")

    @staticmethod
    def walk_sqlite(data: bytes) -> Generator[Tuple[str, Any], None, None]:
        """Yields data from sqlite3 database"""
        if 10 < sys.version_info.minor:
            # Added in version 3.11
            with sqlite3.connect(":memory:") as sqlite3db:
                sqlite3db.deserialize(data)  # type: ignore
                yield from Sqlite3Scanner.__walk(sqlite3db)
        elif "nt" != os.name:
            # a tmpfile has to be used. TODO: remove when 3.10 will deprecate
            with tempfile.NamedTemporaryFile(suffix=".sqlite") as t:
                t.write(data)
                t.flush()
                with sqlite3.connect(t.name) as sqlite3db:
                    yield from Sqlite3Scanner.__walk(sqlite3db)
        elif "nt" == os.name:
            # windows trick. TODO: remove when 3.10 will deprecate
            with tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite") as t:
                t.write(data)
                t.flush()
            sqlite3db = sqlite3.connect(t.name)
            yield from Sqlite3Scanner.__walk(sqlite3db)
            sqlite3db.close()
            if os.path.exists(t.name):
                os.remove(t.name)

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Extracts data file from .ar (debian) archive and launches data_scan"""
        try:
            candidates: List[Candidate] = []
            new_limit = recursive_limit_size - len(data_provider.data)
            for table, row in self.walk_sqlite(data_provider.data):
                struct_content_provider = StructContentProvider(struct=row,
                                                                file_path=data_provider.file_path,
                                                                file_type=data_provider.file_type,
                                                                info=f"{data_provider.info}|SQLite3.{table}")
                if new_candidates := self.structure_scan(struct_content_provider, depth, new_limit):
                    candidates.extend(new_candidates)
            return candidates
        except Exception as exc:
            logger.error(exc)
        return None
