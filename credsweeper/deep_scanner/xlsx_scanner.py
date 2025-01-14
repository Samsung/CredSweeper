import io
import logging
from abc import ABC
from typing import List, Optional

import pandas as pd

from credsweeper.credentials import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class XlsxScanner(AbstractScanner, ABC):
    """Implements xlsx scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan xlsx text elements for all slides"""
        try:
            candidates = []
            book = pd.read_excel(io.BytesIO(data_provider.data), sheet_name=None, header=None)
            for sheet_name, sheet_data in book.items():
                # replace open xml carriage returns _x000D_ before line feed only
                df = sheet_data.replace(to_replace="_x000D_\n", value='\n', regex=True).fillna('').astype(str)
                sheet_lines = ['\t'.join(x) for x in df.values]
                string_data_provider = StringContentProvider(lines=sheet_lines,
                                                             file_path=data_provider.file_path,
                                                             file_type=data_provider.file_type,
                                                             info=f"{data_provider.info}|xlsx:{sheet_name}")
                sheet_candidates = self.scanner.scan(string_data_provider)
                candidates.extend(sheet_candidates)
            return candidates
        except Exception as xlsx_exc:
            logger.error(f"{data_provider.file_path}:{xlsx_exc}")
        return None
