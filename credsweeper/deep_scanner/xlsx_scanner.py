import io
import logging
from abc import ABC
from typing import List, Optional, Union

import pandas as pd

from credsweeper.credentials.augment_candidates import augment_candidates
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class XlsxScanner(AbstractScanner, ABC):
    """Implements xlsx scanning"""

    @staticmethod
    def match(data: Union[bytes, bytearray]) -> bool:
        """According https://en.wikipedia.org/wiki/List_of_file_signatures"""
        if data.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
            # Compound File Binary Format: doc, xls, ppt, msi, msg
            return True
        return False

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
                sheet_info = f"{data_provider.info}|{sheet_name}"
                # replace open xml carriage returns _x000D_ before line feed only
                df = sheet_data.replace(to_replace="_x000D_\n", value='\n', regex=True).fillna('').astype(str)
                for row_pos, row in enumerate(df.values):
                    for col_pos, cell in enumerate(row):
                        cell_info = f"{sheet_info}:{Util.get_excel_column_name(col_pos)}{row_pos + 1}"
                        cell_provider = StringContentProvider(lines=cell.splitlines(),
                                                              file_path=data_provider.file_path,
                                                              file_type=data_provider.file_type,
                                                              info=cell_info)
                        cell_candidates = self.scanner.scan(cell_provider)
                        candidates.extend(cell_candidates)
                    row_line = '\t'.join(row)
                    row_provider = StringContentProvider(lines=[row_line],
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{sheet_info}:R{row_pos + 1}")
                    row_candidates = self.scanner.scan(row_provider)
                    augment_candidates(candidates, row_candidates)

            return candidates
        except Exception as xlsx_exc:
            logger.error(f"{data_provider.file_path}:{xlsx_exc}")
        return None
