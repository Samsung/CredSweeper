import csv
import io
import logging
from abc import ABC
from typing import List, Optional, Dict, Any

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider

logger = logging.getLogger(__name__)


class CsvScanner(AbstractScanner, ABC):
    """Implements CSV scanning"""

    sniffer = csv.Sniffer()
    # do not use space as separator to avoid hallucinations
    delimiters = ",;\t|\x1F"

    @classmethod
    def get_structure(cls, text: str) -> List[Dict[str, Any]]:
        """Reads a text as CSV standard with guessed dialect"""
        # windows style \r\n
        first_line_end = text.find('\r', 0, MAX_LINE_LENGTH)
        line_terminator = "\r\n"
        if 0 > first_line_end:
            # unix style \n
            first_line_end = text.find('\n', 0, MAX_LINE_LENGTH)
            line_terminator = "\n"
            if 0 > first_line_end:
                raise ValueError(f"No suitable line end found in {MAX_LINE_LENGTH} symbols")

        first_line = text[:first_line_end]
        dialect = cls.sniffer.sniff(first_line, delimiters=cls.delimiters)
        rows = []
        reader = csv.DictReader(io.StringIO(text),
                                delimiter=dialect.delimiter,
                                lineterminator=line_terminator,
                                strict=True)
        # check the constant columns number for all rows
        fields_number = sum(1 for x in reader.fieldnames if x is not None)
        for row in reader:
            if not isinstance(row, dict):
                raise ValueError(f"ERROR: wrong row '{row}'")
            if len(row) != fields_number or any(x is None for x in row.values()):
                # None means no separator used
                raise ValueError(f"Different columns number in row '{row}' - mismatch {fields_number}")
            rows.append(row)
        return rows

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan each row as structure with column name in key"""
        try:
            if rows := self.get_structure(data_provider.text):
                struct_content_provider = StructContentProvider(struct=rows,
                                                                file_path=data_provider.file_path,
                                                                file_type=data_provider.file_type,
                                                                info=f"{data_provider.info}|CSV")
                new_limit = recursive_limit_size - sum(len(x) for x in rows)
                struct_candidates = self.structure_scan(struct_content_provider, depth, new_limit)
                return struct_candidates
        except Exception as csv_exc:
            logger.debug(f"{data_provider.file_path}:{csv_exc}")
        return None
