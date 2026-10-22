import ast
import json
import logging
import warnings
from abc import ABC
from typing import List, Optional

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.string_content_provider import StringContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider
from credsweeper.logger import TRACE

logger = logging.getLogger(__name__)


class LangScanner(AbstractScanner, ABC):
    """Implements scanning of data if it is a script of some markup language"""

    shelf = True

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Check matches for a JSON or Python format"""
        quot = bool(b'"' in data)
        if quot and 0 <= data.find(b'{', 0, MAX_LINE_LENGTH) \
                and 0 < data.find(b':', 0, MAX_LINE_LENGTH) \
                and 0 < data.rfind(b'}', max(0, len(data) - MAX_LINE_LENGTH)):
            # JSON which requires "key":"value":
            return True
        if quot and 0 <= data.find(b'[', 0, MAX_LINE_LENGTH) and data.rfind(b']', max(0, len(data) - MAX_LINE_LENGTH)):
            # listed JSON or NDJSON
            return True
        # check for python text
        if (quot or b"'" in data) and \
                (0 < data.find(b';', 0, MAX_LINE_LENGTH) or 1 < data.count(b'\n', 0, MAX_LINE_LENGTH)):
            return True
        return False

    @staticmethod
    def parse_python(source: str) -> list[str]:
        """Parse Python source and back to remove strings merge and line wrap"""
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("error", SyntaxWarning)
            tree = ast.parse(source)
            result = ast.unparse(tree)
            return result.splitlines()

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to represent data as markup language and scan as structure"""

        new_limit = recursive_limit_size - len(data_provider.data)

        # try to parse as NDJSON
        try:
            ndjson_candidates = []
            for n, line in enumerate(data_provider.text.splitlines(), start=1):
                # each line must be in json format, otherwise - exception rises
                structure = json.loads(line)
                ndjson_data_provider = StructContentProvider(struct=structure,
                                                             file_path=data_provider.file_path,
                                                             file_type=data_provider.file_type,
                                                             info=f"{data_provider.info}|NDJSON[{n}]")
                candidates = self.structure_scan(ndjson_data_provider, depth, new_limit)
                ndjson_candidates.extend(candidates)
            return ndjson_candidates
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.log(TRACE, "Cannot parse as ndjson %s:%s %s", type(exc), exc, data_provider.descriptor)

        # plain JSON probe
        try:
            structure = json.loads(data_provider.text)
            json_data_provider = StructContentProvider(struct=structure,
                                                       file_path=data_provider.file_path,
                                                       file_type=data_provider.file_type,
                                                       info=f"{data_provider.info}|JSON")
            candidates = self.structure_scan(json_data_provider, depth, new_limit)
            return candidates
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.log(TRACE, "Cannot parse as json %s:%s %s", type(exc), exc, data_provider.descriptor)

        # try to parse as Python code
        try:
            if python_refurbish_lines := LangScanner.parse_python(data_provider.text):
                python_content_provider = StringContentProvider(lines=python_refurbish_lines,
                                                                file_path=data_provider.file_path,
                                                                file_type=data_provider.file_type,
                                                                info=f"{data_provider.info}|Python")
                candidates = self.scanner.scan(python_content_provider)
                return candidates
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.log(TRACE, "Cannot parse as Python %s:%s %s", type(exc), exc, data_provider.descriptor)

        return None
