import io
import logging
from abc import ABC
from typing import List, Optional, Tuple, Type

import pygments
from pdfminer.high_level import extract_pages
from pdfminer.layout import LAParams, LTText, LTItem
from pygments.lexers import guess_lexer, guess_lexer_for_filename
from pygments.lexers import CLexer
from pygments.token import Comment, Token

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider, MIN_DATA_LEN
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class LexCScanner(AbstractScanner, ABC):
    """Implements C source scanning with lexical info"""

    C_EXTENSIONS = (".c", ".h")

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Suggestion may be done with file extension"""
        return True

    @staticmethod
    def guess(text: str, descriptor: Descriptor) -> bool:
        """Forecast validation for deep scan"""
        if descriptor.extension in LexCScanner.C_EXTENSIONS:
            return True
        elif descriptor.path.endswith(LexCScanner.C_EXTENSIONS):
            guessed_lexer = guess_lexer_for_filename(descriptor.path, text)
        elif descriptor.info.endswith(LexCScanner.C_EXTENSIONS):
            guessed_lexer = guess_lexer_for_filename(descriptor.info, text)
        else:
            guessed_lexer = guess_lexer(text)
        if isinstance(guessed_lexer, CLexer):
            return True
        return False

    @staticmethod
    def get_lines(text: str) -> Tuple[List[str], List[int]]:
        lines: List[str] = []
        line_numbers: List[int] = []
        lexer = CLexer(
            stripnl=True,
            stripall=True,
            ensurenl=True,
        )
        last_token_type = None
        line = ''
        line_number = 0
        for offset, token_type, value in lexer.get_tokens_unprocessed(text):
            if not line_number:
                line_number = 1 + text.count('\n', 0, offset)

            if last_token_type is None:
                last_token_type = token_type

            if token_type is Comment.Single:
                lines.append(stripped_value.replace('\n', ' '))
                line_numbers.append(line_number)
                continue

            if token_type is Token.Comment.Preproc and '\n'==value:
                lines.append(line)
                line = ''
                line_numbers.append(line_number)
                line_number = 0
                continue

            stripped_value = value.strip()
            if not stripped_value:
                # empty line - just put space for line
                line += ' '
                continue
            value_len = len(value)


            if stripped_value.endswith('\\'):
                stripped_value = stripped_value.rstrip('\\')
                len_diff = value_len - len(stripped_value)
                if 1 < len_diff:
                    stripped_value += '\\' * (len_diff // 2)

            if ';' == stripped_value:
                line += ';'
                lines.append(line)
                line = ''
                line_numbers.append(line_number)
                line_number = 0
                continue
            line += stripped_value
        # remains
        if line:
            lines.append(line)
        if line_number:
            line_numbers.append(line_number)
        return lines, line_numbers

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan C code with lexical structures"""
        try:
            if LexCScanner.guess(data_provider.text, data_provider.descriptor):
                lines, line_numbers = LexCScanner.get_lines(data_provider.text)
                string_data_provider = StringContentProvider(lines=lines,
                                                             line_numbers=line_numbers,
                                                             file_path=data_provider.file_path,
                                                             file_type=data_provider.file_type,
                                                             info=f"{data_provider.info}|C")
                candidates = self.scanner.scan(string_data_provider)
                return candidates
        except Exception as lex_c_exc:
            logger.warning("%s:%s", data_provider.file_path, lex_c_exc)
        return None
