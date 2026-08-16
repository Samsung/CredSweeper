import logging
from abc import ABC
from typing import List, Optional, Tuple, Type

from pygments.lexer import Lexer
from pygments.lexers import CLexer, CppLexer
from pygments.lexers import guess_lexer, guess_lexer_for_filename
from pygments.token import Comment, Token

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class LexerScanner(AbstractScanner, ABC):
    """Implements C source scanning with lexical info"""

    C_EXTENSIONS = (".c", ".h")
    CPP_EXTENSIONS = (".cpp", ".hpp", ".cc", ".hh", ".cxx", ".hxx")

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Suggestion may be done with file extension"""
        return True

    @staticmethod
    def get_lexer(text: str, descriptor: Descriptor) -> Lexer:
        """Forecast validation for deep scan"""
        if descriptor.extension in LexerScanner.C_EXTENSIONS:
            return CLexer(stripnl=False, stripall=False, ensurenl=False, )
        elif descriptor.extension in LexerScanner.CPP_EXTENSIONS:
            return CppLexer(stripnl=False, stripall=False, ensurenl=False, )
        elif descriptor.path.endswith(LexerScanner.C_EXTENSIONS):
            guessed_lexer = guess_lexer_for_filename(descriptor.path, text)
        elif descriptor.info.endswith(LexerScanner.C_EXTENSIONS):
            guessed_lexer = guess_lexer_for_filename(descriptor.info, text)
        else:
            guessed_lexer = guess_lexer(text)
        return guessed_lexer

    @staticmethod
    def get_lines_semicolon(text: str, lexer: Lexer) -> Tuple[List[str], List[int]]:
        lines: List[str] = []
        line_numbers: List[int] = []
        last_token_type = None
        line = ''
        line_number = 0
        for offset, token_type, value in lexer.get_tokens_unprocessed(text):
            if not line_number:
                line_number = 1 + text.count('\n', 0, offset)

            if last_token_type is None:
                last_token_type = token_type

            if token_type is Comment.Single:
                lines.append(value.replace('\n', ' '))
                line_numbers.append(line_number)
                continue

            if token_type is Token.Comment.Preproc and '\n' == value:
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
            lexer = LexerScanner.get_lexer(data_provider.text, data_provider.descriptor)
            if isinstance(lexer, (CLexer, CppLexer)):
                lines, line_numbers = LexerScanner.get_lines_semicolon(data_provider.text, lexer)
            else:
                raise ValueError(f"Unsupported lexer {lexer}")
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
