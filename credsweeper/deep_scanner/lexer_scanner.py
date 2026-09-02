import logging
from abc import ABC
from typing import List, Optional, Tuple, cast

from pygments.lexer import Lexer
from pygments.lexers import guess_lexer_for_filename
from pygments.lexers.c_cpp import CppLexer, CLexer
from pygments.lexers.dotnet import CSharpLexer
from pygments.lexers.hdl import VerilogLexer
from pygments.lexers.javascript import JavascriptLexer, ObjectiveJLexer, TypeScriptLexer
from pygments.lexers.jvm import JavaLexer
from pygments.lexers.objective import ObjectiveCLexer
from pygments.lexers.perl import Perl6Lexer, PerlLexer
from pygments.lexers.special import TextLexer
from pygments.token import Comment, Token

from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.file_handler.string_content_provider import StringContentProvider

logger = logging.getLogger(__name__)


class LexerScanner(AbstractScanner, ABC):
    """Implements C source scanning with lexical info"""

    LEXER_MATCHER = {
        (".c", ".h"): CLexer,
        (".cpp", ".hpp", ".cc", ".hh", ".cxx", ".hxx"): CppLexer,
        (".java", ): JavaLexer,
        (".js", ): JavascriptLexer,
        (".cs", ): CSharpLexer,
        (".m", ".mm"): ObjectiveCLexer,
        (".objj", ): ObjectiveJLexer,
        (".pl", ".pm"): PerlLexer,
        (".p6", ".pl6", ".raku"): Perl6Lexer,
        (".v", ): VerilogLexer,
        (".ts", ): TypeScriptLexer,
    }
    EASY_MATCHER = {i: y for x, y in LEXER_MATCHER.items() for i in x}
    SUPPORTED_EXTENSIONS = tuple(x for y in LEXER_MATCHER.keys() for x in y)
    SUPPORTED_LEXERS = tuple(LEXER_MATCHER.values())
    # the lexers that were guessed without extensions
    GUESSED_LEXERS = tuple(x for x in LEXER_MATCHER.values() if x not in (VerilogLexer, ObjectiveCLexer))

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Suggestion may be done with file extension, however the """
        if 0 <= data.find(b';', 0, 65536) or 0 <= data.find(b'#', 0, 65536):
            return True
        return False

    @staticmethod
    def get_lexer(text: str, descriptor: Descriptor) -> Lexer:
        """Select a lexer for the source text.

        A standard lexer is selected by file extension when available.
        Otherwise, the lexer is detected using the file path, file information,
        or, as a fallback, the source content itself.

        Args:
            text: Source text to analyze.
            descriptor: File descriptor containing the extension, path, and
                file information used for lexer detection.

        Returns:
            A Pygments lexer suitable for parsing the source text."""
        lexer: Lexer
        if lexer_cls := LexerScanner.EASY_MATCHER.get(descriptor.extension):
            lexer = lexer_cls(stripnl=False, stripall=False, ensurenl=False)
        elif any(descriptor.path.endswith(x) for x in LexerScanner.SUPPORTED_EXTENSIONS):
            lexer = guess_lexer_for_filename(descriptor.path, text)
        elif any(descriptor.info.endswith(x) for x in LexerScanner.SUPPORTED_EXTENSIONS):
            lexer = guess_lexer_for_filename(descriptor.info, text)
        else:
            best_rv = 0.0
            # simple text lexer by default
            best_lexer = cast(type[Lexer], TextLexer)
            # 8~9Mb of sqlite amalgamation
            _text = text if len(text) < 10_000_000 else text[:10_000_000]
            for _lexer in LexerScanner.GUESSED_LEXERS:
                rv = _lexer.analyse_text(_text)
                if 0.0 < rv and best_rv < rv:
                    best_lexer = cast(type[Lexer], _lexer)
            lexer = best_lexer()
        return lexer

    @staticmethod
    def get_lines_semicolon(text: str, lexer: Lexer) -> Tuple[List[str], List[int]]:
        """Build logical source lines terminated by semicolons.

        Joins consecutive physical lines until a semicolon terminating the
        current statement is encountered. Semicolons inside strings or other
        non-terminating lexical contexts do not split the statement.

        Comments are extracted as separate logical lines and do not become
        part of the surrounding source statement.

        Returns:
            A tuple of:
            - logical source lines;
            - starting line number of each logical line in the original text.
        """
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

            if token_type is Comment.Multiline:
                for n, l in enumerate(value.splitlines(), start=line_number):
                    lines.append(l)
                    line_numbers.append(n)
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
            if type(lexer) not in LexerScanner.SUPPORTED_LEXERS:
                logger.debug("Unsupported lexer %s", lexer)
                return None
            lines, line_numbers = LexerScanner.get_lines_semicolon(data_provider.text, lexer)
            string_data_provider = StringContentProvider(lines=lines,
                                                         line_numbers=line_numbers,
                                                         file_path=data_provider.file_path,
                                                         file_type=data_provider.file_type,
                                                         info=f"{data_provider.info}|{lexer}")
            candidates = self.scanner.scan(string_data_provider)
            return candidates
        except Exception as lex_c_exc:
            logger.warning("%s:%s", data_provider.file_path, lex_c_exc)
        return None
