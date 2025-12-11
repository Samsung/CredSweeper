import contextlib
import hashlib
import re
import string
from functools import cached_property
from typing import Any, Dict, Optional, Tuple

from colorama import Fore, Style

from credsweeper.common.constants import MAX_LINE_LENGTH, UTF_8, StartEnd, ML_HUNK
from credsweeper.config.config import Config
from credsweeper.utils.util import Util


class LineData:
    """Object to treat and store scanned line related data.

    Parameters:
        key: Optional[str] = None
        line: string variable, line
        line_num: int variable, number of line in file
        path: string variable, path to file
        file_type: string variable, extension of file '.txt'
        info: additional info about how the data was detected
        pattern: regex pattern, detected pattern in line
        separator: optional string variable, separators between variable and value
        separator_start: optional variable, separator position start
        value: optional string variable, detected value in line
        variable: optional string variable, detected variable in line

    """

    quotation_marks = ('"', "'", '`')
    comment_starts = ("//", "* ", "# ", "/*", "<!––", "%{", "%", "...", "(*", "--", "--[[", "#=")
    bash_param_split = re.compile("\\s+(\\-|\\||\\>|\\w+?\\>|\\&)")
    line_endings = re.compile(r"\\{1,8}[nr]")
    # https://en.wikipedia.org/wiki/Percent-encoding
    url_percent_split = re.compile(r"%(21|23|24|26|27|28|29|2a|2b|2c|2f|3a|3b|3d|3f|40|5b|5d)", flags=re.IGNORECASE)
    url_unicode_split = re.compile(r"\\u00(0000)?(21|23|24|26|27|28|29|2a|2b|2c|2f|3a|3b|3d|3f|40|5b|5d)",
                                   flags=re.IGNORECASE)
    # some symbols e.g. double quotes cannot be in URL string https://www.ietf.org/rfc/rfc1738.txt
    # \ - was added for case of url in escaped string \u0026amp; - means escaped & in HTML
    url_scheme_part_regex = re.compile(r"[0-9A-Za-z.-]{3}")
    url_chars_not_allowed_pattern = re.compile(r'[\s"<>\[\]^~`{|}]')
    url_value_pattern = re.compile(r'[^\s&;"<>\[\]^~`{|}]+[&;][^\s=;"<>\[\]^~`{|}]{3,80}=[^\s;&="<>\[\]^~`{|}]{1,80}')
    variable_strip_pattern = string.whitespace + """,'"-;"""

    INITIAL_WRONG_POSITION = -3
    EXCEPTION_POSITION = -2

    def __init__(
            self,  #
            config: Config,  #
            line: str,  #
            line_pos: int,  #
            line_num: int,  #
            path: str,  #
            file_type: str,  #
            info: str,  #
            pattern: re.Pattern,  #
            match_obj: Optional[re.Match] = None) -> None:
        self.config = config
        self.line: str = line
        self.line_pos: int = line_pos
        self.line_num: int = line_num
        self.path: str = path
        self.file_type: str = file_type
        self.info: str = info
        self.pattern: re.Pattern = pattern
        # do not store match object due it cannot be pickled with multiprocessing

        # start - end position of matched object
        self.value_start = LineData.INITIAL_WRONG_POSITION
        self.value_end = LineData.INITIAL_WRONG_POSITION
        self.key: Optional[str] = None
        self.separator: Optional[str] = None
        self.separator_start: int = LineData.INITIAL_WRONG_POSITION
        self.separator_end: int = LineData.INITIAL_WRONG_POSITION
        self.value: Optional[str] = None
        self.variable: Optional[str] = None
        self.variable_start = LineData.INITIAL_WRONG_POSITION
        self.variable_end = LineData.INITIAL_WRONG_POSITION
        self.value_leftquote: Optional[str] = None
        self.value_rightquote: Optional[str] = None
        # is set when variable & value are in URL for any source type
        self.url_part = False
        self.wrap = None
        self._3d_escaped_separator = False
        self.initialize(match_obj)
        # the line is very useful for debug breakpoint
        pass  # pylint: disable=W0107

    def compare(self, other: 'LineData') -> bool:
        """Comparison method - skip whole line and checks only when variable and value are the same"""
        if self.path == other.path \
                and self.info == other.info \
                and self.line_num == other.line_num \
                and self.value_start == other.value_start \
                and self.variable == other.variable \
                and self.value == other.value:
            return True
        else:
            return False

    def initialize(self, match_obj: Optional[re.Match] = None) -> None:
        """Apply regex to the candidate line and set internal fields based on match."""
        if not isinstance(match_obj, re.Match) and isinstance(self.pattern, re.Pattern):
            match_obj = self.pattern.search(self.line, endpos=MAX_LINE_LENGTH)
        if match_obj is None:
            return

        def get_group_from_match_obj(_match_obj: re.Match, group: str) -> Any:
            with contextlib.suppress(Exception):
                return _match_obj.group(group)
            return None

        def get_span_from_match_obj(_match_obj: re.Match, group: str) -> Tuple[int, int]:
            with contextlib.suppress(Exception):
                span = _match_obj.span(group)
                return span[0], span[1]
            return LineData.EXCEPTION_POSITION, LineData.EXCEPTION_POSITION

        self.key = get_group_from_match_obj(match_obj, "keyword")
        self.separator = get_group_from_match_obj(match_obj, "separator")
        self.separator_start, self.separator_end = get_span_from_match_obj(match_obj, "separator")
        self.value = get_group_from_match_obj(match_obj, "value")
        self.value_start, self.value_end = get_span_from_match_obj(match_obj, "value")
        self.variable = get_group_from_match_obj(match_obj, "variable")
        self.variable_start, self.variable_end = get_span_from_match_obj(match_obj, "variable")
        self.value_leftquote = get_group_from_match_obj(match_obj, "value_leftquote")
        self.value_rightquote = get_group_from_match_obj(match_obj, "value_rightquote")
        self.wrap = get_group_from_match_obj(match_obj, "wrap")
        # percent encoded '=' in url
        self._3d_escaped_separator = bool(self.separator) and "%3D" == self.separator.upper()
        self.sanitize_value()
        self.sanitize_variable()

    def sanitize_value(self):
        """Clean found value from extra artifacts. Correct positions if changed."""
        # process the quotation workaround before cached properties invocation
        if not self.value_leftquote and not self.value_rightquote:
            while self.value:
                first_symbol_code = ord(self.value[0])
                last_symbol_code = ord(self.value[-1])
                if 0x2018 <= first_symbol_code <= 0x201B and 0x2018 <= last_symbol_code <= 0x201B:
                    self.value_leftquote = self.value_rightquote = "'"
                    self.value = self.value[:-1]
                    self.value_end -= 1
                    self.value = self.value[1:]
                    self.value_start += 1
                elif 0x201C <= first_symbol_code <= 0x201F and 0x201C <= last_symbol_code <= 0x201F:
                    self.value_leftquote = self.value_rightquote = '"'
                    self.value = self.value[1:]
                    self.value_start += 1
                    self.value = self.value[:-1]
                    self.value_end -= 1
                else:
                    break

        if self.variable and self.value and not self.is_well_quoted_value:
            # sanitize is actual step for keyword pattern only
            _value = self.value
            self.clean_url_parameters()
            self.clean_bash_parameters()
            self.clean_toml_parameters()
            self.clean_tag_parameters()
            if 0 <= self.value_start and 0 <= self.value_end and len(self.value) < len(_value):
                start = _value.find(self.value)
                self.value_start += start
                self.value_end = self.value_start + len(self.value)

    def check_url_part(self) -> bool:
        """Determines whether value is part of url like line"""
        line_before_value = self.line[:self.value_start]
        url_pos = -1
        find_pos = 0
        while find_pos < self.value_start:
            # find rightmost pattern
            find_pos = line_before_value.find("://", find_pos)
            if -1 == find_pos:
                break
            else:
                url_pos = find_pos
                find_pos += 3
        # whether the line has url start pattern
        self.url_part = 3 <= url_pos
        self.url_part &= bool(self.url_scheme_part_regex.match(line_before_value, pos=url_pos - 3, endpos=url_pos))
        self.url_part &= not self.url_chars_not_allowed_pattern.search(line_before_value, pos=url_pos + 3)
        self.url_part |= self.line[self.variable_start - 1] in "?&" if 0 < self.variable_start else False
        self.url_part |= bool(self.url_value_pattern.match(self.value))
        self.url_part |= self._3d_escaped_separator
        return self.url_part

    def clean_url_parameters(self) -> None:
        """Clean url address from 'query parameters'.

        If line seem to be a URL - split by & character.
        Variable should be right most value after & or ? ([-1]). And value should be left most before & ([0])
        """
        # skip sanitize in case of URL credential rule - the regex is mature enough
        if self.check_url_part() and not self.variable.endswith("://"):
            # all checks have passed - line before the value may be a URL
            self.variable = self.variable.rsplit('&')[-1].rsplit('?')[-1].rsplit(';')[-1]
            self.value = self.value.split('&', maxsplit=1)[0].split(';', maxsplit=1)[0].split('#', maxsplit=1)[0]
            self.value = self.url_unicode_split.split(self.value)[0]
            if self._3d_escaped_separator:
                self.value = self.url_percent_split.split(self.value)[0]

    def clean_bash_parameters(self) -> None:
        """Split variable and value by bash special characters, if line assumed to be CLI command."""
        if self.variable.startswith("-"):
            value_spl = self.bash_param_split.split(self.value)
            # If variable name starts with `-` (usual case for args in CLI)
            #  and value can be split by bash special characters
            if len(value_spl) > 1:
                self.value = value_spl[0]
        if ' ' not in self.value and ("\\n" in self.value or "\\r" in self.value):
            value_whsp = self.line_endings.split(self.value)
            if len(value_whsp) > 1:
                self.value = value_whsp[0]

    def clean_toml_parameters(self) -> None:
        """Parenthesis, curly and squared brackets may be caught in TOML format and bash. Simple clearing"""
        cleaning_required = self.value and self.value[-1] in ['}', ']', ')']
        line_before_value = self.line[:self.value_start] if self.value_start and 0 <= self.value_start else ""
        while cleaning_required:
            cleaning_required = False
            for left, right in [('{', '}'), ('[', ']'), ('(', ')')]:
                if self.value.endswith(right) and left not in self.value \
                        and line_before_value.count(left) > line_before_value.count(right):
                    # full match does not reasonable to implement due open character may be in other line
                    self.value = self.value[:-1]
                    cleaning_required = True

    def clean_tag_parameters(self) -> None:
        """Remove closing tag from value if the opened is somewhere before in line"""
        cleaning_required = self.value and self.value.endswith('>')
        while cleaning_required:
            closing_tag_pos = self.value.rfind("</")
            if 0 <= closing_tag_pos:
                # use `<a` to avoid tag parameters
                opening_tag_prefix = f"<{self.value[closing_tag_pos + 2:-1]}"
                if cleaning_required := (opening_tag_prefix not in self.value
                                         and 0 <= self.line.find(opening_tag_prefix, 0, self.value_start)):
                    self.value = self.value[:closing_tag_pos]
                    cleaning_required = self.value and self.value.endswith('>')
            else:
                break

    def sanitize_variable(self) -> None:
        """Remove trailing spaces, dashes and quotations around the variable. Correct position."""
        sanitized_var_len = 0
        variable = self.variable
        while self.variable and sanitized_var_len != len(self.variable):
            sanitized_var_len = len(self.variable)
            self.variable = self.variable.strip(self.variable_strip_pattern)
            if self.variable.endswith('\\'):
                self.variable = self.variable[:-1]
            if self.variable.startswith('{') and '}' in self.line[self.variable_end:]:
                # TOML case
                self.variable = self.variable[1:]
        if variable and len(self.variable) < len(variable) and 0 <= self.variable_start and 0 <= self.variable_end:
            start = variable.find(self.variable)
            self.variable_start += start
            self.variable_end = self.variable_start + len(self.variable)

    def is_comment(self) -> bool:
        """Check if line with credential is a comment.

        Return:
            True if line is a comment, False otherwise

        """
        cleaned_line = self.line.strip()
        for comment_start in self.comment_starts:
            if cleaned_line.startswith(comment_start):
                return True
        return False

    @cached_property
    def is_well_quoted_value(self) -> bool:
        """Well quoted value - means the value has been quoted or has line wrap"""
        result = False
        if self.value_leftquote and self.value_rightquote:
            if self.value_leftquote == self.value_rightquote:
                # regex caught well
                return True

            if 1 == len(self.value_leftquote):
                leftquote = self.value_leftquote
            else:
                # right side symbol should be a quote
                leftquote = self.value_leftquote[-1]
                if leftquote not in self.quotation_marks:
                    leftquote = ""

            if 1 == len(self.value_rightquote):
                rightquote = self.value_rightquote
            else:
                # clean \ sign in escaping text
                for q in self.value_rightquote:
                    if q in self.quotation_marks:
                        rightquote = q
                        break
                else:
                    rightquote = ""

            result = bool(leftquote) and (  #
                bool(rightquote) and (leftquote == rightquote)  # normal case
                or '\\' == self.value_rightquote and '\\' == self.line[-1]  # line wrap
            )

        elif self.value_leftquote:
            result = (  #
                ('\\' == self.value_rightquote or '\\' == self.value[-1]) and '\\' == self.line[-1]  # line wrap
                or '.php' == self.file_type  # php may use multiline string
                or 3 == self.value_leftquote.count('"') or 3 == self.value_leftquote.count("'")  # python multiline
            )

        return result

    @cached_property
    def is_quoted(self) -> bool:
        """Check if variable and value in a quoted string.

        Return:
            True if candidate in a quoted string, False otherwise

        """
        left_quote = None
        if 0 < self.variable_start:
            for i in self.line[:self.variable_start]:
                if i in ('"', "'", '`'):
                    left_quote = i
                    break
        right_quote = None
        if len(self.line) > self.value_end:
            for i in self.line[self.value_end:]:
                if i in ('"', "'", '`'):
                    right_quote = i
                    break
        result = bool(left_quote) and bool(right_quote) and left_quote == right_quote
        return result

    def is_source_file(self) -> bool:
        """Check if file with credential is a source code file or not (data, log, plain text).

        Return:
            True if file is source file, False otherwise

        """
        if not self.path:
            return False
        if Util.get_extension(self.path) in self.config.source_extensions:
            return True
        return False

    def is_source_file_with_quotes(self) -> bool:
        """Check if file with credential require quotation for string literals.

        Return:
            True if file require quotation, False otherwise

        """
        file_type = self.file_type or Util.get_extension(self.path)
        return bool(file_type) and file_type in self.config.source_quote_ext

    @staticmethod
    def get_hash_or_subtext(
            text: Optional[str],  #
            hashed: bool,  #
            cut_pos: Optional[StartEnd] = None,  #
    ) -> Optional[str]:
        """Represent not empty text with hash or a "beauty" subtext if required

        Args:
            text: str - input string
            hashed: bool - whether the text will be hashed and returned
            cut_pos: Optional[StartEnd] - start, end positions which text must be kept in output

        Return:
            sha256 hash in hex representation of input text with UTF-8 encodings
            or
            subtext from start to end, or original text as is

        """
        if text:
            if hashed:
                text = hashlib.sha256(text.encode(UTF_8, errors="strict")).hexdigest()
            elif cut_pos is not None:
                if 2 * ML_HUNK < cut_pos.end - cut_pos.start:
                    # subtext positions exceed the limit
                    text = text[cut_pos.start:cut_pos.end]
                else:
                    strip_text = text.strip()
                    if 2 * ML_HUNK >= len(strip_text):
                        # stripped text length meets the limit
                        text = strip_text
                    else:
                        offset = len(text) - len(text.lstrip())
                        center = (cut_pos.end + cut_pos.start - offset) >> 1
                        text = Util.subtext(strip_text, center, ML_HUNK)
        return text

    def to_str(self, subtext: bool = False, hashed: bool = False) -> str:
        """Represent line_data with subtext or|and hashed values"""
        cut_pos = StartEnd(self.variable_start, self.value_end) if subtext else None
        return f"path: {self.path}" \
               f" | line_num: {self.line_num}" \
               f" | value: '{self.get_hash_or_subtext(self.value, hashed)}'" \
               f" | line: '{self.get_hash_or_subtext(self.line, hashed, cut_pos)}'"

    def __str__(self):
        return self.to_str()

    def __repr__(self):
        return self.to_str(subtext=True)

    def to_json(self, hashed: bool, subtext: bool) -> Dict:
        """Convert line data object to dictionary.

        Return:
            Dictionary object generated from current line data

        """
        cut_pos = StartEnd(self.variable_start if 0 <= self.variable_start else self.value_start,
                           self.value_end) if subtext else None
        if isinstance(self.value, str):
            entropy = round(Util.get_shannon_entropy(self.value), 5)
        else:
            entropy = None
        full_output = {
            "key": self.key,
            "line": self.get_hash_or_subtext(self.line, hashed, cut_pos),
            "line_num": self.line_num,
            "path": self.path,
            # info may contain variable name - so let it be hashed if requested
            "info": self.get_hash_or_subtext(self.info, hashed),
            "pattern": self.pattern.pattern,
            "variable": self.get_hash_or_subtext(self.variable, hashed),
            "variable_start": self.variable_start,
            "variable_end": self.variable_end,
            "separator": self.separator,
            "separator_start": self.separator_start,
            "separator_end": self.separator_end,
            "value": self.get_hash_or_subtext(self.value, hashed),
            "value_start": self.value_start,
            "value_end": self.value_end,
            "entropy": entropy,
            "value_leftquote": self.value_leftquote,
            "value_rightquote": self.value_rightquote,
        }
        reported_output = {k: v for k, v in full_output.items() if k in self.config.line_data_output}
        return reported_output

    def get_colored_line(self, hashed: bool, subtext: bool = False) -> str:
        """Represents the LineData with a value, separator, and variable color formatting"""
        if hashed:
            # return colored hash
            return Fore.LIGHTGREEN_EX \
                + self.get_hash_or_subtext(self.line, hashed,
                                           StartEnd(self.value_start, self.value_end) if subtext else None) \
                + Style.RESET_ALL
        # at least, value must present
        line = self.line[:self.value_start] \
               + Fore.LIGHTYELLOW_EX \
               + self.line[self.value_start:self.value_end] \
               + Style.RESET_ALL \
               + self.line[self.value_end:]  # noqa: E127
        # separator may be missing
        if 0 <= self.separator_start < self.separator_end <= self.value_start:
            line = line[:self.separator_start] \
                   + Fore.LIGHTGREEN_EX \
                   + line[self.separator_start:self.separator_end] \
                   + Style.RESET_ALL \
                   + line[self.separator_end:]
        # variable may be missing
        if 0 <= self.separator_start \
                and 0 <= self.variable_start < self.variable_end <= self.separator_end <= self.value_start \
                or 0 <= self.variable_start < self.variable_end <= self.value_start:
            line = line[:self.variable_start] \
                   + Fore.LIGHTBLUE_EX \
                   + line[self.variable_start:self.variable_end] \
                   + Style.RESET_ALL \
                   + line[self.variable_end:]
        if subtext:
            # display part of the text, centered around the start of the value, style reset at the end as a fallback
            line = f"{Util.subtext(line, self.value_start + len(line) - len(self.line), ML_HUNK)}{Style.RESET_ALL}"
        return line
