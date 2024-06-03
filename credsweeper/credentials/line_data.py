import contextlib
import re
from functools import cached_property
from typing import Any, Dict, Optional, Tuple

from credsweeper.common.constants import MAX_LINE_LENGTH, CHUNKS_OVERLAP_SIZE
from credsweeper.config import Config
from credsweeper.utils import Util
from credsweeper.utils.entropy_validator import EntropyValidator


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

    comment_starts = ["//", "*", "#", "/*", "<!––", "%{", "%", "...", "(*", "--", "--[[", "#="]
    bash_param_split = re.compile("\\s+(\\-|\\||\\>|\\w+?\\>|\\&)")
    # some symbols e.g. double quotes cannot be in URL string https://www.ietf.org/rfc/rfc1738.txt
    # \ - was added for case of url in escaped string \u0026amp; - means escaped & in HTML
    url_scheme_part_regex = re.compile(r"[0-9A-Za-z.-]{3}")
    url_chars_not_allowed_pattern = re.compile(r'[\s"<>\[\]^~`{|}]')

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

        self.initialize(match_obj)

    @cached_property
    def line_len(self) -> int:
        """cached property"""
        return len(self.line)

    @cached_property
    def search_start(self) -> int:
        """Decides from which position of line should be searched a pattern for line filters"""
        if MAX_LINE_LENGTH >= self.line_len or CHUNKS_OVERLAP_SIZE > self.value_start:
            return 0
        else:
            return self.value_start - CHUNKS_OVERLAP_SIZE

    @cached_property
    def search_end(self) -> int:
        """Decides to which position of line should be searched a pattern for line filters"""
        if MAX_LINE_LENGTH >= self.line_len or CHUNKS_OVERLAP_SIZE + self.value_end > self.line_len:
            return self.line_len
        else:
            return self.value_end + CHUNKS_OVERLAP_SIZE

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
        self.sanitize_value()
        self.sanitize_variable()

    def sanitize_value(self):
        """Clean found value from extra artifacts"""
        if self.variable and self.value:
            # sanitize is actual step for keyword pattern only
            _value = self.value
            self.clean_url_parameters()
            self.clean_bash_parameters()
            self.check_value_pos(_value)

    def check_value_pos(self, value: str) -> None:
        """checks and corrects value_start, value_end in case of self.value was shrink"""
        if 0 <= self.value_start and 0 <= self.value_end and len(self.value) < len(value):
            start = value.find(self.value)
            self.value_start += start
            self.value_end = self.value_start + len(self.value)

    def clean_url_parameters(self) -> None:
        """Clean url address from 'query parameters'.

        If line seem to be a URL - split by & character.
        Variable should be right most value after & or ? ([-1]). And value should be left most before & ([0])
        """
        # search only in 8000 bytes before value because a URL length does not exceed in common
        line_before_value = self.line[:self.value_start][-MAX_LINE_LENGTH:]
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
        if 3 > url_pos:
            return
        if not self.url_scheme_part_regex.match(line_before_value, pos=url_pos - 3, endpos=url_pos):
            # check for scheme naming - must be matched
            return
        # use line only after ://
        if self.url_chars_not_allowed_pattern.search(line_before_value, pos=url_pos + 3):
            return
        # all checks have passed - line before the value may be a URL
        self.variable = self.variable.rsplit('&', 1)[-1].rsplit('?', 1)[-1].rsplit(';', 1)[-1]
        self.value = self.value.split('&', maxsplit=1)[0].split(';', maxsplit=1)[0]

    def clean_bash_parameters(self) -> None:
        """Split variable and value by bash special characters, if line assumed to be CLI command."""
        if self.variable and self.variable.startswith("-") and self.value:
            value_spl = self.bash_param_split.split(self.value)
            # If variable name starts with `-` (usual case for args in CLI)
            #  and value can be split by bash special characters
            if len(value_spl) > 1:
                self.value = value_spl[0]

    def sanitize_variable(self) -> None:
        """Remove trailing spaces, dashes and quotations around the variable."""
        sanitized_var_len = 0
        while self.variable and sanitized_var_len != len(self.variable):
            sanitized_var_len = len(self.variable)
            # Remove trailing \s. Can happen if there are \s between variable and `=` character
            self.variable = self.variable.strip()
            # Remove trailing `-` at the variable name start. Usual case for CLI commands
            self.variable = self.variable.strip("-")
            # Remove trailing `'"`. Usual case for JSON data
            self.variable = self.variable.strip('"')
            self.variable = self.variable.strip("'")

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
        if not self.path:
            return False
        if Util.get_extension(self.path) in self.config.source_quote_ext:
            return True
        return False

    def __repr__(self) -> str:
        return f"line: '{self.line}' | line_num: {self.line_num} | path: {self.path}" \
               f" | value: '{self.value}' | entropy_validation: {EntropyValidator(self.value)}"

    def to_json(self) -> Dict:
        """Convert line data object to dictionary.

        Return:
            Dictionary object generated from current line data

        """
        full_output = {
            "key": self.key,
            "line": self.line,
            "line_num": self.line_num,
            "path": self.path,
            "info": self.info,
            "pattern": self.pattern.pattern,
            "separator": self.separator,
            "separator_start": self.separator_start,
            "separator_end": self.separator_end,
            "value": self.value,
            "value_start": self.value_start,
            "value_end": self.value_end,
            "variable": self.variable,
            "value_leftquote": self.value_leftquote,
            "value_rightquote": self.value_rightquote,
            "entropy_validation": EntropyValidator(self.value).to_dict()
        }
        reported_output = {k: v for k, v in full_output.items() if k in self.config.line_data_output}
        return reported_output
