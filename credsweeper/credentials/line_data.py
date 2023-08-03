import contextlib
import re
from typing import Any, Dict, Optional, Tuple

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
        separator_span: optional tuple variable, separator position
        value: optional string variable, detected value in line
        variable: optional string variable, detected variable in line

    """

    comment_starts = ["//", "*", "#", "/*", "<!––", "%{", "%", "...", "(*", "--", "--[[", "#="]
    bash_param_split = re.compile("\\s+(\\-|\\||\\>|\\w+?\\>|\\&)")

    def __init__(
            self,  #
            config: Config,  #
            line: str,  #
            line_pos: int,  #
            line_num: int,  #
            path: str,  #
            file_type: str,  #
            info: str,  #
            pattern: re.Pattern) -> None:
        self.config = config
        self.line: str = line
        self.line_pos: int = line_pos
        self.line_num: int = line_num
        self.path: str = path
        self.file_type: str = file_type
        self.info: str = info
        self.pattern: re.Pattern = pattern

        self.key: Optional[str] = None
        self.separator: Optional[str] = None
        self.separator_span: Optional[Tuple[int, int]] = None
        self.value: Optional[str] = None
        self.variable: Optional[str] = None
        self.value_leftquote: Optional[str] = None
        self.value_rightquote: Optional[str] = None

        self.initialize()

    def initialize(self) -> None:
        """Set all internal fields."""
        self.set_pattern_match_groups()

    def set_pattern_match_groups(self) -> None:
        """Apply regex to the candidate line and set internal fields based on match."""
        match_obj = self.pattern.search(self.line)
        if match_obj is None:
            return

        def get_group_from_match_obj(_match_obj: re.Match, group: str) -> Any:
            with contextlib.suppress(Exception):
                return _match_obj.group(group)
            return None

        def get_span_from_match_obj(_match_obj: re.Match, group: str) -> Optional[Tuple[int, int]]:
            with contextlib.suppress(Exception):
                return _match_obj.span(group)
            return None

        self.key = get_group_from_match_obj(match_obj, "keyword")
        self.separator = get_group_from_match_obj(match_obj, "separator")
        self.separator_span = get_span_from_match_obj(match_obj, "separator")
        self.value = get_group_from_match_obj(match_obj, "value")
        self.variable = get_group_from_match_obj(match_obj, "variable")
        self.value_leftquote = get_group_from_match_obj(match_obj, "value_leftquote")
        self.value_rightquote = get_group_from_match_obj(match_obj, "value_rightquote")
        self.clean_url_parameters()
        self.clean_bash_parameters()
        self.sanitize_variable()

    def clean_url_parameters(self) -> None:
        """Clean url address from 'query parameters'.

        If line seem to be a URL - split by & character.
        Variable should be right most value after & or ? ([-1]). And value should be left most before & ([0])
        """
        if "http://" in self.line or "https://" in self.line:
            if self.variable:
                self.variable = self.variable.split('&')[-1].split('?')[-1]
            if self.value:
                self.value = self.value.split('&')[0]

    def clean_bash_parameters(self) -> None:
        """Split variable and value by bash special characters, if line assumed to be CLI command."""
        if self.value and self.variable:
            value_spl = self.bash_param_split.split(self.value)

            # If variable name starts with `-` (usual case for args in CLI)
            #  and value can be split by bash special characters
            if len(value_spl) > 1 and self.variable.startswith("-"):
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
        return f"line: '{self.line}' / line_num: {self.line_num} / path: {self.path} " \
               f"/ value: '{self.value}' / entropy_validation: {EntropyValidator(self.value)}"

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
            "separator_span": self.separator_span,
            "value": self.value,
            "variable": self.variable,
            "value_leftquote": self.value_leftquote,
            "value_rightquote": self.value_rightquote,
            "entropy_validation": EntropyValidator(self.value).to_dict()
        }
        reported_output = {k: v for k, v in full_output.items() if k in self.config.line_data_output}
        return reported_output
