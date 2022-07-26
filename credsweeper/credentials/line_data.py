from typing import Any, Optional, Tuple

from regex import regex

from credsweeper.config import Config
from credsweeper.utils import Util


class LineData:
    """Object to treat and store scanned line related data.

    Parameters:
        key: Optional[str] = None
        line: string variable, line
        line_num: int variable, number of line in file
        path: string variable, path to file
        pattern: regex pattern, detected pattern in line
        separator: optional string variable, separators between variable and value
        separator_span: optional tuple variable, separator position
        value: optional string variable, detected value in line
        variable: optional string variable, detected variable in line

    """

    comment_starts = ["//", "*", "#", "/*", "<!––", "%{", "%", "...", "(*", "--", "--[[", "#="]
    bash_param_split = regex.compile("\\s+(\\-|\\||\\>|\\w+?\\>|\\&)")

    def __init__(self, config: Config, line: str, line_num: int, path: str, pattern: regex.Pattern) -> None:
        self.config = config
        self.key: Optional[str] = None
        self.line: str = line
        self.line_num: int = line_num
        self.path: str = path
        self.pattern: regex.Pattern = pattern
        self.separator: Optional[str] = None
        self.separator_span: Optional[Tuple[int, int]] = None
        self.value: Optional[str] = None
        self.variable: Optional[str] = None
        self.value_leftquote: Optional[str] = None
        self.value_rightquote: Optional[str] = None

        self.initialize()

    @property
    def key(self) -> str:
        """key getter"""
        return self.__key

    @key.setter
    def key(self, key: str) -> None:
        """key setter"""
        self.__key = key

    @property
    def line(self) -> str:
        """line getter"""
        return self.__line

    @line.setter
    def line(self, line: str) -> None:
        """line setter"""
        self.__line = line

    @property
    def line_num(self) -> int:
        """line_num getter"""
        return self.__line_num

    @line_num.setter
    def line_num(self, line_num: int) -> None:
        """line_num setter"""
        self.__line_num = line_num

    @property
    def path(self) -> str:
        """path getter"""
        return self.__path

    @path.setter
    def path(self, path: str) -> None:
        """path setter"""
        self.__path = path

    @property
    def pattern(self) -> regex.Pattern:
        """pattern getter"""
        return self.__pattern

    @pattern.setter
    def pattern(self, pattern: regex.Pattern) -> None:
        """pattern setter"""
        self.__pattern = pattern

    @property
    def separator(self) -> str:
        """separator getter"""
        return self.__separator

    @separator.setter
    def separator(self, separator: str) -> None:
        """separator setter"""
        self.__separator = separator

    @property
    def separator_span(self) -> Tuple[int, int]:
        """separator_span getter"""
        return self.__separator_span

    @separator_span.setter
    def separator_span(self, separator_span: Tuple[int, int]) -> None:
        """separator_span setter"""
        self.__separator_span = separator_span

    @property
    def value(self) -> str:
        """value getter"""
        return self.__value

    @value.setter
    def value(self, value: str) -> None:
        """value setter"""
        self.__value = value

    @property
    def variable(self) -> str:
        """variable getter"""
        return self.__variable

    @variable.setter
    def variable(self, variable: str) -> None:
        """variable setter"""
        self.__variable = variable

    @property
    def value_leftquote(self) -> str:
        """value_leftquote getter"""
        return self.__value_leftquote

    @value_leftquote.setter
    def value_leftquote(self, value_leftquote: str) -> None:
        """value_leftquote setter"""
        self.__value_leftquote = value_leftquote

    @property
    def value_rightquote(self) -> str:
        """value_rightquote getter"""
        return self.__value_rightquote

    @value_rightquote.setter
    def value_rightquote(self, value_rightquote: str) -> None:
        """value_rightquote setter"""
        self.__value_rightquote = value_rightquote

    def initialize(self) -> None:
        """Set all internal fields."""
        self.set_pattern_match_groups()

    def set_pattern_match_groups(self) -> None:
        """Apply regex to the candidate line and set internal fields based on match."""
        match_obj = self.pattern.search(self.line)
        if match_obj is None:
            return

        def get_group_from_match_obj(match_obj: regex.Match, group: str) -> Any:
            try:
                return match_obj.group(group)
            except Exception:
                return None

        def get_span_from_match_obj(match_obj: regex.Match, group: str) -> Optional[Tuple[int, int]]:
            try:
                return match_obj.span(group)
            except Exception:
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
        if self.variable:
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
        starts_from_comment = any(cleaned_line.startswith(comment_start) for comment_start in self.comment_starts)
        return starts_from_comment

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
               f"/ value: '{self.value}' / entropy_validation: {Util.is_entropy_validate(self.value)}"

    def to_json(self) -> dict:
        """Convert line data object to dictionary.

        Return:
            Dictionary object generated from current line data

        """
        full_output = {
            "key": self.key,
            "line": self.line,
            "line_num": self.line_num,
            "path": self.path,
            "pattern": self.pattern.pattern,
            "separator": self.separator,
            "separator_span": self.separator_span,
            "value": self.value,
            "variable": self.variable,
            "value_leftquote": self.value_leftquote,
            "value_rightquote": self.value_rightquote,
            "entropy_validation": Util.is_entropy_validate(self.value)
        }
        reported_output = {k: v for k, v in full_output.items() if k in self.config.line_data_output}
        return reported_output
