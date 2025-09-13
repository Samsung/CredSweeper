import re
from typing import Dict, List, Optional, Set, Any

from humanfriendly import parse_size

from credsweeper.common.constants import Severity, DEFAULT_PATTERN_LEN
from credsweeper.utils.util import Util


class Config:
    """Class that contain configs that can be changed by user."""

    NOT_ALLOWED_PATH = [
        ".*\\.min\\.js", ".*message.*\\.properties", ".*locale.*\\.properties", ".*makefile.*", ".*package-lock\\.json",
        ".*package\\.json", ".*\\.css", ".*\\.scss"
    ]

    def __init__(self, config: Dict[str, Any]) -> None:
        self.exclude_patterns: List[re.Pattern] = [re.compile(pattern) for pattern in config["exclude"]["pattern"]]
        self.exclude_paths: List[str] = config["exclude"]["path"]
        self.exclude_containers: List[str] = config["exclude"]["containers"]
        self.exclude_documents: List[str] = config["exclude"]["documents"]
        self.exclude_extensions: List[str] = config["exclude"]["extension"]
        self.exclude_lines: Set[str] = set(config["exclude"].get("lines", []))
        self.exclude_values: Set[str] = set(config["exclude"].get("values", []))
        self.source_extensions: List[str] = config["source_ext"]
        self.source_quote_ext: List[str] = config["source_quote_ext"]
        self.find_by_ext_list: List[str] = config["find_by_ext_list"]
        self.bruteforce_list: List[str] = config["bruteforce_list"]
        self.check_for_literals: bool = config["check_for_literals"]
        self.not_allowed_path_pattern = re.compile(f"{Util.get_regex_combine_or(self.NOT_ALLOWED_PATH)}",
                                                   flags=re.IGNORECASE)
        self.use_filters: bool = config["use_filters"]
        self.line_data_output: List[str] = config["line_data_output"]
        self.candidate_output: List[str] = config["candidate_output"]
        self.find_by_ext: bool = config["find_by_ext"]
        self.size_limit: Optional[int] = parse_size(config["size_limit"]) if config["size_limit"] is not None else None
        self.pedantic: bool = bool(config["pedantic"])
        self.depth: int = int(config["depth"])
        self.doc: bool = config["doc"]
        self.severity: Severity = Severity.get(config.get("severity"))

        self.max_url_cred_value_length: int = int(config["max_url_cred_value_length"])
        self.max_password_value_length: int = int(config["max_password_value_length"])

        # Trim exclude patterns from space like characters
        self.exclude_lines = set(line.strip() for line in self.exclude_lines)
        self.exclude_values = set(line.strip() for line in self.exclude_values)

        self.pattern_len = config.get("pattern_len", DEFAULT_PATTERN_LEN)
