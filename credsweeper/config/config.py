from typing import Dict, List, Optional

from humanfriendly import parse_size
from regex import regex

from credsweeper.utils import Util


class Config:
    """Class that contain configs that can be changed by user."""

    NOT_ALLOWED_PATH = [
        ".*\\.min\\.js", ".*message.*\\.properties", ".*locale.*\\.properties", ".*makefile.*", ".*package-lock\\.json",
        ".*package\\.json", ".*\\.css", ".*\\.scss"
    ]

    def __init__(self, config: Dict) -> None:
        self.exclude_patterns: List[regex.Pattern] = [
            regex.compile(pattern) for pattern in config["exclude"]["pattern"]
        ]
        self.exclude_paths: List[str] = config["exclude"]["path"]
        self.exclude_extensions: List[str] = config["exclude"]["extension"]
        self.source_extensions: List[str] = config["source_ext"]
        self.source_quote_ext: List[str] = config["source_quote_ext"]
        self.find_by_ext_list: List[str] = config["find_by_ext_list"]
        self.check_for_literals: bool = config["check_for_literals"]
        self.not_allowed_path_pattern = regex.compile(f"{Util.get_regex_combine_or(self.NOT_ALLOWED_PATH)}",
                                                      flags=regex.IGNORECASE)
        self.api_validation: bool = config["validation"]["api_validation"]
        self.use_filters: bool = config["use_filters"]
        self.line_data_output: List[str] = config["line_data_output"]
        self.candidate_output: List[str] = config["candidate_output"]
        self.find_by_ext: bool = config["find_by_ext"]
        self.size_limit: Optional[int] = parse_size(config["size_limit"]) if config["size_limit"] is not None else None
        self.depth: int = int(config["depth"])
        if self.depth > 0 and ".zip" in self.exclude_extensions:
            self.exclude_extensions.remove(".zip")
