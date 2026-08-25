import re
from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValuePlaceholderCheck(Filter):
    """Filter values that are explicitly documented as placeholders or examples."""

    PLACEHOLDER_PATTERN = re.compile(
        r"^(?:change[-_ ]?me|dummy(?:[-_ ]?(?:api[-_ ]?key|secret|token))?|"
        r"example(?:[-_ ]?(?:api[-_ ]?key|secret|token|value|key))?|placeholder|"
        r"your[-_ ]?(?:api[-_ ]?key|password|secret|token)|test\d*|xxxxx+|"
        r"do[-_ ]?not[-_ ]?use(?:[-_ ]?in[-_ ]?prod(?:uction)?)?)$",
        re.IGNORECASE,
    )
    EXAMPLE_PATH_PARTS = ("test", "tests", "example", "examples", "fixture", "fixtures", "mock", "mocks")

    def __init__(self, config: Optional[Config] = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        value = line_data.value.strip()
        if self.PLACEHOLDER_PATTERN.fullmatch(value):
            return True

        path_parts = re.split(r"[/\\]+", line_data.path.lower())
        return bool(any(part in self.EXAMPLE_PATH_PARTS for part in path_parts))