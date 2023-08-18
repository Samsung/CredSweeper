import contextlib
import datetime
import re

from dateutil.parser import parse

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValuePIICheck(Filter):
    """Filter for PII
    The rule has multiple values, so it has to be recognised """

    PATTERN_NAME = re.compile(r"[A-Z][a-z]+ +[A-Z][a-z]+")
    PATTERN_DATE = re.compile(r"\d{2}.\d{2}.\d{2}")

    def __init__(self, config: Config = None) -> None:
        now = datetime.datetime.now()
        self.low_date = now - datetime.timedelta(days=35600)
        self.top_date = now - datetime.timedelta(days=1)
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        if not line_data.value:
            return True

        if "@" in line_data.value:
            # email
            if line_data.value.endswith("@example.com"):
                return True
        elif ValuePIICheck.PATTERN_DATE:
            with contextlib.suppress(Exception):
                date = parse(line_data.value, fuzzy=True)
                if self.low_date < date < self.top_date:
                    return False
            return True
        elif ValuePIICheck.PATTERN_NAME:
            if "John Doe" == line_data.value:
                return True

        return False
