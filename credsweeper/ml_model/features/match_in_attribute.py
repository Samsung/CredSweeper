import re

from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.feature import Feature


class MatchInAttribute(Feature):
    """Abstract feature returns boolean for matched pattern in member of first LineData"""

    def __init__(self, pattern: str, attribute: str):
        super().__init__()
        self.pattern = re.compile(pattern)
        self.attribute = attribute

    def extract(self, candidate: Candidate) -> bool:
        """Returns boolean for first LineData member"""
        if attribute := getattr(candidate.line_data_list[0], self.attribute, None):
            if self.pattern.match(attribute):
                return True
        return False
