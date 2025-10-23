from difflib import SequenceMatcher

from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.feature import Feature


class Distance(Feature):
    """Abstract class to calculate distance between two strings"""

    def extract(self, candidate: Candidate) -> float:
        if variable := candidate.line_data_list[0].variable:
            if value := candidate.line_data_list[0].value:
                return SequenceMatcher(None, variable.lower(), value.lower()).ratio()
        return 0.0
