"""Most rules are described in 'Secrets in Source Code: Reducing False Positives Using Machine Learning'."""
import re

from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.feature import Feature


class PossibleComment(Feature):
    """Feature is true if candidate line starts with #,\*,/\*? (Possible comment)."""
    possible_comment_pattern = re.compile(r"\s*(#|\*|/\*|//|--\s)")

    def extract(self, candidate: Candidate) -> bool:
        """Checks whether first line of candidate may be a comment"""
        if self.possible_comment_pattern.match(candidate.line_data_list[0].line):
            return True
        else:
            return False
