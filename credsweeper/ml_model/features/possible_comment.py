"""Most rules are described in 'Secrets in Source Code: Reducing False Positives Using Machine Learning'."""

from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.feature import Feature


class PossibleComment(Feature):
    r"""Feature is true if candidate line starts with #,\*,/\*? (Possible comment)."""

    def extract(self, candidate: Candidate) -> bool:
        line = candidate.line_data_list[0].line.lstrip()
        for i in ["#", "*", "/*", "//"]:
            if line.startswith(i):
                return True
        return False
