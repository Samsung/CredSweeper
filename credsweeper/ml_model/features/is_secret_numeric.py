import contextlib

from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.feature import Feature


class IsSecretNumeric(Feature):
    """Feature is true if candidate value is a numerical value."""

    def extract(self, candidate: Candidate) -> bool:
        with contextlib.suppress(ValueError):
            float(candidate.line_data_list[0].value)
            return True
        return False
