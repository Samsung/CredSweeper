import numpy as np

from credsweeper.common.constants import ML_HUNK
from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.feature import Feature


class LengthOfAttribute(Feature):
    """Abstract class for obtain a normalized value of length with max size of hunk"""

    def __init__(self, attribute: str):
        super().__init__()
        if "line" == attribute:
            self.hunk_plus = 2 * ML_HUNK + 1
        elif "value" == attribute or "variable" == attribute:
            self.hunk_plus = ML_HUNK + 1
        else:
            raise ValueError(f"Not supported attribute '{attribute}'")
        self.attribute = attribute

    def extract(self, candidate: Candidate) -> np.ndarray:
        """Returns boolean for first LineData member"""
        if attribute := getattr(candidate.line_data_list[0], self.attribute, None):
            if len(attribute) < self.hunk_plus:
                # should be in (0, 1)
                return np.array([len(attribute) / self.hunk_plus])
            else:
                # 1.0 means the attribute is oversize
                return np.array([1.0])
        # the attribute is empty
        return np.array([0.0])
