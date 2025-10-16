import numpy as np

from credsweeper.credentials.candidate import Candidate
from credsweeper.ml_model.features.word_in import WordIn


class WordInVariable(WordIn):
    """Feature returns array of words matching in variable"""

    def extract(self, candidate: Candidate) -> np.ndarray:
        """Returns array of matching words for first line"""
        if variable := candidate.line_data_list[0].variable:
            return self.word_in_(variable.lower())
        return np.array([self.zero])
