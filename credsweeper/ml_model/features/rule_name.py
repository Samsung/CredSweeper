from typing import List, Any

import numpy as np

from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.word_in import WordIn


class RuleName(WordIn):
    """Categorical feature that corresponds to rule name.

    Parameters:
        rule_names: rule name labels

    """

    def __init__(self, rule_names: List[str]) -> None:
        super().__init__(rule_names)

    def __call__(self, candidates: List[Candidate]) -> np.ndarray:
        candidate_rule_set = set(x.rule_name for x in candidates)
        return self.word_in_set(candidate_rule_set)

    def extract(self, candidate: Candidate) -> Any:
        raise NotImplementedError
