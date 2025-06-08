import math
from typing import Dict, List, Set

import numpy as np

from credsweeper.common.constants import Chars, ML_HUNK
from credsweeper.credentials.candidate import Candidate
from credsweeper.file_handler.data_content_provider import MIN_DATA_LEN
from credsweeper.ml_model.features.feature import Feature


class EntropyEvaluation(Feature):
    """
    Renyi, Shannon entropy evaluation with Hartley entropy normalization.
    Augmentation with possible set of chars (hex, base64, etc.)
    Analyse only begin of the value

    See next link for details:
    https://digitalassets.lib.berkeley.edu/math/ucb/text/math_s4_v1_article-27.pdf

    """

    def __init__(self) -> None:
        """Class initializer"""
        super().__init__()
        # Max size of ML analyzed value is ML_HUNK but value may be bigger
        self.hunk_size = 4 * ML_HUNK
        self.log2_cache: Dict[int, float] = {x: math.log2(x) for x in range(4, self.hunk_size + 1)}
        self.char_sets: List[Set[str]] = [set(x.value) for x in Chars]

    def extract(self, candidate: Candidate) -> np.ndarray:
        """Returns real entropy and possible sets of characters"""
        # only head of value will be analyzed
        result: np.ndarray = np.zeros(shape=3 + len(self.char_sets), dtype=np.float32)
        value = candidate.line_data_list[0].value[:self.hunk_size]
        size = len(value)
        uniq, counts = np.unique(list(value), return_counts=True)
        if MIN_DATA_LEN <= size:
            # evaluate the entropy for a value of at least 4
            probabilities = counts / size
            hartley_entropy = self.log2_cache.get(size, -1.0)
            assert hartley_entropy, str(candidate)

            # renyi_entropy alpha=0.5
            sum_prob_05 = np.sum(probabilities**0.5)
            renyi_entropy_05 = 2 * np.log2(sum_prob_05)
            result[0] = renyi_entropy_05 / hartley_entropy

            # shannon_entropy or renyi_entropy alpha=1
            shannon_entropy = -np.sum(probabilities * np.log2(probabilities))
            result[1] = shannon_entropy / hartley_entropy

            # renyi_entropy alpha=2
            sum_prob_2 = np.sum(probabilities**2)
            renyi_entropy_2 = -1 * np.log2(sum_prob_2)
            result[2] = renyi_entropy_2 / hartley_entropy

        if 0 < size:
            # check charset for non-zero value
            # use the new variable to deal with mypy
            uniq_set = set(uniq)
            for n, i in enumerate(self.char_sets, start=3):
                if not uniq_set.difference(i):
                    result[n] = 1.0

        return result
