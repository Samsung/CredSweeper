import string
from typing import Dict, Set

import numpy as np

from credsweeper.common import KeywordChecklist
from credsweeper.common.constants import Base, Chars
from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.feature import Feature


class MorphemeDense(Feature):
    """Feature calculates morphemes density for a value"""

    def __init__(self, base: str) -> None:
        """CharSet class initializer.

        Args:
            base: base set ID

        """
        super().__init__()

    def extract(self, candidate: Candidate) -> float:
        if value := candidate.line_data_list[0].value.lower():
            morphemes_counter = 0
            for morpheme in KeywordChecklist.morpheme_set:
                if morpheme in value:
                    morphemes_counter += 1
            return morphemes_counter / len(value)
        else:
            # empty value case
            return 0.0
