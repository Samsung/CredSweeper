"""Most rules are described in 'Secrets in Source Code: Reducing False Positives Using Machine Learning'."""
import contextlib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Any, Dict, Tuple, Set

import numpy as np

from credsweeper.common.constants import Base, Chars, CHUNK_SIZE
from credsweeper.credentials import Candidate
from credsweeper.utils import Util


class Feature(ABC):
    """Base class for features."""

    def __init__(self):
        self.words = []

    def __call__(self, candidates: List[Candidate]) -> np.ndarray:
        """Call base class for features.

        Args:
            candidates: list of candidates to extract features

        """
        return np.array([self.extract(candidate) for candidate in candidates])

    @abstractmethod
    def extract(self, candidate: Candidate) -> Any:
        """Abstract method of base class"""
        raise NotImplementedError

    @property
    def words(self) -> List[str]:
        """getter"""
        return self.__words

    @words.setter
    def words(self, words: List[str]) -> None:
        """setter"""
        self.__words = words

    def any_word_in_(self, a_string: str) -> bool:
        """Returns true if any words in a string"""
        for i in self.words:
            if i in a_string:
                return True
        return False






class HasHtmlTag(Feature):
    """Feature is true if line has HTML tags (HTML file)."""

    def __init__(self) -> None:
        super().__init__()
        self.words = [
            '< img', '<img', '< script', '<script', '< p', '<p', '< link', '<link', '< meta', '<meta', '< a', '<a'
        ]

    def extract(self, candidate: Candidate) -> bool:
        subtext = Util.subtext(candidate.line_data_list[0].line, candidate.line_data_list[0].value_start, CHUNK_SIZE)
        candidate_line_data_list_0_line_lower = subtext.lower()
        if '<' not in candidate_line_data_list_0_line_lower:
            # early check
            return False
        if self.any_word_in_(candidate_line_data_list_0_line_lower):
            return True
        if "/>" in candidate_line_data_list_0_line_lower or "</" in candidate_line_data_list_0_line_lower:
            # possible closed tag
            return True
        return False


class PossibleComment(Feature):
    r"""Feature is true if candidate line starts with #,\*,/\*? (Possible comment)."""

    def extract(self, candidate: Candidate) -> bool:
        for i in ["#", "*", "/*", "//"]:
            if candidate.line_data_list[0].line.startswith(i):
                return True
        return False


class IsSecretNumeric(Feature):
    """Feature is true if candidate value is a numerical value."""

    def extract(self, candidate: Candidate) -> bool:
        try:
            float(candidate.line_data_list[0].value)
            return True
        except ValueError:
            return False

