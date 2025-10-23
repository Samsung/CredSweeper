from abc import ABC, abstractmethod
from typing import List, Any

import numpy as np

from credsweeper.credentials.candidate import Candidate


class Feature(ABC):
    """Base class for features."""

    def __init__(self):
        pass

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
