from typing import Dict

import numpy as np

from credsweeper.common.constants import Base, Chars
from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.feature import Feature


class RenyiEntropy(Feature):
    """Renyi entropy.

    See next link for details:
    https://digitalassets.lib.berkeley.edu/math/ucb/text/math_s4_v1_article-27.pdf

    Parameters:
        alpha: entropy parameter
        norm: set True to normalize output probabilities

    """

    # Constant dictionary to get characters set via name
    CHARS: Dict[Base, Chars] = {  #
        Base.base32: Chars.BASE32_CHARS,  #
        Base.base36: Chars.BASE36_CHARS,  #
        Base.base64: Chars.BASE64_CHARS,  #
        Base.hex: Chars.HEX_CHARS  #
    }

    def __init__(self, base: str, alpha: float, norm=False) -> None:
        """Renyi entropy class initializer.

        Args:
            base: number base type
            alpha: entropy parameter
            norm: set True to normalize output probabilities, default is False

        """
        super().__init__()
        self.base: Base = getattr(Base, base)
        self.alpha = alpha
        self.norm = norm

    def extract(self, candidate: Candidate) -> np.ndarray:
        p_x = self.get_probabilities(candidate.line_data_list[0].value)
        return np.array([self.estimate_entropy(p_x)])

    def get_probabilities(self, data: str) -> np.ndarray:
        """Get list of alphabet's characters presented in inputted string."""
        unique_elements = [x for x in RenyiEntropy.CHARS[self.base].value if data.count(x) > 0]

        # perform estimation of probability of characters
        p_x = np.array([float(data.count(x)) / len(data) for x in unique_elements])
        # get probabilities for alphabet's characters presented in data
        p_x = p_x[p_x > 0]

        # linear weighting of probabilities for theirs normalization
        if self.norm:
            p_x /= p_x.sum()

        return p_x

    def estimate_entropy(self, p_x: np.ndarray) -> float:
        """Calculate Renyi entropy of 'p_x' sequence.

        Function is based on definition of Renyi entropy for arbitrary probability distribution.
        Please see next link for details:
        https://digitalassets.lib.berkeley.edu/math/ucb/text/math_s4_v1_article-27.pdf
        """
        if 0 == len(p_x):
            entropy = 0
        elif np.abs(0.0 - self.alpha) < np.finfo(np.float32).eps:
            # corresponds to Hartley or max-entropy
            entropy = np.log2(p_x.size)
        elif np.abs(1.0 - self.alpha) < np.finfo(np.float32).eps:
            # corresponds to Shannon entropy
            entropy = np.sum(-p_x * np.log2(p_x))
        else:
            entropy = np.log2((p_x**self.alpha).sum()) / (1.0 - self.alpha)

        return entropy
