"""
    Most rules are described in "Secrets in Source Code: Reducing False Positives
    Using Machine Learning"
"""

import os.path
from abc import ABC
from typing import List

import numpy as np
from scipy.sparse.csr import csr_matrix
from sklearn.preprocessing import LabelBinarizer

from credsweeper.common.constants import Chars
from credsweeper.credentials import Candidate


class Feature(ABC):
    """ Base class for features """
    def __call__(self, candidates: List[Candidate]) -> List[bool]:
        """ Base class for features

        Args:
            candidates: list of candidates to extract features
        """
        return [self.extract(candidate) for candidate in candidates]


class WordInSecret(Feature):
    """ Feature returns true if candidate value contains at least one word from predefined list """
    def __init__(self, words: List[str]) -> None:
        """ Feature is true if candidate value contains at least one predefined word

        Args:
            words: list of predefined words
        """
        self.words = words

    def extract(self, candidate: Candidate) -> bool:
        return any(w.lower() in candidate.line_data_list[0].value.lower() for w in self.words)


class WordInLine(Feature):
    """ Feature is true if line contains at least one word from predefined list """
    def __init__(self, words: List[str]) -> None:
        """ Feature is true if line contains at least one predefined word

        Args:
            words: list of predefined words
        """
        self.words = words

    def extract(self, candidate: Candidate) -> bool:
        return any(w.lower() in candidate.line_data_list[0].line.lower() for w in self.words)


class WordInPath(Feature):
    """ Feature is true if candidate path contains at least one word from predefined list """
    def __init__(self, words: List[str]) -> None:
        """ Feature is true if candidate path contains at least one predefined word

        Args:
            words: list of predefined words
        """
        self.words = words

    def extract(self, candidate: Candidate) -> bool:
        return any(c.lower() in candidate.line_data_list[0].path.lower() for c in self.words)


class HasHtmlTag(Feature):
    """ Feature is true if line has HTML tags (HTML file) """
    def __init__(self) -> None:
        self.word_in_line = WordInLine(
            ['< img', '<img', '< script', '<script', '< p', '<p', '< link', '<link', '< meta', '<meta', '< a', '<a'])

    def extract(self, candidate: Candidate) -> bool:
        tag_closings = ["<", "/>"]
        return self.word_in_line.extract(candidate) | all(c in candidate.line_data_list[0].line for c in tag_closings)


class PossibleComment(Feature):
    """ Feature is true if candidate line starts with #,*,/*? (Possible comment) """
    def extract(self, candidate: Candidate) -> bool:
        comment_symbols = ["#", "*", "/*"]
        return any(candidate.line_data_list[0].line.startswith(s) for s in comment_symbols)


class IsSecretNumeric(Feature):
    """ Feature is true if candidate value is a numerical value """
    def extract(self, candidate: Candidate) -> bool:
        try:
            float(candidate.line_data_list[0].value)
            return True
        except ValueError:
            return False


class RenyiEntropy(Feature):
    """ Renyi entropy
    See next link for details:
    https://digitalassets.lib.berkeley.edu/math/ucb/text/math_s4_v1_article-27.pdf

    Attributes:
        CHARS: Number base
        alpha: entropy parameter
        norm: set True to normalize output probabilities
    """
    CHARS = {
        'hex': "1234567890abcdefABCDEF",
        'base36': "abcdefghijklmnopqrstuvwxyz1234567890",
        'base64': "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    }

    def __init__(self, base: Chars, alpha: float, norm=False) -> None:
        """ initializer

        Args:
            CHARS: Number base
            alpha: entropy parameter
            norm: set True to normalize output probabilities, default is False
        """

        self.base = base
        self.alpha = alpha
        self.norm = norm

    def extract(self, candidate: Candidate) -> np.array:
        p_x = self.get_probabilities(candidate.line_data_list[0].value)
        return self.estimate_entropy(p_x)

    def get_probabilities(self, data: str) -> np.array:
        # get list of alphabet's characters presented in inputted string
        unique_elements = [x for x in ShannonEntropy.CHARS[self.base] if data.count(x) > 0]

        # perform estimation of probability of characters
        p_x = np.array([float(data.count(x)) / len(data) for x in unique_elements])
        # get probabilities for alphabet's characters presented in data
        p_x = p_x[p_x > 0]

        # linear weighting of probabilities for theirs normalization
        if self.norm:
            p_x /= p_x.sum()

        return p_x

    def estimate_entropy(self, p_x: np.array) -> float:
        # Function is based on definition of Renyi entropy for arbitrary probability distribution
        # Please see next link for details:
        # https://digitalassets.lib.berkeley.edu/math/ucb/text/math_s4_v1_article-27.pdf

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


class ShannonEntropy(RenyiEntropy):
    """ Shannon entropy feature """
    def __init__(self, base: Chars, norm: bool = False) -> None:
        super().__init__(base, 1.0, norm)


class HartleyEntropy(RenyiEntropy):
    """ Hartley entropy feature """
    def __init__(self, base: Chars, norm: bool = False) -> None:
        super().__init__(base, 0.0, norm)


class FileExtension(Feature):
    """ categorical feature of file type

    Attributes:
        extensions: extension labels
    """
    def __init__(self, extensions: List[str]) -> None:
        self.extensions = extensions

    def __call__(self, candidates: List[Candidate]) -> csr_matrix:
        enc = LabelBinarizer()
        enc.fit(self.extensions)
        extensions = [os.path.splitext(candidate.line_data_list[0].path)[1] for candidate in candidates]
        return enc.transform(extensions)


class RuleName(Feature):
    """
    Categorical feature that corresponds to rule name

    Attributes:
        rule_names: rule name labels
    """
    def __init__(self, rule_names: List[str]) -> None:
        self.rule_names = rule_names

    def __call__(self, candidates: List[Candidate]) -> csr_matrix:
        enc = LabelBinarizer()
        enc.fit(self.rule_names)
        rule_names = [candidate.rule_name for candidate in candidates]
        return enc.transform(rule_names)
