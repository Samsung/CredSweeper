"""Most rules are described in 'Secrets in Source Code: Reducing False Positives Using Machine Learning'."""

from abc import ABC, abstractmethod
from typing import List, Any, Dict

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.preprocessing import LabelBinarizer

from credsweeper.common.constants import Base, Chars
from credsweeper.credentials import Candidate


class Feature(ABC):
    """Base class for features."""

    def __init__(self):
        self.__words: List[str] = []  # type: ignore

    def __call__(self, candidates: List[Candidate]) -> List[bool]:
        """Call base class for features.

        Args:
            candidates: list of candidates to extract features

        """
        return [self.extract(candidate) for candidate in candidates]

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
        """setter - MUST BE IN LOWER CASE"""
        self.__words = words

    def any_word_in_(self, lower_case_line: str) -> bool:
        """Returns true if any words in first line"""
        for i in self.words:
            if i in lower_case_line:
                return True
        return False


class WordInSecret(Feature):
    """Feature returns true if candidate value contains at least one word from predefined list."""

    def __init__(self, words: List[str]) -> None:
        """Feature is true if candidate value contains at least one predefined word.

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE

        """
        super().__init__()
        self.words = words

    def extract(self, candidate: Candidate) -> bool:
        """Returns true if any words in first line"""
        return self.any_word_in_(candidate.line_data_list[0].value.lower())


class WordInLine(Feature):
    """Feature is true if line contains at least one word from predefined list."""

    def __init__(self, words: List[str]) -> None:
        """Feature is true if line contains at least one predefined word.

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE

        """
        super().__init__()
        self.words = words

    def extract(self, candidate: Candidate) -> bool:
        """Returns true if any words in first line"""
        return self.any_word_in_(candidate.line_data_list[0].line.lower())


class WordInPath(Feature):
    """Feature is true if candidate path contains at least one word from predefined list."""

    def __init__(self, words: List[str]) -> None:
        """Feature is true if candidate path contains at least one predefined word.

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE

        """
        super().__init__()
        self.words = words

    def extract(self, candidate: Candidate) -> bool:
        """Returns true if any words in first line"""
        return self.any_word_in_(candidate.line_data_list[0].path.lower())


class HasHtmlTag(Feature):
    """Feature is true if line has HTML tags (HTML file)."""

    def __init__(self) -> None:
        super().__init__()
        self.words = [
            '< img', '<img', '< script', '<script', '< p', '<p', '< link', '<link', '< meta', '<meta', '< a', '<a'
        ]

    def extract(self, candidate: Candidate) -> bool:
        candidate_line_data_list_0_line_lower = candidate.line_data_list[0].line.lower()
        if self.any_word_in_(candidate_line_data_list_0_line_lower):
            return True
        for i in ["<", "/>"]:
            if i not in candidate_line_data_list_0_line_lower:
                return False
        return True


class PossibleComment(Feature):
    r"""Feature is true if candidate line starts with #,\*,/\*? (Possible comment)."""

    def extract(self, candidate: Candidate) -> bool:
        for i in ["#", "*", "/*"]:
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


class ShannonEntropy(RenyiEntropy):
    """Shannon entropy feature."""

    def __init__(self, base: str, norm: bool = False) -> None:
        super().__init__(base, 1.0, norm)


class HartleyEntropy(RenyiEntropy):
    """Hartley entropy feature."""

    def __init__(self, base: str, norm: bool = False) -> None:
        super().__init__(base, 0.0, norm)


class FileExtension(Feature):
    """Categorical feature of file type.

    Parameters:
        extensions: extension labels

    """

    def __init__(self, extensions: List[str]) -> None:
        super().__init__()
        self.extensions = extensions

    def __call__(self, candidates: List[Candidate]) -> csr_matrix:
        enc = LabelBinarizer()
        enc.fit(self.extensions)
        extensions = [candidate.line_data_list[0].file_type for candidate in candidates]
        return enc.transform(extensions)

    def extract(self, candidate: Candidate) -> Any:
        raise NotImplementedError


class RuleName(Feature):
    """Categorical feature that corresponds to rule name.

    Parameters:
        rule_names: rule name labels

    """

    def __init__(self, rule_names: List[str]) -> None:
        super().__init__()
        self.rule_names = rule_names

    def __call__(self, candidates: List[Candidate]) -> csr_matrix:
        enc = LabelBinarizer()
        enc.fit(self.rule_names)
        rule_names = [candidate.rule_name for candidate in candidates]
        return enc.transform(rule_names)

    def extract(self, candidate: Candidate) -> Any:
        raise NotImplementedError
