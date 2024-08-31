"""Most rules are described in 'Secrets in Source Code: Reducing False Positives Using Machine Learning'."""
import contextlib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Any, Dict, Tuple, Set

import numpy as np

from credsweeper.app import logger
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



class WordIn(Feature):
    """Abstract feature returns array with all matched words in a string"""

    def __init__(self,words:List[str]):
        super().__init__()
        self.dimension = len(words)
        self.words=sorted(list(set(words)))
        self.enumerated_words = list(enumerate(self.words))
        if len(self.enumerated_words) != self.dimension:
            raise RuntimeError(f"Check duplicates:{words}")

    @property
    def enumerated_words(self) -> List[Tuple[int,str]]:
        """getter for speedup"""
        return self.__enumerated_words

    @enumerated_words.setter
    def enumerated_words(self, enumerated_words: List[Tuple[int,str]]) -> None:
        """setter for speedup"""
        self.__enumerated_words = enumerated_words

    @property
    def dimension(self) -> int:
        """getter"""
        return self.__dimension

    @dimension.setter
    def dimension(self, dimension: int) -> None:
        """setter"""
        self.__dimension = dimension

    @abstractmethod
    def extract(self, candidate: Candidate) -> Any:
        raise NotImplementedError

    def word_in_str(self, a_string: str) -> np.ndarray:
        """Returns array with words included in a string"""
        result = np.zeros(shape=[self.dimension], dtype=np.int8)
        for i, word in self.enumerated_words:
            if word in a_string:
                result[i] = 1
        return np.array([result])

    def word_in_set(self, a_strings_set: Set[str]) -> np.ndarray:
        """Returns array with words matches in a_strings_set"""
        result = np.zeros(shape=[self.dimension], dtype=np.int8)
        for i, word in self.enumerated_words:
            if word in a_strings_set:
                result[i] = 1
        return np.array([result])



class WordInVariable(WordIn):
    """Feature returns array of words matching in variable"""

    def __init__(self, words: List[str]) -> None:
        """Feature is true if candidate value contains at least one predefined word.

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE

        """
        super().__init__(words)

    def extract(self, candidate: Candidate) ->  np.ndarray:
        """Returns array of matching words for first line"""
        if candidate.line_data_list[0].variable:
            return self.word_in_str(candidate.line_data_list[0].variable.lower())
        else:
            return np.zeros(shape=[self.dimension], dtype=np.int8)


class WordInSecret(WordIn):
    """Feature returns true if candidate value contains at least one word from predefined list."""

    def __init__(self, words: List[str]) -> None:
        """Feature is true if candidate value contains at least one predefined word.

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE

        """
        super().__init__(words)

    def extract(self, candidate: Candidate) ->  np.ndarray:
        """Returns array of matching words for first line"""
        value = candidate.line_data_list[0].value
        if value:
            return self.word_in_str(value.lower())
        else:
            return np.zeros(shape=[self.dimension], dtype=np.int8)


class WordInLine(WordIn):
    """Feature is true if line contains at least one word from predefined list."""

    def __init__(self, words: List[str]) -> None:
        """Feature returns array of matching words

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE

        """
        super().__init__(words)

    def extract(self, candidate: Candidate) -> np.ndarray:
        """Returns true if any words in first line"""
        subtext = Util.subtext(candidate.line_data_list[0].line, candidate.line_data_list[0].value_start, CHUNK_SIZE)
        if subtext:
            return self.word_in_str(subtext.lower())
        else:
            return np.zeros(shape=[self.dimension], dtype=np.int8)



class WordInPath(WordIn):
    """Categorical feature that corresponds to words in path (POSIX, lowercase)"""

    def __init__(self, words: List[str]) -> None:
        """WordInPath constructor

        Args:
            words: list of predefined words - MUST BE IN LOWER CASE & POSIX

        """
        super().__init__(words)

    def __call__(self, candidates: List[Candidate]) -> np.ndarray:
        # actually there must be one path because the candidates are grouped before
        candidate_path = Path( candidates[0].line_data_list[0].path).as_posix().lower()
        if candidate_path:
            return self.word_in_str(candidate_path.lower())
        else:
            return np.zeros(shape=[self.dimension], dtype=np.int8)

    def extract(self, candidate: Candidate) -> Any:
        raise NotImplementedError


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
        if self.any_word_in_(candidate_line_data_list_0_line_lower):
            return True
        for i in ["<", "/>"]:
            if i not in candidate_line_data_list_0_line_lower:
                return False
        return True


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


class ShannonEntropy(RenyiEntropy):
    """Shannon entropy feature."""

    def __init__(self, base: str, norm: bool = False) -> None:
        super().__init__(base, 1.0, norm)


class HartleyEntropy(RenyiEntropy):
    """Hartley entropy feature."""

    def __init__(self, base: str, norm: bool = False) -> None:
        super().__init__(base, 0.0, norm)


class CharSet(Feature):
    """Feature is true when all characters of the value are from a set."""

    # Constant dictionary to get characters set via name
    CHARS: Dict[Base, str] = {  #
        Base.base16upper: Chars.BASE16UPPER.value,  #
        Base.base16lower: Chars.BASE16LOWER.value,  #
        Base.base32: Chars.BASE32_CHARS.value,  #
        Base.base36: Chars.BASE36_CHARS.value,  #
        Base.base64std: Chars.BASE64STD_CHARS.value + '=',  #
        Base.base64url: Chars.BASE64URL_CHARS.value + '=',  #
    }

    def __init__(self, base: str) -> None:
        """CharSet class initializer.

        Args:
            base: base set ID

        """
        super().__init__()
        self.base: Base = getattr(Base, base)

    def extract(self, candidate: Candidate) -> bool:
        with contextlib.suppress(Exception):
            for i in self.CHARS[self.base]:
                if i not in candidate.line_data_list[0].value:
                    break
            else:
                return True
        return False


class FileExtension(WordIn):
    """Categorical feature of file type.

    Parameters:
        extensions: extension labels

    """

    def __init__(self, extensions: List[str]) -> None:
        super().__init__(extensions)

    def __call__(self, candidates: List[Candidate]) -> np.ndarray:
        extension_set = set([candidate.line_data_list[0].file_type.lower() for candidate in candidates])
        return self.word_in_set(extension_set)


    def extract(self, candidate: Candidate) -> Any:
        raise NotImplementedError


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
