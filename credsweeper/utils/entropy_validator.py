from functools import cached_property
from typing import Optional

from credsweeper.common.constants import Chars, ENTROPY_LIMIT_BASE64, ENTROPY_LIMIT_BASE3x
from credsweeper.utils import Util


class EntropyValidator:
    """Verifies data entropy with base64, base36 and base16(hex)"""
    CHARS_LIMIT_MAP = {
        Chars.BASE64_CHARS: ENTROPY_LIMIT_BASE64,
        Chars.BASE36_CHARS: ENTROPY_LIMIT_BASE3x,
        Chars.HEX_CHARS: ENTROPY_LIMIT_BASE3x
    }

    def __init__(self, data: str, iterator: Optional[Chars] = None):
        self.__valid: Optional[bool] = None
        self.__entropy: Optional[float] = None
        self.__iterator: Optional[str] = None
        if isinstance(data, str):
            if isinstance(iterator, Chars):
                self.__entropy = Util.get_shannon_entropy(data, iterator.value)
                if _limit := self.CHARS_LIMIT_MAP.get(iterator):
                    self.__valid = _limit < self.__entropy
                    self.__iterator = iterator.name
            else:
                for _iterator, _limit in self.CHARS_LIMIT_MAP.items():
                    entropy = Util.get_shannon_entropy(data, _iterator.value)
                    if _limit < entropy:
                        self.__entropy = entropy
                        self.__iterator = _iterator.name
                        self.__valid = True
                        break
                    else:
                        # keep maximal entropy value
                        if self.__entropy:
                            if self.__entropy < entropy:
                                self.__entropy = entropy
                                self.__iterator = _iterator.name
                        else:
                            self.__entropy = entropy
                            self.__iterator = _iterator.name
                else:
                    self.__valid = False

    @cached_property
    def valid(self) -> Optional[bool]:
        """Shows whether validation was successful"""
        return self.__valid

    @cached_property
    def entropy(self) -> Optional[float]:
        """Value success entropy or maximal value"""
        return self.__entropy

    @cached_property
    def iterator(self) -> Optional[str]:
        """Which iterator was used for the entropy"""
        return self.__iterator

    def __repr__(self) -> str:
        if isinstance(self.entropy, float):
            return f"{self.iterator} {self.entropy:.6f} {self.valid}"
        else:
            return f"{self.iterator} {self.entropy} {self.valid}"

    def __str__(self) -> str:
        return self.__repr__()

    def to_dict(self) -> dict:
        """Representation to dictionary"""
        return {"iterator": self.iterator, "entropy": self.entropy, "valid": self.valid}
