import string
from typing import Dict, Set

from credsweeper.common.constants import Base, Chars
from credsweeper.credentials import Candidate
from credsweeper.ml_model.features.feature import Feature


class CharSet(Feature):
    """Feature is true when all characters of the value are from a set."""

    # Constant dictionary to get characters set via name
    CHARS: Dict[Base, Set[str]] = {  #
        Base.digits: set(string.digits),  #
        Base.ascii_uppercase: set(string.ascii_uppercase),  #
        Base.ascii_lowercase: set(string.ascii_lowercase),  #
        Base.base16upper: set(Chars.BASE16UPPER.value),  #
        Base.base16lower: set(Chars.BASE16LOWER.value),  #
        Base.base32: set(Chars.BASE32_CHARS.value),  #
        Base.base36: set(Chars.BASE36_CHARS.value),  #
        Base.base64std: set(Chars.BASE64STD_CHARS.value + '='),  #
        Base.base64url: set(Chars.BASE64URL_CHARS.value + '='),  #
    }

    def __init__(self, base: str) -> None:
        """CharSet class initializer.

        Args:
            base: base set ID

        """
        super().__init__()
        self.base_set: Set[str] = self.CHARS[getattr(Base, base)]

    def extract(self, candidate: Candidate) -> bool:
        if set(candidate.line_data_list[0].value).difference(self.base_set):
            # value contains characters not from the set
            return False
        else:
            # no extra symbols in value
            return True
