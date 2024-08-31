"""Most rules are described in 'Secrets in Source Code: Reducing False Positives Using Machine Learning'."""
import contextlib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Any, Dict, Tuple, Set

import numpy as np

from credsweeper.common.constants import Base, Chars, CHUNK_SIZE
from credsweeper.credentials import Candidate
from credsweeper.ml_model.features import Feature
from credsweeper.utils import Util



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

