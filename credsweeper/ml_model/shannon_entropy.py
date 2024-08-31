"""Most rules are described in 'Secrets in Source Code: Reducing False Positives Using Machine Learning'."""
import contextlib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Any, Dict, Tuple, Set

import numpy as np

from credsweeper.common.constants import Base, Chars, CHUNK_SIZE
from credsweeper.credentials import Candidate
from credsweeper.ml_model.reny_entropy import RenyiEntropy
from credsweeper.utils import Util




class ShannonEntropy(RenyiEntropy):
    """Shannon entropy feature."""

    def __init__(self, base: str, norm: bool = False) -> None:
        super().__init__(base, 1.0, norm)

