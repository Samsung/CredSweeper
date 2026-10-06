import math
import string
from typing import Optional

from credsweeper.common.constants import Chars
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueEntropyCheck(Filter):
    """Check that candidate value has enough full Shanon Entropy in bits"""

    # base91x case
    MAX_CHAR_ENTROPY = math.log2(91)

    CHARSET_MAPPER = (
        (set(Chars.BASE64URLPAD_CHARS.value), 6),
        (set(Chars.BASE64STDPAD_CHARS.value), 6),
        (set(Chars.BASE62_CHARS.value), math.log2(62)),
        (set(Chars.BASE36_CHARS.value), math.log2(36)),
        (set(Chars.BASE32_CHARS.value), 5),
        (set(Chars.UUID_UPPER_CHARS.value), 4),
        (set(Chars.UUID_LOWER_CHARS.value), 4),
        (set(string.digits), math.log2(10)),
    )

    def __init__(self, config: Optional[Config] = None, threshold: Optional[int] = None) -> None:
        self.threshold = threshold

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        if self.threshold:
            char_entropy = ValueEntropyCheck.MAX_CHAR_ENTROPY
            value_charset = set(line_data.value)
            for charset, entropy in ValueEntropyCheck.CHARSET_MAPPER:
                if value_charset <= charset:
                    char_entropy = min(char_entropy, entropy)
            theoretical_entropy = char_entropy * len(line_data.value)
            if theoretical_entropy < self.threshold:
                return True
        return False
