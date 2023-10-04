from credsweeper.config import Config
from credsweeper.filters import ValuePatternCheck


class ValuePemPatternCheck(ValuePatternCheck):
    """Check if candidate value contain specific pattern.

    Similar to ValuePatternCheck but pattern_len is different
    """

    def __init__(self, config: Config):
        """Create ValuePatternCheck with a specific pattern_len to check.

        Args:
            config: pattern len to use during check. DEFAULT_PATTERN_LEN by default

        """
        super().__init__(config)
