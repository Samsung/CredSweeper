from credsweeper.config import Config
from credsweeper.filters import ValueLengthCheck


class ValuePatternLengthCheck(ValueLengthCheck):
    """Check if potential candidate value is not too short like ValueLengthCheck but with different min_len"""

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.min_len = config.min_pattern_value_length
