from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import ValueCoupleKeywordCheck, ValuePatternCheck, ValueNumberCheck, ValueEntropyBase36Check, \
    ValueTokenBase36Check
from credsweeper.filters.group import Group


class WeirdBase36Token(Group):
    """Structured Token"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.DEFAULT)
        self.filters = [
            ValueCoupleKeywordCheck(),
            ValuePatternCheck(config),
            ValueNumberCheck(),
            ValueTokenBase36Check(),
            ValueEntropyBase36Check()
        ]
