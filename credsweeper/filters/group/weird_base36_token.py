from credsweeper.common.constants import GroupType
from credsweeper.config.config import Config
from credsweeper.filters import ValueMorphemesCheck, ValuePatternCheck, ValueNumberCheck, ValueEntropyBase36Check, \
    ValueTokenBase36Check
from credsweeper.filters.group.group import Group


class WeirdBase36Token(Group):
    """Structured Token"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.DEFAULT)
        self.filters = [
            ValueMorphemesCheck(threshold=1),
            ValuePatternCheck(),
            ValueNumberCheck(),
            ValueTokenBase36Check(),
            ValueEntropyBase36Check(),
        ]
