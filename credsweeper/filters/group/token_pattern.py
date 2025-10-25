from credsweeper.common.constants import GroupType
from credsweeper.config.config import Config
from credsweeper.filters import ValueMorphemesCheck, ValueCamelCaseCheck, ValueNumberCheck, ValuePatternCheck
from credsweeper.filters.group.group import Group


class TokenPattern(Group):
    """Token Pattern"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.DEFAULT)
        self.filters = [
            ValueMorphemesCheck(),
            ValueNumberCheck(),
            ValueCamelCaseCheck(),
            ValuePatternCheck(),
        ]
