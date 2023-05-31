from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import ValueCoupleKeywordCheck, ValueCamelCaseCheck, ValueNumberCheck, ValuePatternCheck
from credsweeper.filters.group import Group


class TokenPattern(Group):
    """Token Pattern"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.DEFAULT)
        self.filters = [ValueCoupleKeywordCheck(), ValueNumberCheck(), ValueCamelCaseCheck(), ValuePatternCheck(config)]
