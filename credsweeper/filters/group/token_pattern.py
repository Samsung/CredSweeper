from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import ValueCoupleKeywordCheck
from credsweeper.filters.group import Group


class TokenPattern(Group):
    """TokenPattern"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.PATTERN)
        self.filters.extend([ValueCoupleKeywordCheck()])
