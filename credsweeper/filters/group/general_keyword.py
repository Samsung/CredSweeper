from credsweeper.common.constants import GroupType
from credsweeper.config.config import Config
from credsweeper.filters import ValueDictionaryKeywordCheck
from credsweeper.filters.group.group import Group


class GeneralKeyword(Group):
    """GeneralKeyword"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.KEYWORD)
        self.filters.extend([ValueDictionaryKeywordCheck()])
