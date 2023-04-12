from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import ValueDictionaryValueLengthCheck
from credsweeper.filters import ValueSplitKeywordCheck
from credsweeper.filters.group import Group


class PasswordKeyword(Group):
    """General keyword rule"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.KEYWORD)
        self.filters.extend([ValueDictionaryValueLengthCheck(), ValueSplitKeywordCheck()])
