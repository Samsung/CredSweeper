from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import ValueDictionaryKeywordCheck, ValueUselessWordCheck
from credsweeper.filters.group import Group


class GeneralKeyword(Group):

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.KEYWORD)
        self.filters.extend([ValueDictionaryKeywordCheck(), ValueUselessWordCheck()])
