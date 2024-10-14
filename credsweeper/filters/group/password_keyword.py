from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import ValueDictionaryValueLengthCheck, LineGitBinaryCheck
from credsweeper.filters import ValueSplitKeywordCheck
from credsweeper.filters.group import Group
from credsweeper.filters.line_uue_part_check import LineUUEPartCheck


class PasswordKeyword(Group):
    """PasswordKeyword"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.KEYWORD)
        self.filters.extend(
            [ValueDictionaryValueLengthCheck(),
             ValueSplitKeywordCheck(),
             LineGitBinaryCheck(),
             LineUUEPartCheck()])
