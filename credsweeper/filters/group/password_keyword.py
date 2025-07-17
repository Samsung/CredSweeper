from credsweeper.common.constants import GroupType
from credsweeper.config.config import Config
from credsweeper.filters import ValueLengthCheck, LineGitBinaryCheck
from credsweeper.filters import ValueSplitKeywordCheck
from credsweeper.filters.group.group import Group
from credsweeper.filters.line_uue_part_check import LineUUEPartCheck


class PasswordKeyword(Group):
    """PasswordKeyword"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.KEYWORD)
        self.filters.extend([
            ValueLengthCheck(max_len=config.max_password_value_length),
            ValueSplitKeywordCheck(),
            LineGitBinaryCheck(),
            LineUUEPartCheck()
        ])
