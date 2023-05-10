from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import ValueCoupleKeywordCheck
from credsweeper.filters.group import Group
from credsweeper.filters.value_token_base32_check import ValueTokenBase32Check


class TokenBase32(Group):
    """TokenBase32 - uses specific for base32 entropy validation"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.PATTERN)
        self.filters.extend([ValueCoupleKeywordCheck(), ValueTokenBase32Check()])
