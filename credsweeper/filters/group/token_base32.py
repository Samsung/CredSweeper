from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import ValueCoupleKeywordCheck, ValueTokenBase32Check
from credsweeper.filters.group import Group


class TokenBase32(Group):
    """TokenBase32 - uses specific for base32 entropy validation"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.DEFAULT)
        self.filters = [ValueCoupleKeywordCheck(), ValueTokenBase32Check()]
