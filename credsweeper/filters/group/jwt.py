from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import ValueJsonWebTokenCheck
from credsweeper.filters.group import Group


class JWT(Group):
    """Json WEB Token"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.DEFAULT)
        self.filters = [ValueJsonWebTokenCheck()]
