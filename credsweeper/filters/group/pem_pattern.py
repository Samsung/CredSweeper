from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import LineSpecificKeyCheck
from credsweeper.filters.group import Group


class PEMPattern(Group):
    """PEMPattern"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.DEFAULT)
        self.filters = [LineSpecificKeyCheck()]
