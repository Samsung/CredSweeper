from credsweeper.common.constants import GroupType
from credsweeper.config.config import Config
from credsweeper.filters.group.group import Group


class GeneralPattern(Group):
    """GeneralPattern"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.PATTERN)
