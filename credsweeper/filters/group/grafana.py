from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import ValueGrafanaCheck
from credsweeper.filters.group import Group


class Grafana(Group):
    """Grafana Provisioned API Key and Access Policy Token"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.DEFAULT)
        self.filters = [ValueGrafanaCheck()]
