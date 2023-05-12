from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters.cred_card_number_check import CreditCardNumberCheck
from credsweeper.filters.group import Group


class CreditCardNumberSequence(Group):
    """NumberSequence credentials group class.

    Applied credit card sequence filter
    """

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.PATTERN)
        self.filters = [CreditCardNumberCheck()]
