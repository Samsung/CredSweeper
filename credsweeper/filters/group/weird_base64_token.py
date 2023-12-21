from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import ValueCoupleKeywordCheck, ValueNotPartEncodedCheck, \
    ValueBase64DataCheck, ValueEntropyBase64Check, ValuePatternCheck, ValueNumberCheck, ValueTokenBase64Check
from credsweeper.filters.group import Group


class WeirdBase64Token(Group):
    """Structured Token"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.DEFAULT)
        self.filters = [
            ValueCoupleKeywordCheck(),
            ValueNumberCheck(),
            ValueBase64DataCheck(),
            ValueTokenBase64Check(),
            ValueEntropyBase64Check(),
            ValuePatternCheck(config),
            ValueNotPartEncodedCheck()
        ]
