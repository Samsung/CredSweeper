from credsweeper.common.constants import GroupType
from credsweeper.config.config import Config
from credsweeper.filters import ValueMorphemesCheck, ValueNotPartEncodedCheck, \
    ValueBase64DataCheck, ValueEntropyBase64Check, ValuePatternCheck, ValueNumberCheck, ValueTokenBase64Check, \
    ValueBase64PartCheck
from credsweeper.filters.group.group import Group


class WeirdBase64Token(Group):
    """Structured Token"""

    def __init__(self, config: Config) -> None:
        super().__init__(config, GroupType.DEFAULT)
        self.filters = [
            ValueMorphemesCheck(threshold=1),
            ValueNumberCheck(),
            ValueBase64DataCheck(),
            ValueTokenBase64Check(),
            ValueEntropyBase64Check(),
            ValuePatternCheck(),
            ValueNotPartEncodedCheck(),
            ValueBase64PartCheck(),
        ]
