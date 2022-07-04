from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import (ValueAllowlistCheck, ValueArrayDictionaryCheck, ValueAsciiCheck, ValueBlocklistCheck,
                                 ValueCamelCaseCheck, ValueDictionaryValueLengthCheck, ValueFilePathCheck,
                                 ValueFirstWordCheck, ValueLastWordCheck, ValueLengthCheck, ValueMethodCheck,
                                 ValueNotAllowedPatternCheck, ValuePatternCheck, ValueStringTypeCheck, ValueTokenCheck)
from credsweeper.filters.group import Group


class UrlCredentialsGroup(Group):

    def __init__(self, config: Config) -> None:
        """URL credentials group class.

        Similar to PasswordKeyword, but exclude all checks dependent on the variable name, as URL credentials have no
        explicitly defined variable
        """
        super().__init__(config, GroupType.EMPTY)
        self.filters = [
            ValueAllowlistCheck(),
            ValueArrayDictionaryCheck(),
            ValueAsciiCheck(),
            ValueBlocklistCheck(),
            ValueCamelCaseCheck(),
            ValueFilePathCheck(),
            ValueFirstWordCheck(),
            ValueLastWordCheck(),
            ValueLengthCheck(),
            ValueMethodCheck(),
            ValueStringTypeCheck(config),
            ValueNotAllowedPatternCheck(),
            ValueTokenCheck(),
            ValueDictionaryValueLengthCheck(),
            ValuePatternCheck()
        ]
