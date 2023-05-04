from abc import ABC
from typing import List

from credsweeper.common.constants import GroupType
from credsweeper.config import Config
from credsweeper.filters import (Filter, LineSpecificKeyCheck, SeparatorUnusualCheck, ValueAllowlistCheck,
                                 ValueArrayDictionaryCheck, ValueBlocklistCheck, ValueCamelCaseCheck,
                                 ValueFilePathCheck, ValueFirstWordCheck, ValueLastWordCheck, ValueLengthCheck,
                                 ValueMethodCheck, ValueNotAllowedPatternCheck, ValuePatternCheck, ValueSimilarityCheck,
                                 ValueStringTypeCheck, ValueTokenCheck, VariableNotAllowedPatternCheck)


class Group(ABC):
    """Abstract Group class"""

    def __init__(self, config: Config, rule_type: GroupType) -> None:
        if rule_type == GroupType.KEYWORD:
            self.filters: List[Filter] = self.get_keyword_base_filters(config)
        elif rule_type == GroupType.PATTERN:
            self.filters: List[Filter] = self.get_pattern_base_filters(config)
        else:
            self.filters: List[Filter] = []

    @property
    def filters(self) -> List[Filter]:
        """property getter"""
        return self.__filters

    @filters.setter
    def filters(self, filters: List[Filter]) -> None:
        """property setter"""
        self.__filters = filters

    def get_keyword_base_filters(self, config: Config) -> List[Filter]:
        """returns base filters"""
        return [
            SeparatorUnusualCheck(),
            ValueAllowlistCheck(),
            ValueArrayDictionaryCheck(),
            ValueBlocklistCheck(),
            ValueCamelCaseCheck(),
            ValueFilePathCheck(),
            ValueFirstWordCheck(),
            ValueLastWordCheck(),
            ValueLengthCheck(config.min_keyword_value_length),
            ValueMethodCheck(),
            ValueNotAllowedPatternCheck(),
            ValueSimilarityCheck(),
            ValueStringTypeCheck(config),
            ValueTokenCheck(),
            VariableNotAllowedPatternCheck(),
            ValuePatternCheck()
        ]

    def get_pattern_base_filters(self, config: Config) -> List[Filter]:
        """return base filters for pattern"""
        return [LineSpecificKeyCheck(), ValuePatternCheck(), ValueLengthCheck(config.min_pattern_value_length)]
