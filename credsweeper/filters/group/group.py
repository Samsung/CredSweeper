from abc import ABC
from typing import List

from credsweeper.common.constants import GroupType
from credsweeper.config.config import Config
from credsweeper.filters.filter import Filter
from credsweeper.filters.line_specific_key_check import LineSpecificKeyCheck
from credsweeper.filters.value_allowlist_check import ValueAllowlistCheck
from credsweeper.filters.value_array_dictionary_check import ValueArrayDictionaryCheck
from credsweeper.filters.value_blocklist_check import ValueBlocklistCheck
from credsweeper.filters.value_camel_case_check import ValueCamelCaseCheck
from credsweeper.filters.value_file_path_check import ValueFilePathCheck
from credsweeper.filters.value_hex_number_check import ValueHexNumberCheck
from credsweeper.filters.value_last_word_check import ValueLastWordCheck
from credsweeper.filters.value_method_check import ValueMethodCheck
from credsweeper.filters.value_not_allowed_pattern_check import ValueNotAllowedPatternCheck
from credsweeper.filters.value_pattern_check import ValuePatternCheck
from credsweeper.filters.value_similarity_check import ValueSimilarityCheck
from credsweeper.filters.value_string_type_check import ValueStringTypeCheck
from credsweeper.filters.value_token_check import ValueTokenCheck


class Group(ABC):
    """Abstract Group class"""

    def __init__(self, config: Config, rule_type: GroupType = GroupType.DEFAULT) -> None:
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

    @staticmethod
    def get_keyword_base_filters(config: Config) -> List[Filter]:
        """returns base filters"""
        filters = [  #
            ValueAllowlistCheck(),
            ValueArrayDictionaryCheck(),
            ValueBlocklistCheck(),
            ValueCamelCaseCheck(),
            ValueFilePathCheck(),
            ValueHexNumberCheck(),
            ValueLastWordCheck(),
            ValueMethodCheck(),
            ValueSimilarityCheck(),
            ValueStringTypeCheck(config),
            ValueTokenCheck(),
        ]
        if not config.doc:
            filters.extend([ValuePatternCheck(pattern_len=config.pattern_len), ValueNotAllowedPatternCheck()])
        return filters

    @staticmethod
    def get_pattern_base_filters(config: Config) -> List[Filter]:
        """return base filters for pattern"""
        return [  #
            LineSpecificKeyCheck(),  #
            ValuePatternCheck(pattern_len=config.pattern_len),  #
        ]
