import logging
import re
from functools import cached_property
from typing import Dict, List, Optional, Union

from credsweeper import validations, filters
from credsweeper.common.constants import RuleType, Severity, MAX_LINE_LENGTH
from credsweeper.config import Config
from credsweeper.filters import Filter, group
from credsweeper.filters.group import Group
from credsweeper.utils import Util
from credsweeper.validations import Validation

logger = logging.getLogger(__name__)


class Rule:
    """Regular expression to detect some credential type.

    Class contains regular expression to detect some credential type, credential name, assumed severity
        and details on how detection should be processed

    Parameters:
        rule_name: Name displayed if rule
        rule_type: RuleType used for this rule
        severity: critical/high/medium/low
        filters: List of Filter OR _one_ filter Group that can be used to filters False detections based on rules
        patterns: Regular expressions that can be used for detection
        pattern_type: single_pattern/multi_pattern/pem_key_pattern. single_pattern for simple single line credentials
          multi_pattern for credentials span for rew lines. pem_key_pattern for PEM like credentials
        use_ml: Should ML work on this credential or not. If not prediction based on regular expression and filter only
        validations: List of Validation objects that can check this credential using external API
        required_substrings: Optional list of substrings. Scanner would only apply this rule if line contain at least
          one of this substrings
        min_line_len: Optional minimal line length. Scanner would only apply this rule if line is equal or longer
        usage_list: List of analyze types. There are 2 different analyze type now ("src", "doc")

    """

    SINGLE_PATTERN = "single_pattern"
    MULTI_PATTERN = "multi_pattern"
    PEM_KEY_PATTERN = "pem_key_pattern"

    # mandatory fields
    NAME = "name"
    SEVERITY = "severity"
    TYPE = "type"
    USAGE_LIST = "usage_list"
    VALUES = "values"
    FILTER_TYPE = "filter_type"
    MIN_LINE_LEN = "min_line_len"

    # auxiliary fields
    USE_ML = "use_ml"
    REQUIRED_SUBSTRINGS = "required_substrings"
    VALIDATIONS = "validations"

    def __init__(self, config: Config, rule_dict: Dict) -> None:
        self.config = config
        self._assert_rule_mandatory_fields(rule_dict)
        # mandatory fields
        self.__rule_name = str(rule_dict[Rule.NAME])
        if severity := Severity.get(rule_dict[Rule.SEVERITY]):
            self.__severity = severity
        else:
            self._malformed_rule_error(rule_dict, Rule.SEVERITY)
        if rule_type := getattr(RuleType, str(rule_dict[Rule.TYPE]).upper(), None):
            self.__rule_type: RuleType = rule_type
        else:
            self._malformed_rule_error(rule_dict, Rule.TYPE)
        self.__patterns = Rule._get_patterns(self.rule_type, rule_dict[Rule.VALUES])
        # auxiliary fields
        self.__filters = self._get_filters(rule_dict.get(Rule.FILTER_TYPE))
        self.__pattern_type = Rule._get_pattern_type(self.rule_type, len(self.patterns))
        self.__use_ml = bool(rule_dict.get(Rule.USE_ML))
        self.__validations = self._get_validations(rule_dict.get(Rule.VALIDATIONS))
        self.__required_substrings = [i.strip().lower() for i in rule_dict.get(Rule.REQUIRED_SUBSTRINGS, [])]
        self.__min_line_len = int(rule_dict.get(Rule.MIN_LINE_LEN, MAX_LINE_LENGTH))
        self.__usage_list: List[str] = rule_dict.get(Rule.USAGE_LIST, [])

    def _malformed_rule_error(self, rule_dict: Dict, field: str):
        raise ValueError(f"Malformed rule '{self.__rule_name}'."
                         f" field '{field}' has invalid value"
                         f" '{rule_dict.get(field)}'")

    @cached_property
    def rule_name(self) -> str:
        """rule_name getter"""
        return self.__rule_name

    @cached_property
    def rule_type(self) -> RuleType:
        """rule_type getter"""
        return self.__rule_type

    @cached_property
    def severity(self) -> Severity:
        """severity getter"""
        return self.__severity

    @cached_property
    def filters(self) -> List[Filter]:
        """filters getter"""
        return self.__filters

    def _get_filters(self, filter_type: Union[None, str, List[str]]) -> List[Filter]:
        """
            filter_type: str - applies Group of filter
                         list - creates specific set of Filters
        """
        if isinstance(filter_type, str):
            # when string passed - (Group) of filters is applied
            filter_group = getattr(group, filter_type, None)
            if isinstance(filter_group, type) and issubclass(filter_group, Group):
                return filter_group(self.config).filters  # type: ignore
        elif isinstance(filter_type, list):
            # list type means - list of (Filter)s is applied
            filter_list = []
            for i in filter_type:
                _filter = getattr(filters, i, None)
                if isinstance(_filter, type) and issubclass(_filter, Filter):
                    filter_list.append(_filter(self.config))
                else:
                    break
            else:
                return filter_list
        raise ValueError(f"Malformed rule '{self.__rule_name}'."
                         f" field '{Rule.FILTER_TYPE}' has invalid value"
                         f" '{filter_type}'")

    @staticmethod
    def _get_patterns(_rule_type: RuleType, _values: List[str]) -> List[re.Pattern]:
        """Get pattern values for rule object.

        Set the pattern value attribute of the rule object based on the passed values.
        So, if the received rule type corresponds to the RuleType.KEYWORD type,
        the "patterns" attribute is assigned the value of template keyword regex
        with the corresponding value. Otherwise, if the received rule type corresponds
        to the RuleType.PATTERN or RuleType.PEM_KEY types, the "patterns" attribute is
        assigned the compile regex ov received value

        Args:
            _rule_type: type of rule
            _values: regular expressions

        """
        _patterns = []
        if RuleType.KEYWORD == _rule_type:
            for value in _values:
                _patterns.append(Util.get_keyword_pattern(value))
        elif _rule_type in (RuleType.PATTERN, RuleType.PEM_KEY):
            for value in _values:
                _patterns.append(re.compile(value))
        else:
            raise ValueError(f"Malformed rule config file. Rule type '{_rule_type}' is invalid.")
        return _patterns

    @cached_property
    def patterns(self) -> List[re.Pattern]:
        """patterns getter"""
        return self.__patterns

    @staticmethod
    def _get_pattern_type(_rule_type: RuleType, _values_len: int) -> str:
        """Detect pattern type for rule object.

        Set the pattern_type attribute of the rule object based on the passed values.
        So, if the received rule type corresponds to the RuleType.PEM_KEY type,
        the class attribute is assigned the value "pem_key_pattern". Otherwise,
        for rules containing only one search value set the type "single_pattern"
        and for rules with more than one value set "multi_pattern" type

        Args:
            _rule_type: rule type
            _values_len: length of values with expressions

        """
        _pattern_type: Optional[str] = None
        if RuleType.PEM_KEY == _rule_type:
            _pattern_type = Rule.PEM_KEY_PATTERN
        elif 1 == _values_len:
            _pattern_type = Rule.SINGLE_PATTERN
        elif 1 < _values_len:
            _pattern_type = Rule.MULTI_PATTERN
        else:
            raise ValueError(f"Malformed rule config file. Rule type '{_rule_type}' or '{_values_len}' are invalid.")
        return _pattern_type

    @cached_property
    def pattern_type(self) -> str:
        """pattern_type getter"""
        return self.__pattern_type

    @cached_property
    def use_ml(self) -> bool:
        """use_ml getter"""
        return self.__use_ml

    @cached_property
    def validations(self) -> List[Validation]:
        """validations getter"""
        return self.__validations

    def _get_validations(self, validation_names: Union[None, str, List[str]]) -> List[Validation]:
        """Set api validations to the current rule.

        All string in `validation_names` should be class names from `credsweeper.validations`

        Args:
            validation_names: validation names

        """

        if not validation_names:
            # empty string check to avoid exceptions for getattr
            return []
        elif isinstance(validation_names, str):
            # more convenience way in case of single validator - only one line in YAML
            if validation_template := getattr(validations, validation_names, None):
                return [validation_template]
        elif isinstance(validation_names, list):
            selected_validations = []
            for vn in validation_names:
                if validation_template := getattr(validations, vn, None):
                    selected_validations.append(validation_template())
                else:
                    break
            else:
                return selected_validations
        raise ValueError(f"Malformed rule '{self.__rule_name}'."
                         f" field '{Rule.VALIDATIONS}' has invalid value"
                         f" '{validation_names}'")

    @staticmethod
    def _assert_rule_mandatory_fields(rule_template: Dict) -> None:
        """Assert that rule_template have all required fields.

        Args:
            rule_template: dictionary loaded from the config file

        Raises:
            ValueError if missing fields is present

        """
        mandatory_fields = [
            Rule.NAME, Rule.SEVERITY, Rule.TYPE, Rule.USAGE_LIST, Rule.VALUES, Rule.FILTER_TYPE, Rule.MIN_LINE_LEN
        ]
        missing_fields = [field for field in mandatory_fields if field not in rule_template]
        if len(missing_fields) > 0:
            raise ValueError(f"Malformed rule config file. Contain rule with missing fields: {missing_fields}.")

    @cached_property
    def required_substrings(self) -> List[str]:
        """required_substrings getter"""
        return self.__required_substrings

    @cached_property
    def min_line_len(self) -> int:
        """min_line_len getter"""
        return self.__min_line_len

    @cached_property
    def usage_list(self) -> List[str]:
        """usage_list getter"""
        return self.__usage_list
