import logging
import re
from functools import cached_property
from typing import Dict, List, Optional, Union, Set

from credsweeper import validations, filters
from credsweeper.common.constants import RuleType, Severity, MAX_LINE_LENGTH, Confidence
from credsweeper.common.keyword_pattern import KeywordPattern
from credsweeper.config import Config
from credsweeper.filters import Filter, group
from credsweeper.filters.group import Group
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
        use_ml: Should ML work on this credential or not. If not prediction based on regular expression and filter only
        validations: List of Validation objects that can check this credential using external API
        required_substrings: Optional list of substrings. Scanner would only apply this rule if line contain at least
          one of this substrings
        min_line_len: Optional minimal line length. Scanner would only apply this rule if line is equal or longer
        usage_list: List of analyze types. There are 2 different analyze type now ("src", "doc")

    """

    # mandatory fields
    NAME = "name"
    SEVERITY = "severity"
    CONFIDENCE = "confidence"
    TYPE = "type"
    VALUES = "values"
    MIN_LINE_LEN = "min_line_len"

    # auxiliary fields
    FILTER_TYPE = "filter_type"
    USE_ML = "use_ml"
    REQUIRED_SUBSTRINGS = "required_substrings"
    REQUIRED_REGEX = "required_regex"
    VALIDATIONS = "validations"
    TARGET = "target"

    def __init__(self, config: Config, rule_dict: Dict) -> None:
        self.config = config
        self._assert_rule_mandatory_fields(rule_dict)
        # mandatory fields
        self.__rule_name = str(rule_dict[Rule.NAME])
        if severity := Severity.get(rule_dict[Rule.SEVERITY]):
            self.__severity = severity
        else:
            self._malformed_rule_error(rule_dict, Rule.SEVERITY)
        if confidence := Confidence.get(rule_dict[Rule.CONFIDENCE]):
            self.__confidence = confidence
        else:
            self._malformed_rule_error(rule_dict, Rule.CONFIDENCE)
        if rule_type := getattr(RuleType, str(rule_dict[Rule.TYPE]).upper(), None):
            self.__rule_type: RuleType = rule_type
        else:
            self._malformed_rule_error(rule_dict, Rule.TYPE)
        self.__patterns = self._init_patterns(rule_dict[Rule.VALUES])
        # auxiliary fields
        self.__filters = self._init_filters(rule_dict.get(Rule.FILTER_TYPE, []))
        self.__use_ml = bool(rule_dict.get(Rule.USE_ML))
        self.__validations = self._init_validations(rule_dict.get(Rule.VALIDATIONS))
        self.__required_substrings = set(i.strip().lower() for i in rule_dict.get(Rule.REQUIRED_SUBSTRINGS, []))
        self.__has_required_substrings = bool(self.__required_substrings)
        required_regex = rule_dict.get(Rule.REQUIRED_REGEX)
        if required_regex and not isinstance(required_regex, str):
            self._malformed_rule_error(rule_dict, Rule.REQUIRED_REGEX)
        self.__required_regex = re.compile(required_regex) if required_regex else None
        self.__min_line_len = int(rule_dict.get(Rule.MIN_LINE_LEN, MAX_LINE_LENGTH))
        self.__target: List[str] = rule_dict.get(Rule.TARGET, [])

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
    def confidence(self) -> Confidence:
        """confidence getter"""
        return self.__confidence

    @cached_property
    def filters(self) -> List[Filter]:
        """filters getter"""
        return self.__filters

    def _init_filters(self, filter_type: Union[None, str, List[str]]) -> List[Filter]:
        """
            filter_type: str - applies Group of filter
                         list - creates specific set of Filters
        """
        _filters: List[Filter] = []
        if isinstance(filter_type, str):
            # when string passed - (Group) of filters is applied
            filter_group = getattr(group, filter_type, None)
            if isinstance(filter_group, type) and issubclass(filter_group, Group):
                return filter_group(self.config).filters  # type: ignore
        elif isinstance(filter_type, list):
            # list type means - list of (Filter)s is applied
            for i in filter_type:
                _filter = getattr(filters, i, None)
                if isinstance(_filter, type) and issubclass(_filter, Filter):
                    _filters.append(_filter(self.config))
                else:
                    break
            else:
                return _filters
        raise ValueError(f"Malformed rule '{self.__rule_name}'."
                         f" field '{Rule.FILTER_TYPE}' has invalid value"
                         f" '{filter_type}'")

    def _init_patterns(self, _values: List[str]) -> List[re.Pattern]:
        """Get pattern values for rule object.

        Set the pattern value attribute of the rule object based on the passed values.
        So, if the received rule type corresponds to the RuleType.KEYWORD type,
        the "patterns" attribute is assigned the value of template keyword regex
        with the corresponding value. Otherwise, if the received rule type corresponds
        to the RuleType.PATTERN, RuleType.MULTI or RuleType.PEM_KEY types, the "patterns" attribute is
        assigned the compile regex ov received value

        Args:
            _values: regular expressions

        """
        _patterns: List[re.Pattern] = []
        if RuleType.KEYWORD == self.rule_type and 0 < len(_values):
            for value in _values:
                _pattern = KeywordPattern.get_keyword_pattern(value)
                _patterns.append(_pattern)
            return _patterns
        elif RuleType.MULTI == self.rule_type and 2 == len(_values) \
                or self.rule_type in (RuleType.PATTERN, RuleType.PEM_KEY) and 0 < len(_values):
            for value in _values:
                _patterns.append(re.compile(value))
            if RuleType.PEM_KEY == self.rule_type and 1 < len(_values):
                logger.warning(f"Rule {self.rule_name} has extra patterns. Only single pattern supported.")
            elif RuleType.MULTI == self.rule_type and 2 < len(_values):
                logger.warning(f"Rule {self.rule_name} has extra patterns. Only two patterns supported.")
            return _patterns
        raise ValueError(f"Malformed rule config file. Rule '{self.rule_name}' type '{self.rule_type}' is invalid.")

    @cached_property
    def patterns(self) -> List[re.Pattern]:
        """patterns getter"""
        return self.__patterns

    @cached_property
    def use_ml(self) -> bool:
        """use_ml getter"""
        return self.__use_ml

    @cached_property
    def validations(self) -> List[Validation]:
        """validations getter"""
        return self.__validations

    def _init_validations(self, validation_names: Union[None, str, List[str]]) -> List[Validation]:
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
            _validations: List[Validation] = []
            for vn in validation_names:
                if validation_template := getattr(validations, vn, None):
                    _validations.append(validation_template())
                else:
                    break
            else:
                return _validations
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
        mandatory_fields = [Rule.NAME, Rule.SEVERITY, Rule.TYPE, Rule.VALUES, Rule.MIN_LINE_LEN]
        missing_fields = [field for field in mandatory_fields if field not in rule_template]
        if len(missing_fields) > 0:
            raise ValueError(f"Malformed rule config file. Contain rule with missing fields: {missing_fields}.")

    @cached_property
    def required_substrings(self) -> Set[str]:
        """required_substrings getter"""
        return self.__required_substrings

    @cached_property
    def has_required_substrings(self) -> bool:
        """has_required_substrings getter for speedup"""
        return self.__has_required_substrings

    @cached_property
    def required_regex(self) -> Optional[re.Pattern]:
        """required_regex getter"""
        return self.__required_regex

    @cached_property
    def min_line_len(self) -> int:
        """min_line_len getter"""
        return self.__min_line_len

    @cached_property
    def target(self) -> List[str]:
        """target getter"""
        return self.__target
