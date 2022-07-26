from typing import Dict, List, Optional

from regex import regex

from credsweeper import validations
from credsweeper.common.constants import RuleType, Severity
from credsweeper.config import Config
from credsweeper.filters import Filter, group
from credsweeper.utils import Util
from credsweeper.validations import Validation


class Rule:
    """Regular expression to detect some credential type.

    Class contains regular expression to detect some credential type, credential name, assumed severity
        and details on how detection should be processed

    Parameters:
        rule_name: Name displayed if rule
        rule_type: RuleType used for this rule
        severity: critical/high/medium/low
        filters: List of Filter objects that can be used to filters False detections based on rules
        patterns: Regular expressions that can be used for detection
        pattern_type: single_pattern/multi_pattern/pem_key_pattern. single_pattern for simple single line credentials
          multi_pattern for credentials span for rew lines. pem_key_pattern for PEM like credentials
        use_ml: Should ML work on this credential or not. If not prediction based on regular expression and filter only
        validations: List of Validation objects that can check this credential using external API
        required_substrings: Optional list of substrings. Scanner would only apply this rule if line contain at least
          one of this substrings
        min_line_len: Optional minimal line length. Scanner would only apply this rule if line is equal or longer

    """

    SINGLE_PATTERN = "single_pattern"
    MULTI_PATTERN = "multi_pattern"
    PEM_KEY_PATTERN = "pem_key_pattern"

    def __init__(self, config: Config, rule_template: Dict) -> None:
        self.config = config
        self._assert_all_rule_fields(rule_template)
        self.rule_name: Optional[str] = rule_template["name"]
        _rule_template_type = rule_template["type"]
        self.rule_type: Optional[RuleType] = getattr(RuleType, _rule_template_type.upper(), None)
        if self.rule_type is None:
            raise ValueError(f"Malformed rule config file. Rule type '{_rule_template_type}' is invalid.")
        self.severity: Severity = rule_template["severity"]
        self.filters: List[Filter] = rule_template.get("filter_type")
        self.patterns: List[regex.Pattern] = Rule._get_patterns(self.rule_type, rule_template["values"])
        self.pattern_type: str = Rule._get_pattern_type(self.rule_type, len(self.patterns))
        self.use_ml: bool = rule_template["use_ml"]
        self.validations: List[Validation] = rule_template.get("validations")
        self.required_substrings: List[str] = [s.lower() for s in rule_template.get("required_substrings", [""])]
        self.min_line_len: int = rule_template.get("min_line_len", -1)

    @property
    def rule_name(self) -> str:
        """rule_name getter"""
        return self.__rule_name

    @rule_name.setter
    def rule_name(self, rule_name: str) -> None:
        """rule_name setter"""
        self.__rule_name = rule_name

    @property
    def rule_type(self) -> RuleType:
        """rule_type getter"""
        return self.__rule_type

    @rule_type.setter
    def rule_type(self, rule_type: RuleType) -> None:
        """rule_type getter"""
        self.__rule_type = rule_type

    @property
    def severity(self) -> Severity:
        """severity getter"""
        return self.__severity

    @severity.setter
    def severity(self, severity: str) -> None:
        """severity setter"""
        severity_obj: Severity = getattr(Severity, severity.upper(), None)
        if severity_obj is None:
            raise ValueError(f'Malformed rule config file. Rule severity "{severity}" is invalid.')
        self.__severity = severity_obj

    @property
    def filters(self) -> List[Filter]:
        """filters getter"""
        return self.__filters

    @filters.setter
    def filters(self, filter_type: str) -> None:
        """filters setter"""
        if filter_type == "" or filter_type is None:
            self.__filters = []
        else:
            filter_group = getattr(group, filter_type, None)
            if filter_group is None:
                raise ValueError(f'Malformed rule config file. Rule filter_type "{filter_type}" is invalid.')
            self.__filters = filter_group(self.config).filters

    @staticmethod
    def _get_patterns(_rule_type: RuleType, _values: List[str]) -> List[regex.Pattern]:
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
                _patterns.append(regex.compile(value))
        else:
            raise ValueError(f"Malformed rule config file. Rule type '{_rule_type}' is invalid.")
        return _patterns

    @property
    def patterns(self) -> List[regex.Pattern]:
        """patterns getter"""
        return self.__patterns

    @patterns.setter
    def patterns(self, _patterns: List[regex.Pattern]) -> None:
        """patterns setter"""
        self.__patterns = _patterns

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

    @property
    def pattern_type(self) -> str:
        """pattern_type getter"""
        return self.__pattern_type

    @pattern_type.setter
    def pattern_type(self, _pattern_type: str) -> None:
        """pattern_type setter"""
        self.__pattern_type = _pattern_type

    @property
    def use_ml(self) -> bool:
        """use_ml getter"""
        return self.__use_ml

    @use_ml.setter
    def use_ml(self, use_ml: bool) -> None:
        """use_ml setter"""
        if not isinstance(use_ml, bool):
            raise ValueError('Malformed rule config file. Field "use_ml" should have a boolean value.')
        self.__use_ml = use_ml

    @property
    def validations(self) -> List[Validation]:
        """validations getter"""
        return self.__validations

    @validations.setter
    def validations(self, validation_names: List[str]) -> None:
        """Set api validations to the current rule.

        All string in `validation_names` should be class names from `credsweeper.validations`

        Args:
            validation_names: validation names

        """
        selected_validations = []

        if validation_names is not None:
            for vn in validation_names:
                validation_template = getattr(validations, vn, None)
                if validation_template is None:
                    raise ValueError(f'Malformed rule config file. Validation "{vn}" is invalid.')
                selected_validations.append(validation_template())

        self.__validations = selected_validations

    @staticmethod
    def _assert_all_rule_fields(rule_template: Dict) -> None:
        """Assert that rule_template have all required fields.

        Args:
            rule_template: dictionary loaded from the config file

        Raises:
            ValueError if missing fields is present

        """
        required_fields = ["name", "severity", "type", "values", "use_ml"]
        missing_fields = [field for field in required_fields if field not in rule_template]
        if len(missing_fields) > 0:
            raise ValueError(f"Malformed rule config file. Contain rule with missing fields: {missing_fields}.")

    @property
    def required_substrings(self) -> List[str]:
        """required_substrings getter"""
        return self.__required_substrings

    @required_substrings.setter
    def required_substrings(self, required_substrings: List[str]) -> None:
        """required_substrings setter"""
        self.__required_substrings = required_substrings

    @property
    def min_line_len(self) -> int:
        """min_line_len getter"""
        return self.__min_line_len

    @min_line_len.setter
    def min_line_len(self, min_line_len: int) -> None:
        """min_line_len setter"""
        self.__min_line_len = min_line_len
