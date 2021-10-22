from typing import Dict, List, Optional, Tuple

from regex import regex

from credsweeper import validations
from credsweeper.common.constants import RuleType, Severity
from credsweeper.config import Config
from credsweeper.filters import Filter, group
from credsweeper.utils import Util
from credsweeper.validations import Validation


class Rule:
    """Class contains regular expression to detect some credential type, credential name, assumed severity
        and details on how detection should be processed

    Attributes:
        rule_name: Name displayed if rule
        severity: critical/high/medium/low
        filters: List of Filter objects that can be used to filters False detections based on rules
        patterns: regular expressions that can be used for detection
        pattern_type: single_pattern/multi_pattern/pem_key_pattern. single_pattern for simple single line credentials
            multi_pattern for credentials span for rew lines. pem_key_pattern for PEM like credentials
        use_ml: Should ML work on this credential or not. If not prediction based on regular expression and filter only
        validations: List of Validation objects that can check this credential using external API
    """
    SINGLE_PATTERN = "single_pattern"
    MULTI_PATTERN = "multi_pattern"
    PEM_KEY_PATTERN = "pem_key_pattern"

    def __init__(self, config: Config, rule_template: Dict) -> None:
        self.config = config
        self._assert_all_rule_fields(rule_template)
        self.rule_name: Optional[str] = rule_template["name"]
        self.severity: Severity = rule_template["severity"]
        self.filters: List[Filter] = rule_template.get("filter_type")
        self.patterns: List[regex.Pattern] = (rule_template["type"], rule_template["values"])
        self.pattern_type: Optional[str] = (rule_template["type"], rule_template["values"])
        self.use_ml: bool = rule_template["use_ml"]
        self.validations: List[Validation] = rule_template.get("validations")

    @property
    def rule_name(self) -> str:
        return self.__rule_name

    @rule_name.setter
    def rule_name(self, rule_name: str) -> None:
        self.__rule_name = rule_name

    @property
    def severity(self) -> Severity:
        return self.__severity

    @severity.setter
    def severity(self, severity: str) -> None:
        severity_obj = getattr(Severity, severity.upper(), None)
        if severity_obj is None:
            raise ValueError(f'Malformed rule config file. Rule severity "{severity}" is invalid.')
        self.__severity = severity_obj

    @property
    def filters(self) -> List[Filter]:
        return self.__filters

    @filters.setter
    def filters(self, filter_type: str) -> None:
        if filter_type == "" or filter_type is None:
            self.__filters = []
        else:
            filter_group = getattr(group, filter_type, None)
            if filter_group is None:
                raise ValueError(f'Malformed rule config file. Rule filter_type "{filter_type}" is invalid.')
            self.__filters = filter_group(self.config).filters

    @property
    def patterns(self) -> List[regex.Pattern]:
        return self.__patterns

    @patterns.setter
    def patterns(self, args: Tuple[str, List[str]]) -> None:
        """Set pattern value for rule object

        Set the pattern value attribute of the rule object based on the passed values.
        So, if the received rule type corresponds to the RuleType.KEYWORD type,
        the "patterns" attribute is assigned the value of template keyword regex
        with the corresponding value. Otherwise, if the received rule type corresponds
        to the RuleType.PATTERN or RuleType.PEM_KEY types, the "patterns" attribute is
        assigned the compile regex ov received value

        Args:
            args: Tuple of rule type and regular expressions
        """
        rule_type_str, values = args
        rule_type = getattr(RuleType, rule_type_str.upper(), None)
        self.__patterns = []
        if rule_type is None:
            raise ValueError(f'Malformed rule config file. Rule type "{rule_type_str}" is invalid.')
        if rule_type == RuleType.KEYWORD:
            for value in values:
                self.__patterns.append(Util.get_keyword_pattern(value))
        elif rule_type in (RuleType.PATTERN, RuleType.PEM_KEY):
            for value in values:
                self.__patterns.append(regex.compile(value))

    @property
    def pattern_type(self) -> str:
        return self.__pattern_type

    @pattern_type.setter
    def pattern_type(self, args: Tuple[str, List[str]]) -> None:
        """Set pattern type for rule object

        Set the pattern_type attribute of the rule object based on the passed values.
        So, if the received rule type corresponds to the RuleType.PEM_KEY type,
        the class attribute is assigned the value "pem_key_pattern". Otherwise,
        for rules containing only one search value set the type "single_pattern"
        and for rules with more than one value set "multi_pattern" type

        Args:
            args: Tuple of rule type and regular expressions
        """
        rule_type_str, values = args
        self.__pattern_type = None
        rule_type = getattr(RuleType, rule_type_str.upper(), None)
        if rule_type is None:
            raise ValueError(f'Malformed rule config file. Rule type "{rule_type_str}" is invalid.')
        if rule_type == RuleType.PEM_KEY:
            self.__pattern_type = self.PEM_KEY_PATTERN
        elif len(values) == 1:
            self.__pattern_type = self.SINGLE_PATTERN
        elif len(values) > 1:
            self.__pattern_type = self.MULTI_PATTERN

    @property
    def use_ml(self) -> bool:
        return self.__use_ml

    @use_ml.setter
    def use_ml(self, use_ml: bool) -> None:
        if not isinstance(use_ml, bool):
            raise ValueError('Malformed rule config file. Field "use_ml" should have a boolean value.')
        self.__use_ml = use_ml

    @property
    def validations(self) -> List[Validation]:
        return self.__validations

    @validations.setter
    def validations(self, validation_names: List[str]) -> None:
        """Set api validations to the current rule. All string should be class names from `credsweeper.validations`

        Args:
            validation_names: List of validation names
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
        """Assert that rule_template have all required fields

        Args:
            rule_template: dictionary loaded from the config file

        Raises:
            ValueError if missing fields is present
        """
        required_fields = ["name", "severity", "type", "values", "use_ml"]
        missing_fields = [field for field in required_fields if field not in rule_template]
        if len(missing_fields) > 0:
            raise ValueError(f"Malformed rule config file. Contain rule with missing fields: {missing_fields}.")
