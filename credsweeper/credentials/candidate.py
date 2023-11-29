import copy
import re
from json.encoder import py_encode_basestring_ascii
from typing import Any, Dict, List, Optional

from credsweeper.common.constants import KeyValidationOption, Severity
from credsweeper.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.validations.validation import Validation


class Candidate:
    """Candidates that can be credentials.

    Class contains list of LineData, some attributes from Rule object, and config

    Parameters:
        line_data_list: List of LineData
        patterns: Regular expressions that can be used for detection
        rule_name: Name of Rule
        severity: critical/high/medium/low
        config: user configs
        validations: List of Validation objects that can check this credential using external API
        use_ml: Should ML work on this credential or not. If not prediction based on regular expression and filter only
    """

    def __init__(self,
                 line_data_list: List[LineData],
                 patterns: List[re.Pattern],
                 rule_name: str,
                 severity: Severity,
                 config: Config,
                 validations: List[Validation] = None,
                 use_ml: bool = False) -> None:
        self.line_data_list = line_data_list
        self.patterns = patterns
        self.rule_name = rule_name
        self.severity = severity
        self.config = config
        self.validations: List[Validation] = validations if validations is not None else []
        self.use_ml = use_ml

        self.api_validation = KeyValidationOption.NOT_AVAILABLE
        self.ml_validation = KeyValidationOption.NOT_AVAILABLE
        self.ml_probability: Optional[bool] = None

    @staticmethod
    def _encode(value: Any) -> Any:
        """Encode value to the base string ascii

        Args:
            value: Any type of value to be encoded
        """
        if isinstance(value, str):
            return py_encode_basestring_ascii(value)
        else:
            return value

    def is_api_validation_available(self) -> bool:
        """Check if current credential candidate can be validated with external API.

        Return:
            True if any validation available, False otherwise

        """
        return len(self.validations) > 0

    def __str__(self) -> str:
        return f"rule: {self.rule_name} / severity: {self.severity.value} / line_data_list: {self.line_data_list} " \
               f"/ api_validation: {self.api_validation.name} / ml_validation: {self.ml_validation.name}"

    def to_json(self) -> Dict:
        """Convert credential candidate object to dictionary.

        Return:
            Dictionary object generated from current credential candidate

        """
        full_output = {
            "api_validation": self.api_validation.name,
            "ml_validation": self.ml_validation.name,
            "patterns": [pattern.pattern for pattern in self.patterns],
            "ml_probability": self.ml_probability,
            "rule": self.rule_name,
            "severity": self.severity.value,
            "use_ml": self.use_ml,
            # put the array to end to make json more readable
            "line_data_list": [line_data.to_json() for line_data in self.line_data_list],
        }
        if self.config is not None:
            reported_output = {k: v for k, v in full_output.items() if k in self.config.candidate_output}
        else:
            reported_output = full_output
        return reported_output

    def to_dict_list(self) -> List[dict]:
        """Convert credential candidate object to List[dict].

        Return:
            List[dict] object generated from current credential candidate

        """
        reported_output = []
        json_output = self.to_json()
        refined_data = copy.deepcopy(json_output)
        del refined_data["line_data_list"]
        for line_data in json_output["line_data_list"]:
            line_data.update(refined_data)
            for key in line_data.keys():
                line_data[key] = self._encode(line_data[key])
            reported_output.append(line_data)
        return reported_output

    @classmethod
    def get_dummy_candidate(cls, config: Config, file_path: str, file_type: str, info: str):
        """Create dummy instance to use in searching file by extension"""
        return cls(  #
            line_data_list=[LineData(config, "dummy line", -1, 0, file_path, file_type, info, re.compile(".*"))],
            patterns=[re.compile(".*")],  #
            rule_name="Dummy candidate",  #
            severity=Severity.INFO,  #
            config=config)
