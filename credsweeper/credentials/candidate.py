import copy
import re
from json.encoder import py_encode_basestring_ascii
from typing import Any, Dict, List, Optional

from credsweeper.common.constants import KeyValidationOption, Severity, Confidence
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
        confidence: strong/moderate/weak
        config: user configs
        validations: List of Validation objects that can check this credential using external API
        use_ml: Should ML work on this credential or not. If not prediction based on regular expression and filter only
    """

    def __init__(self,
                 line_data_list: List[LineData],
                 patterns: List[re.Pattern],
                 rule_name: str,
                 severity: Severity,
                 config: Optional[Config] = None,
                 validations: List[Validation] = None,
                 use_ml: bool = False,
                 confidence: Confidence = Confidence.MODERATE) -> None:
        self.line_data_list = line_data_list
        self.patterns = patterns
        self.rule_name = rule_name
        self.severity = severity
        self.config = config
        self.validations: List[Validation] = validations if validations is not None else []
        self.use_ml = use_ml
        self.confidence = confidence

        self.api_validation = KeyValidationOption.NOT_AVAILABLE
        self.ml_validation = KeyValidationOption.NOT_AVAILABLE
        self.ml_probability: Optional[float] = None

    def compare(self, other: 'Candidate') -> bool:
        """Comparison method - checks only result of final cred"""
        if self.rule_name == other.rule_name \
                and self.severity == other.severity \
                and self.confidence == other.confidence \
                and self.api_validation == other.api_validation \
                and self.use_ml == other.use_ml \
                and self.ml_validation == other.ml_validation \
                and self.ml_probability == other.ml_probability \
                and len(self.line_data_list) == len(other.line_data_list):
            for i, j in zip(self.line_data_list, other.line_data_list):
                if i.compare(j):
                    continue
                else:
                    break
            else:
                # all line_data are equal
                return True
        return False

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

    def to_str(self, subtext: bool = False, hashed: bool = False) -> str:
        """Represent candidate with subtext or|and hashed values"""
        return f"rule: {self.rule_name}" \
               f" | severity: {self.severity.value}" \
               f" | confidence: {self.confidence.value}" \
               f" | line_data_list: [{', '.join([x.to_str(subtext, hashed) for x in self.line_data_list])}]" \
               f" | api_validation: {self.api_validation.name}" \
               f" | ml_validation: {self.ml_validation.name}"

    def __str__(self):
        return self.to_str()

    def __repr__(self):
        return self.to_str(subtext=True)

    def to_json(self, hashed: bool, subtext: bool) -> Dict:
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
            "confidence": self.confidence.value,
            "use_ml": self.use_ml,
            # put the array to end to make json more readable
            "line_data_list": [line_data.to_json(hashed, subtext) for line_data in self.line_data_list],
        }
        if self.config is not None:
            reported_output = {k: v for k, v in full_output.items() if k in self.config.candidate_output}
        else:
            reported_output = full_output
        return reported_output

    def to_dict_list(self, hashed: bool, subtext: bool) -> List[dict]:
        """Convert credential candidate object to List[dict].

        Return:
            List[dict] object generated from current credential candidate

        """
        reported_output = []
        json_output = self.to_json(hashed, subtext)
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
            line_data_list=[LineData(config, "dummy line", -1, 0, file_path, file_type, info, re.compile(r".*"))],
            patterns=[re.compile(r".*")],  #
            rule_name="Dummy candidate",  #
            severity=Severity.INFO,  #
            config=config,  #
            confidence=Confidence.MODERATE)
