from typing import List, Optional

from regex import regex

from credsweeper.common.constants import KeyValidationOption, Severity
from credsweeper.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.validations.validation import Validation


class Candidate:

    def __init__(self,
                 line_data_list: List[LineData],
                 patterns: List[regex.Pattern],
                 rule_name: str,
                 severity: Severity,
                 config: Config,
                 validations: List[Validation] = None,
                 use_ml: bool = False) -> None:
        self.api_validation = KeyValidationOption.NOT_AVAILABLE
        self.ml_validation = KeyValidationOption.NOT_AVAILABLE
        self.line_data_list: List[LineData] = line_data_list if line_data_list else []
        self.patterns: List[regex.Pattern] = patterns if patterns else []
        self.ml_probability = None
        self.rule_name: str = rule_name
        self.severity: Optional[Severity] = severity
        self.validations: List[Validation] = validations if validations else []
        self.use_ml: bool = use_ml
        self.config = config

    @property
    def api_validation(self) -> KeyValidationOption:
        return self.__api_validation

    @api_validation.setter
    def api_validation(self, validation: KeyValidationOption) -> None:
        self.__api_validation = validation

    @property
    def ml_validation(self) -> KeyValidationOption:
        return self.__ml_validation

    @ml_validation.setter
    def ml_validation(self, validation: KeyValidationOption) -> None:
        self.__ml_validation = validation

    @property
    def line_data_list(self) -> List[LineData]:
        return self.__line_data_list

    @line_data_list.setter
    def line_data_list(self, line_data_list: List[LineData]) -> None:
        self.__line_data_list = line_data_list

    @property
    def patterns(self) -> List[regex.Pattern]:
        return self.__patterns

    @patterns.setter
    def patterns(self, patterns: List[regex.Pattern]) -> None:
        self.__patterns = patterns

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
    def severity(self, severity: Severity) -> None:
        self.__severity = severity

    def add_line_data(self, line_data: LineData) -> None:
        """Add new line data to the current credential.

        Args:
            line_data: Line data object to be added

        """
        self.line_data_list.append(line_data)

    def is_api_validation_available(self) -> bool:
        """Check if current credential candidate can be validated with external API.

        Return:
            True if any validation available, False otherwise

        """
        return len(self.validations) > 0

    def __str__(self) -> str:
        return f"rule: {self.rule_name} / severity: {self.severity.value} / line_data_list: {self.line_data_list} " \
               f"/ api_validation: {self.api_validation.name} / ml_validation: {self.ml_validation.name}"

    def to_json(self) -> dict:
        """Convert credential candidate object to dictionary.

        Return:
            Dictionary object generated from current credential candidate

        """
        full_output = {
            "api_validation": self.api_validation.name,
            "ml_validation": self.ml_validation.name,
            "line_data_list": [line_data.to_json() for line_data in self.line_data_list],
            "patterns": [s.pattern for s in self.patterns],
            "ml_probability": self.ml_probability,
            "rule": self.rule_name,
            "severity": self.severity.value,
            "use_ml": self.use_ml,
        }
        if self.config is not None:
            reported_output = {k: v for k, v in full_output.items() if k in self.config.candidate_output}
        else:
            reported_output = full_output
        return reported_output

    @classmethod
    def get_dummy_candidate(cls, config: Config, file_path: str):
        """Create dummy instance to use in searching file by extension"""
        return cls(  #
            line_data_list=[  #
                LineData(  #
                    config,  #
                    line="dummy line",  #
                    line_num=-1,  #
                    path=file_path,  #
                    pattern=regex.compile(".*"))
            ],
            patterns=[regex.compile(".*")],  #
            rule_name="Dummy candidate",  #
            severity=Severity.INFO,  #
            config=config)
