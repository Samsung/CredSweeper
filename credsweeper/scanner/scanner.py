import os
from typing import List, Optional, Type

import yaml

from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.logger.logger import logging
from credsweeper.rules import Rule
from credsweeper.scanner.scan_type import MultiPattern, PemKeyPattern, ScanType, SinglePattern


class Scanner:
    """Advanced Credential Scanner base class

    Attributes:
        rules: list of rule objects to check
    """
    def __init__(self, config: Config, rule_path: Optional[str]) -> None:
        self.config = config
        self._set_rules(rule_path)

    def _set_rules(self, rule_path: Optional[str]) -> None:
        self.rules: List[Rule] = []
        if rule_path is None:
            project_dir_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
            rule_path = os.path.join(project_dir_path, "rules", "config.yaml")
        with open(rule_path, "r") as f:
            rule_templates = yaml.load(f, Loader=yaml.Loader)
        for rule_template in rule_templates:
            self.rules.append(Rule(self.config, rule_template))

    def scan(self, targets: List[AnalysisTarget]) -> List[Candidate]:
        """Run scanning of list of target lines from 'targets' with set of rule from 'self.rules'

        Args:
            targets: list of AnalysisTarget, object with data to analyse: line, line number,
                filepath and all lines in file

        Return:
            credentials - list of all detected credential candidates in analysed targets
        """
        credentials = []
        for rule in self.rules:
            for target in targets:
                new_credential = self.get_scanner(rule).run(self.config,
                                                            target.line,
                                                            target.line_num,
                                                            target.file_path,
                                                            rule, target.lines)
                if new_credential:
                    logging.debug(
                        f"Credential for rule: {rule.rule_name} in file: {target.file_path}:{target.line_num} in line: {target.line}"
                    )
                    credentials.append(new_credential)
        return credentials

    @classmethod
    def get_scanner(cls, rule: Rule) -> Type[ScanType]:
        """Choose type of scanner base on rule affiliation
        Args:
            rule: Rule object, rule used to scanning

        Return:
            depending on the rule type, returns the corresponding scanner class
        """
        if rule.pattern_type == Rule.SINGLE_PATTERN:
            return SinglePattern
        elif rule.pattern_type == Rule.MULTI_PATTERN:
            return MultiPattern
        elif rule.pattern_type == Rule.PEM_KEY_PATTERN:
            return PemKeyPattern
        raise ValueError(f"Unknown pattern_type in rule: {rule.pattern_type}")
