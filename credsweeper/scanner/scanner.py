import logging
import re
from pathlib import Path
from typing import List, Type, Tuple, Union, Dict, Generator

from credsweeper.app import APP_PATH
from credsweeper.common.constants import RuleType, MIN_VARIABLE_LENGTH, MIN_SEPARATOR_LENGTH, MIN_VALUE_LENGTH, \
    MAX_LINE_LENGTH, PEM_BEGIN_PATTERN
from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.rules import Rule
from credsweeper.scanner.scan_type import MultiPattern, PemKeyPattern, ScanType, SinglePattern
from credsweeper.utils import Util

logger = logging.getLogger(__name__)


class Scanner:
    """Advanced Credential Scanner base class.

    Parameters:
        rules: list of rule objects to check
        min_pattern_len: minimal length specified in all pattern rules
        min_keyword_len: minimal possible length for a string to be matched by any keyword rule
        min_len: Smallest between min_pattern_len and min_keyword_len
        TargetGroup: Type for List[Tuple[AnalysisTarget, str, int]]

    """

    TargetGroup = List[Tuple[AnalysisTarget, str, int]]

    def __init__(self, config: Config, rule_path: Union[None, str, Path]) -> None:
        self.config = config
        # init with MAX_LINE_LENGTH before _set_rules
        self.min_keyword_len = MAX_LINE_LENGTH
        self.min_pattern_len = MAX_LINE_LENGTH
        self.min_pem_key_len = MAX_LINE_LENGTH
        self.rules_scanners: List[Tuple[Rule, Type[ScanType]]] = []
        self._set_rules_scanners(rule_path)
        self.min_len = min(self.min_pattern_len, self.min_keyword_len, self.min_pem_key_len,
                           MIN_VARIABLE_LENGTH + MIN_SEPARATOR_LENGTH + MIN_VALUE_LENGTH)

    def _set_rules_scanners(self, rule_path: Union[None, str, Path]) -> None:
        """Auxiliary method to fill rules, determine min_pattern_len and set scanners"""
        if rule_path is None:
            rule_path = APP_PATH / "rules" / "config.yaml"
        rule_templates = Util.yaml_load(rule_path)
        if rule_templates and isinstance(rule_templates, list):
            for rule_template in rule_templates:
                rule = Rule(self.config, rule_template)
                if not self._is_available(rule):
                    continue
                if 0 < rule.min_line_len:
                    if rule.rule_type == RuleType.KEYWORD:
                        self.min_keyword_len = min(self.min_keyword_len, rule.min_line_len)
                    elif rule.rule_type == RuleType.PATTERN:
                        self.min_pattern_len = min(self.min_pattern_len, rule.min_line_len)
                    elif rule.rule_type == RuleType.PEM_KEY:
                        self.min_pem_key_len = min(self.min_pem_key_len, rule.min_line_len)
                    else:
                        logger.warning(f"Unknown rule type:{rule.rule_type}")
                self.rules_scanners.append((rule, self.get_scanner(rule)))
        else:
            raise RuntimeError(f"Wrong rules '{rule_templates}' were read from '{rule_path}'")

    def _is_available(self, rule: Rule) -> bool:
        """separate the method to reduce complexity"""
        if rule.severity < self.config.severity:
            return False
        if self.config.doc:
            # apply only available for doc scanning rules
            if rule.doc_available:
                return True
        else:
            return True
        return False

    def yield_rule_scanner(
            self,  #
            line_len: int,  #
            matched_pattern: bool,  #
            matched_keyword: bool,  #
            matched_pem_key: bool) -> Generator[Tuple[Rule, Type[ScanType]], None, None]:
        """returns generator for rules and according scanner"""
        for rule, scanner in self.rules_scanners:
            if line_len >= rule.min_line_len \
                    and (RuleType.PATTERN == rule.rule_type and matched_pattern
                         or RuleType.KEYWORD == rule.rule_type and matched_keyword
                         or RuleType.PEM_KEY == rule.rule_type and matched_pem_key):
                yield rule, scanner

    @staticmethod
    def _required_substrings_not_present(required_substrings: List[str], line: str) -> bool:
        """ returns True if required substring absent in line """
        for substring in required_substrings:
            if substring in line:
                return False
        return True

    @staticmethod
    def _required_regex_not_matched(required_regex: re.Pattern, line: str) -> bool:
        """ returns True if line does not matched required_regex """
        if required_regex.match(line):
            return False
        return True

    def scan(self, provider: ContentProvider) -> List[Candidate]:
        """Run scanning of list of target lines from 'targets' with set of rule from 'self.rules'.

        Args:
            provider: objects with data to analyze: line, line number,
              filepath and all lines in file

        Return:
            list of all detected credential candidates in analyzed targets

        """
        credentials: List[Candidate] = []

        for target in provider.yield_analysis_target(self.min_len):
            # Trim string from outer spaces to make future `x in str` checks faster
            target_line_stripped = target.line_strip
            target_line_stripped_len = len(target_line_stripped)

            # "cache" - YAPF and pycharm formatters ...
            matched_keyword = \
                target_line_stripped_len >= self.min_keyword_len and (  #
                        '=' in target_line_stripped or ':' in target_line_stripped)  #
            matched_pem_key = \
                target_line_stripped_len >= self.min_pem_key_len \
                and PEM_BEGIN_PATTERN in target_line_stripped and "PRIVATE" in target_line_stripped
            matched_pattern = target_line_stripped_len >= self.min_pattern_len

            if not (matched_keyword or matched_pem_key or matched_pattern):
                continue

            # use lower case for required substring
            target_line_stripped_lower = target_line_stripped.lower()
            # cached value to skip the same regex verifying
            matched_regex: Dict[re.Pattern, bool] = {}

            for rule, scanner in self.yield_rule_scanner(target_line_stripped_len, matched_pattern, matched_keyword,
                                                         matched_pem_key):
                for substring in rule.required_substrings:
                    if substring in target_line_stripped_lower:
                        break
                else:
                    if rule.has_required_substrings:
                        continue

                # common regex might be triggered for the same target
                if rule.required_regex:
                    if rule.required_regex in matched_regex:
                        regex_result = matched_regex[rule.required_regex]
                    else:
                        regex_result = bool(rule.required_regex.search(target_line_stripped))
                        matched_regex[rule.required_regex] = regex_result
                    if not regex_result:
                        continue

                if new_credential := scanner.run(self.config, rule, target):
                    credentials.append(new_credential)
                    logger.debug("Credential for rule: %s in file: %s:%d in line: %s", rule.rule_name, target.file_path,
                                 target.line_num, target.line)
        return credentials

    @staticmethod
    def get_scanner(rule: Rule) -> Type[ScanType]:
        """Choose type of scanner base on rule affiliation.

        Args:
            rule: rule object used to scanning

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
