import logging
from pathlib import Path
from typing import List, Optional, Type, Tuple, Dict, Union

from credsweeper.app import APP_PATH
from credsweeper.common.constants import RuleType, MIN_VARIABLE_LENGTH, MIN_SEPARATOR_LENGTH, MIN_VALUE_LENGTH, \
    MAX_LINE_LENGTH, Separator
from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
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

    def __init__(self, config: Config, rule_path: Optional[str], usage_list: Optional[List[str]] = None) -> None:
        self.config = config
        self.__scanner_for_rule: Dict[str, Type[ScanType]] = {}
        self.rules: List[Rule] = []
        # init with MAX_LINE_LENGTH before _set_rules
        self.min_keyword_len = MAX_LINE_LENGTH
        self.min_pattern_len = MAX_LINE_LENGTH
        self.min_pem_key_len = MAX_LINE_LENGTH
        self._set_rules(rule_path, usage_list if isinstance(usage_list, list) else ["src", "doc"])
        self.min_len = min(self.min_pattern_len, self.min_keyword_len, self.min_pem_key_len,
                           MIN_VARIABLE_LENGTH + MIN_SEPARATOR_LENGTH + MIN_VALUE_LENGTH)

    def _set_rules(self, rule_path: Union[None, str, Path], usage_list: List[str]) -> None:
        """Auxiliary method to fill rules, determine min_pattern_len and set scanners"""
        if rule_path is None:
            rule_path = APP_PATH / "rules" / "config.yaml"
        rule_templates = Util.yaml_load(rule_path)
        if rule_templates and isinstance(rule_templates, list):
            for rule_template in rule_templates:
                rule = Rule(self.config, rule_template)
                if not self._is_available(usage_list, rule):
                    continue
                self.rules.append(rule)
                if 0 < rule.min_line_len:
                    if rule.rule_type == RuleType.KEYWORD:
                        self.min_keyword_len = min(self.min_keyword_len, rule.min_line_len)
                    elif rule.rule_type == RuleType.PATTERN:
                        self.min_pattern_len = min(self.min_pattern_len, rule.min_line_len)
                    elif rule.rule_type == RuleType.PEM_KEY:
                        self.min_pem_key_len = min(self.min_pem_key_len, rule.min_line_len)
                    else:
                        logger.warning(f"Unknown rule type:{rule.rule_type}")
                self.__scanner_for_rule[rule.rule_name] = self.get_scanner(rule)
        else:
            raise RuntimeError(f"Wrong rules '{rule_templates}' were read from '{rule_path}'")

    def _select_and_group_targets(self, targets: List[AnalysisTarget]) -> Tuple[TargetGroup, TargetGroup, TargetGroup]:
        """Group targets into 3 lists based on loaded rules.

        Args:
            targets: List of AnalysisTarget to analyze

        Return:
            Three TargetGroup objects: one for keywords, one for patterns, and one for PEM keys

        """
        keyword_targets = []
        pattern_targets = []
        pem_targets = []

        for target in targets:
            # Ignore target if it's too long
            if target.line_len > MAX_LINE_LENGTH:
                logger.warning(f"Skipped oversize({target.line_len}) line in {target.file_path}:{target.line_num}", )
                continue
            # Trim string from outer spaces to make future `a in str` checks faster
            target_line_trimmed = target.line.strip()
            target_line_trimmed_len = len(target_line_trimmed)
            # Ignore target if trimmed part is too short
            if target_line_trimmed_len < self.min_len:
                continue
            target_line_trimmed_lower = target_line_trimmed.lower()
            # check minimal length for keyword rule
            if target_line_trimmed_len >= self.min_keyword_len:
                # Check if have at least one separator character. Otherwise cannot be matched by a keyword
                for x in Separator.common_as_set:
                    if x in target_line_trimmed:
                        keyword_targets.append((target, target_line_trimmed_lower, target_line_trimmed_len))
                        break
            # Check if have length not smaller than smallest `min_line_len` in all pattern rules
            if target_line_trimmed_len >= self.min_pattern_len:
                pattern_targets.append((target, target_line_trimmed_lower, target_line_trimmed_len))
            # Check if have "BEGIN" substring. Cannot otherwise ba matched as a PEM key
            if target_line_trimmed_len >= self.min_pem_key_len and "BEGIN" in target_line_trimmed:
                pem_targets.append((target, target_line_trimmed_lower, target_line_trimmed_len))

        return keyword_targets, pattern_targets, pem_targets

    def _is_available(self, usage_list: List[str], rule: Rule) -> bool:
        """separate the method to reduce complexity"""
        if rule.severity < self.config.severity:
            return False
        for usage in usage_list:
            if usage in rule.usage_list:
                return True
        return False

    @staticmethod
    def _required_substrings_not_present(required_substrings: List[str], line: str):
        """ returns True if required substring absent in line """
        for substring in required_substrings:
            if substring in line:
                return False
        return True

    def scan(self, targets: List[AnalysisTarget]) -> List[Candidate]:
        """Run scanning of list of target lines from 'targets' with set of rule from 'self.rules'.

        Args:
            targets: objects with data to analyze: line, line number,
              filepath and all lines in file

        Return:
            list of all detected credential candidates in analyzed targets

        """
        credentials: List[Candidate] = []
        if not targets:
            # optimization for empty list
            return credentials
        keyword_targets, pattern_targets, pem_targets = self._select_and_group_targets(targets)
        for rule in self.rules:
            min_line_len = rule.min_line_len
            required_substrings = rule.required_substrings
            scanner = self.__scanner_for_rule[rule.rule_name]
            to_check = self.get_targets_to_check(keyword_targets, pattern_targets, pem_targets, rule)
            # It is almost two times faster to pre-compute values related to target_line than to compute them in
            # each iteration
            for target, target_line_trimmed_lower, target_line_trimmed_len in to_check:
                if target_line_trimmed_len < min_line_len or required_substrings \
                        and self._required_substrings_not_present(required_substrings, target_line_trimmed_lower):
                    continue
                if new_credential := scanner.run(self.config, rule, target):
                    logger.debug("Credential for rule: %s in file: %s:%d in line: %s", rule.rule_name, target.file_path,
                                 target.line_num, target.line)
                    credentials.append(new_credential)
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

    @staticmethod
    def get_targets_to_check(keyword_targets: TargetGroup, pattern_targets: TargetGroup, pem_targets: TargetGroup,
                             rule: Rule) -> TargetGroup:
        """Choose target subset based on a rule.

        Args:
            keyword_targets: TargetGroup with targets relevant to a keyword based rules
            pattern_targets: TargetGroup with targets relevant to a pattern based rules
            pem_targets: TargetGroup with targets relevant to a pem key rules
            rule: rule object used to scanning

        Return:
            depending on the rule type, returns one of the other arguments

        """
        if rule.rule_type == RuleType.KEYWORD:
            return keyword_targets
        elif rule.rule_type == RuleType.PATTERN:
            return pattern_targets
        elif rule.rule_type == RuleType.PEM_KEY:
            return pem_targets
        else:
            raise ValueError(f"Unknown RuleType {rule.rule_type}")
