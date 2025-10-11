import logging
import re
from pathlib import Path
from typing import List, Type, Tuple, Union, Dict, Generator, Set

from credsweeper.app import APP_PATH
from credsweeper.common.constants import RuleType, MIN_VARIABLE_LENGTH, MIN_SEPARATOR_LENGTH, MIN_VALUE_LENGTH, \
    MAX_LINE_LENGTH, PEM_BEGIN_PATTERN
from credsweeper.config.config import Config
from credsweeper.credentials.candidate import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.rules.rule import Rule
from credsweeper.scanner.scan_type.multi_pattern import MultiPattern
from credsweeper.scanner.scan_type.pem_key_pattern import PemKeyPattern
from credsweeper.scanner.scan_type.scan_type import ScanType
from credsweeper.scanner.scan_type.single_pattern import SinglePattern
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)

RULES_PATH = APP_PATH / "rules" / "config.yaml"


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
        self.min_multi_len = MAX_LINE_LENGTH
        self.rules_scanners: List[Tuple[Rule, Type[ScanType]]] = []
        self._set_rules_scanners(rule_path)
        self.min_len = min(self.min_pattern_len, self.min_keyword_len, self.min_pem_key_len, self.min_multi_len,
                           MIN_VARIABLE_LENGTH + MIN_SEPARATOR_LENGTH + MIN_VALUE_LENGTH)
        self.__keyword_rules_required_substrings = self._get_required_substrings(RuleType.KEYWORD)

    def keywords_required_substrings_check(self, text: str) -> bool:
        """check whether `text` has any required substring for all keyword type rules"""
        return self._substring_check(self.__keyword_rules_required_substrings, text)

    def _get_required_substrings(self, rule_type: RuleType) -> Set[str]:
        """init set of required substrings for custom rule type"""
        required_substrings: Set[str] = set()
        for rule in (x[0] for x in self.rules_scanners if rule_type == x[0].rule_type):
            required_substrings.update(set(rule.required_substrings))
        return required_substrings

    @staticmethod
    def _substring_check(substrings: Set[str], text: str) -> bool:
        """checks whether `text` has any required substring. Set is used to reduce extra transformations"""
        for substring in substrings:
            if substring in text:
                return True
        return False

    def _set_rules_scanners(self, rules_path: Union[None, str, Path]) -> None:
        """Auxiliary method to fill rules, determine min_pattern_len and set scanners"""
        if rules_path is None:
            rules_path = RULES_PATH
        rule_templates = Util.yaml_load(rules_path)
        if rule_templates and isinstance(rule_templates, list):
            rule_names = set()
            for rule_template in rule_templates:
                try:
                    rule = Rule(self.config, rule_template)
                except Exception as exc:
                    logger.error("Rule creation error%s", str(rule_template))
                    raise exc
                if not self._is_available(rule):
                    continue
                if rule.rule_name in rule_names:
                    raise RuntimeError(f"Duplicated rule name {rule.rule_name}")
                else:
                    rule_names.add(rule.rule_name)
                if 0 < rule.min_line_len:
                    if rule.rule_type == RuleType.KEYWORD:
                        self.min_keyword_len = min(self.min_keyword_len, rule.min_line_len)
                    elif rule.rule_type == RuleType.PATTERN:
                        self.min_pattern_len = min(self.min_pattern_len, rule.min_line_len)
                    elif rule.rule_type == RuleType.PEM_KEY:
                        self.min_pem_key_len = min(self.min_pem_key_len, rule.min_line_len)
                    elif rule.rule_type == RuleType.MULTI:
                        self.min_multi_len = min(self.min_multi_len, rule.min_line_len)
                    else:
                        logger.warning(f"Unknown rule type:{rule.rule_type}")
                self.rules_scanners.append((rule, self.get_scanner(rule)))
        else:
            raise RuntimeError(f"Wrong rules '{rule_templates}' were read from '{rules_path}'")

    def _is_available(self, rule: Rule) -> bool:
        """separate the method to reduce complexity"""
        if rule.severity < self.config.severity:
            return False
        if self.config.doc:
            if "doc" in rule.target:
                return True
        else:
            if "code" in rule.target:
                return True
        return False

    def yield_rule_scanner(
            self,  #
            line_len: int,  #
            matched_pattern: bool,  #
            matched_keyword: bool,  #
            matched_pem_key: bool,  #
            matched_multi: bool) -> Generator[Tuple[Rule, Type[ScanType]], None, None]:
        """returns generator for rules and according scanner"""
        for rule, scanner in self.rules_scanners:
            if line_len >= rule.min_line_len \
                    and (RuleType.PATTERN == rule.rule_type and matched_pattern
                         or RuleType.KEYWORD == rule.rule_type and matched_keyword
                         or RuleType.PEM_KEY == rule.rule_type and matched_pem_key
                         or RuleType.MULTI == rule.rule_type and matched_multi):
                yield rule, scanner

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
            target_line_stripped_len = target.line_strip_len
            # use lower case for required substring
            target_line_stripped_lower = target.line_lower_strip

            # "cache" - YAPF and pycharm formatters ...
            matched_keyword = \
                target_line_stripped_len >= self.min_keyword_len and (  #
                        '=' in target_line_stripped
                        or ':' in target_line_stripped
                        or ("define" in target_line_stripped
                            and ('(' in target_line_stripped and ',' in target_line_stripped
                                 or "#define" in target_line_stripped
                                 or "%define" in target_line_stripped)
                            )
                        or "%global" in target_line_stripped
                        or "set" in target_line_stripped_lower
                        or "%3d" in target_line_stripped_lower
                )  #
            matched_pem_key = \
                target_line_stripped_len >= self.min_pem_key_len \
                and PEM_BEGIN_PATTERN in target_line_stripped and "PRIVATE" in target_line_stripped
            matched_pattern = target_line_stripped_len >= self.min_pattern_len
            matched_multi = target_line_stripped_len >= self.min_multi_len

            if not (matched_keyword or matched_pem_key or matched_pattern or matched_multi):
                # target may be skipped only with length because not all rules have required_substrings
                logger.debug("Skip too short (%d) line %s:%d", target_line_stripped_len, target.file_path,
                             target.line_num)
                continue

            # cached value to skip the same regex verifying
            matched_regex: Dict[re.Pattern, bool] = {}

            for rule, scanner in self.yield_rule_scanner(target_line_stripped_len, matched_pattern, matched_keyword,
                                                         matched_pem_key, matched_multi):
                if rule.has_required_substrings \
                        and not self._substring_check(rule.required_substrings, target_line_stripped_lower):
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

                if new_credentials := scanner.run(self.config, rule, target):
                    credentials.extend(new_credentials)
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
        if RuleType.PATTERN == rule.rule_type or RuleType.KEYWORD == rule.rule_type:
            return SinglePattern
        elif RuleType.MULTI == rule.rule_type:
            return MultiPattern
        elif RuleType.PEM_KEY == rule.rule_type:
            return PemKeyPattern
        raise ValueError(f"Unknown pattern_type in rule: {rule.rule_type}")
