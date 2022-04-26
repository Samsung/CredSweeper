import os
from typing import List, Optional, Type, Tuple

import yaml

from credsweeper.common.constants import RuleType, MIN_VARIABLE_LENGTH, MIN_SEPARATOR_LENGTH, MIN_VALUE_LENGTH, \
    MAX_LINE_LENGTH, Separator, DEFAULT_ENCODING
from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.logger.logger import logging
from credsweeper.rules import Rule
from credsweeper.scanner.scan_type import MultiPattern, PemKeyPattern, ScanType, SinglePattern


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

    def __init__(self, config: Config, rule_path: Optional[str]) -> None:
        self.config = config
        self._set_rules(rule_path)
        self.__scanner_for_rule = {rule.rule_name: self.get_scanner(rule) for rule in self.rules}

    def _set_rules(self, rule_path: Optional[str]) -> None:
        self.rules: List[Rule] = []
        if rule_path is None:
            project_dir_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
            rule_path = os.path.join(project_dir_path, "rules", "config.yaml")
        rule_templates = [
            {'name': 'API', 'severity': 'medium', 'type': 'keyword', 'values': ['api'], 'filter_type': 'GeneralKeyword',
             'use_ml': True, 'validations': [], 'required_substrings': ['api']},
            {'name': 'AWS Client ID', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>(ABIA|ACCA|AGPA|AIDA|AIPA|AKIA|ANPA|ANVA|AROA|APKA|ASCA|ASIA)[0-9A-Z]{16})'],
             'filter_type': 'GeneralPattern', 'use_ml': True, 'validations': [], 'required_substrings': ['A'],
             'min_line_len': 20}, {'name': 'AWS Multi', 'severity': 'high', 'type': 'pattern',
                                   'values': ['(?P<value>(AKIA|ASIA)[0-9A-Z]{16})', '(?P<value>[0-9a-zA-Z/+]{40})'],
                                   'filter_type': 'GeneralPattern', 'use_ml': True, 'validations': [],
                                   'required_substrings': ['AKIA', 'ASIA'], 'min_line_len': 20},
            {'name': 'AWS MWS Key', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'],
             'filter_type': 'GeneralPattern', 'use_ml': True, 'validations': [], 'required_substrings': ['amzn'],
             'min_line_len': 30},
            {'name': 'Credential', 'severity': 'medium', 'type': 'keyword', 'values': ['credential'],
             'filter_type': 'GeneralKeyword', 'use_ml': True, 'validations': [], 'required_substrings': ['credential']},
            {'name': 'Dynatrace API Token', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>dt0[a-zA-Z]{1}[0-9]{2}\\.[A-Z0-9]{24}\\.[A-Z0-9]{64})'],
             'filter_type': 'GeneralPattern', 'use_ml': True, 'validations': [], 'required_substrings': ['dt0'],
             'min_line_len': 90}, {'name': 'Facebook Access Token', 'severity': 'high', 'type': 'pattern',
                                   'values': ['(?P<value>EAACEdEose0cBA[0-9A-Za-z]+)'], 'filter_type': 'GeneralPattern',
                                   'use_ml': True, 'validations': [], 'required_substrings': ['EAACEdEose0cBA'],
                                   'min_line_len': 15},
            {'name': 'Github Old Token', 'severity': 'high', 'type': 'pattern', 'values': [
                '(?i)((git)[\\w\\-]*(token|key|api)[\\w\\-]*(\\s)*(=|:|:=)(\\s)*(["\']?)(?P<value>[a-z|\\d]{40})(["\']?))'],
             'filter_type': 'GeneralPattern', 'use_ml': True, 'validations': ['GithubTokenValidation'],
             'required_substrings': ['git'], 'min_line_len': 47},
            {'name': 'Google API Key', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>AIza[0-9A-Za-z\\-_]{35})'], 'filter_type': 'GeneralPattern', 'use_ml': True,
             'validations': ['GoogleApiKeyValidation'], 'required_substrings': ['AIza'], 'min_line_len': 39},
            {'name': 'Google Multi', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>[0-9]+\\-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com)',
                        '(?<![0-9a-zA-Z_-])(?P<value>[0-9a-zA-Z_-]{24})(?![0-9a-zA-Z_-])'],
             'filter_type': 'GeneralPattern', 'use_ml': True, 'validations': [],
             'required_substrings': ['googleusercontent'], 'min_line_len': 40},
            {'name': 'Google OAuth Access Token', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>ya29\\.[0-9A-Za-z\\-_]+)'], 'filter_type': 'GeneralPattern', 'use_ml': True,
             'validations': [], 'required_substrings': ['ya29.'], 'min_line_len': 6},
            {'name': 'Heroku API Key', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>(?i)heroku(.{0,20})?[0-9a-f]{8}(-[0-9a-f]{4})+-[0-9a-f]{12})'],
             'filter_type': 'GeneralPattern', 'use_ml': True, 'validations': [], 'required_substrings': ['heroku'],
             'min_line_len': 24}, {'name': 'Instagram Access Token', 'severity': 'high', 'type': 'pattern',
                                   'values': ['(?P<value>IGQVJ[\\w]{100,})'], 'filter_type': 'GeneralPattern',
                                   'use_ml': True, 'validations': [], 'required_substrings': ['IGQVJ'],
                                   'min_line_len': 105},
            {'name': 'JSON Web Token', 'severity': 'medium', 'type': 'pattern',
             'values': ['(?P<value>eyJ[A-Za-z0-9-_=]+\\.eyJ[A-Za-z0-9-_=]+(\\.[A-Za-z0-9-_.+\\/=]+)?)'],
             'filter_type': 'GeneralPattern', 'use_ml': True, 'validations': [], 'required_substrings': ['.eyJ'],
             'min_line_len': 9}, {'name': 'MailChimp API Key', 'severity': 'high', 'type': 'pattern',
                                  'values': ['(?P<value>[0-9a-f]{32}-us[0-9]{1,2})'], 'filter_type': 'GeneralPattern',
                                  'use_ml': True, 'validations': ['MailChimpKeyValidation'],
                                  'required_substrings': ['-us'], 'min_line_len': 35},
            {'name': 'MailGun API Key', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>key-[0-9a-zA-Z]{32})'], 'filter_type': 'GeneralPattern', 'use_ml': True,
             'validations': [], 'required_substrings': ['key-'], 'min_line_len': 36},
            {'name': 'Password', 'severity': 'medium', 'type': 'keyword', 'values': ['pass|pwd'],
             'filter_type': 'PasswordKeyword', 'use_ml': True, 'validations': [],
             'required_substrings': ['pass', 'pwd']},
            {'name': 'PayPal Braintree Access Token', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32})'],
             'filter_type': 'GeneralPattern', 'use_ml': True, 'validations': [],
             'required_substrings': ['access_token'], 'min_line_len': 72},
            {'name': 'PEM Certificate', 'severity': 'high', 'type': 'pem_key',
             'values': ['(?P<value>-----BEGIN\\s(?!ENCRYPTED|EC).*PRIVATE)'], 'filter_type': 'PEMPattern',
             'use_ml': False, 'validations': []}, {'name': 'Picatic API Key', 'severity': 'high', 'type': 'pattern',
                                                   'values': ['(?P<value>sk_live_[0-9a-z]{32})'],
                                                   'filter_type': 'GeneralPattern', 'use_ml': True, 'validations': [],
                                                   'required_substrings': ['sk_live_'], 'min_line_len': 40},
            {'name': 'Secret', 'severity': 'medium', 'type': 'keyword', 'values': ['secret'],
             'filter_type': 'GeneralKeyword', 'use_ml': True, 'validations': [], 'required_substrings': ['secret']},
            {'name': 'SendGrid API Key', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>SG\\.[\\w_]{16,32}\\.[\\w_]{16,64})'], 'filter_type': 'GeneralPattern',
             'use_ml': True, 'validations': [], 'required_substrings': ['SG.'], 'min_line_len': 34},
            {'name': 'Shopify Token', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>(shpat|shpca|shppa|shpss)_[a-fA-F0-9]{32})'], 'filter_type': 'GeneralPattern',
             'use_ml': True, 'validations': [], 'required_substrings': ['shp'], 'min_line_len': 38},
            {'name': 'Slack Token', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>xox[a|b|p|r|o|s]\\-[-a-zA-Z0-9]{10,250})'], 'filter_type': 'GeneralPattern',
             'use_ml': True, 'validations': ['SlackTokenValidation'], 'required_substrings': ['xox'],
             'min_line_len': 15}, {'name': 'Slack Webhook', 'severity': 'high', 'type': 'pattern',
                                   'values': ['(?P<value>hooks\\.slack\\.com/services/T\\w{8}/B\\w{8}/\\w{24})'],
                                   'filter_type': 'GeneralPattern', 'use_ml': True, 'validations': [],
                                   'required_substrings': ['slack'], 'min_line_len': 61},
            {'name': 'Stripe Standard API Key', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>sk_live_[0-9a-zA-Z]{24})'], 'filter_type': 'GeneralPattern', 'use_ml': True,
             'validations': ['StripeApiKeyValidation'], 'required_substrings': ['sk_live_'], 'min_line_len': 32},
            {'name': 'Stripe Restricted API Key', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>rk_live_[0-9a-zA-Z]{24})'], 'filter_type': 'GeneralPattern', 'use_ml': True,
             'validations': [], 'required_substrings': ['rk_live_'], 'min_line_len': 32},
            {'name': 'Square Access Token', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>EAAA[0-9A-Za-z\\-_]{60})'], 'filter_type': 'GeneralPattern', 'use_ml': True,
             'validations': ['SquareAccessTokenValidation'], 'required_substrings': ['EAAA'], 'min_line_len': 64},
            {'name': 'Square Client ID', 'severity': 'medium', 'type': 'pattern',
             'values': ['(?P<value>sq0[a-z]{3}-[0-9A-Za-z\\-_]{22})'], 'filter_type': 'GeneralPattern', 'use_ml': True,
             'validations': ['SquareClientIdValidation'], 'required_substrings': ['sq0'], 'min_line_len': 29},
            {'name': 'Square OAuth Secret', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>sq0csp-[0-9A-Za-z\\-_]{43})'], 'filter_type': 'GeneralPattern', 'use_ml': True,
             'validations': [], 'required_substrings': ['sq0csp'], 'min_line_len': 50},
            {'name': 'Token', 'severity': 'medium', 'type': 'keyword', 'values': ['token'],
             'filter_type': 'GeneralKeyword', 'use_ml': True, 'validations': [], 'required_substrings': ['token']},
            {'name': 'Twilio API Key', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>SK[0-9a-fA-F]{32})'], 'filter_type': 'GeneralPattern', 'use_ml': True,
             'validations': [], 'required_substrings': ['SK'], 'min_line_len': 34},
            {'name': 'URL Credentials', 'severity': 'high', 'type': 'pattern',
             'values': ['//[^:]+(?P<separator>:)(?P<value>[^@]+)@'], 'filter_type': 'UrlCredentialsGroup',
             'use_ml': True, 'validations': [], 'required_substrings': ['//'], 'min_line_len': 6},
            {'name': 'Auth', 'severity': 'medium', 'type': 'keyword', 'values': ['auth(?!or)'],
             'filter_type': 'GeneralKeyword', 'use_ml': True, 'validations': [], 'required_substrings': ['auth']},
            {'name': 'Key', 'severity': 'medium', 'type': 'keyword', 'values': ['key(?!word)'],
             'filter_type': 'GeneralKeyword', 'use_ml': True, 'validations': [], 'required_substrings': ['key']},
            {'name': 'Telegram Bot API Token', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>[0-9]{10}:AA[\\w\\\\-_-]{33})'], 'filter_type': 'GeneralPattern', 'use_ml': False,
             'validations': [], 'required_substrings': [':AA'], 'min_line_len': 45},
            {'name': 'PyPi API Token', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>pypi-[\\w_\\-]{150,})'], 'filter_type': 'GeneralPattern', 'use_ml': False,
             'validations': [], 'required_substrings': ['pypi'], 'min_line_len': 155},
            {'name': 'Github Token', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>(ghr|gho|ghu|ghs)_[\\w]{36,255})'], 'filter_type': 'GeneralPattern', 'use_ml': False,
             'validations': [], 'required_substrings': ['gh'], 'min_line_len': 40},
            {'name': 'Github Personal Access Token', 'severity': 'high', 'type': 'pattern',
             'values': ['(?P<value>ghp_[\\w]{36,255})'], 'filter_type': 'GeneralPattern', 'use_ml': False,
             'validations': ['GithubTokenValidation'], 'required_substrings': ['ghp_'], 'min_line_len': 40},
            {'name': 'Firebase Domain', 'severity': 'info', 'type': 'pattern',
             'values': ['(?P<value>[a-z0-9.-]+\\.firebaseio\\.com|[a-z0-9.-]+\\.firebaseapp\\.com)'],
             'filter_type': 'GeneralPattern', 'use_ml': False, 'validations': [], 'required_substrings': ['firebase'],
             'min_line_len': 16}, {'name': 'AWS S3 Bucket', 'severity': 'info', 'type': 'pattern', 'values': [
                '(?P<value>[a-z0-9.-]+\\.s3\\.amazonaws\\.com|[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn))'],
                                   'filter_type': 'GeneralPattern', 'use_ml': False, 'validations': [],
                                   'required_substrings': ['s3-website', 'amazonaws'], 'min_line_len': 14},
            {'name': 'Nonce', 'severity': 'medium', 'type': 'keyword', 'values': ['nonce'],
             'filter_type': 'GeneralKeyword', 'use_ml': True, 'validations': [], 'required_substrings': ['nonce']},
            {'name': 'Salt', 'severity': 'medium', 'type': 'keyword', 'values': ['salt'],
             'filter_type': 'GeneralKeyword', 'use_ml': True, 'validations': [], 'required_substrings': ['salt']},
            {'name': 'Certificate', 'severity': 'medium', 'type': 'keyword', 'values': ['cert'],
             'filter_type': 'GeneralKeyword', 'use_ml': True, 'validations': [], 'required_substrings': ['cert']}]

        for rule_template in rule_templates:
            self.rules.append(Rule(self.config, rule_template))
        self.min_pattern_len = 999
        for rule in self.rules:
            if rule.rule_type == RuleType.PATTERN:
                self.min_pattern_len = min(self.min_pattern_len, rule.min_line_len)
        self.min_keyword_len = MIN_VARIABLE_LENGTH + MIN_SEPARATOR_LENGTH + MIN_VALUE_LENGTH
        self.min_len = min(self.min_keyword_len, self.min_pattern_len)

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
            if len(target.line) > MAX_LINE_LENGTH:
                continue
            # Trim string from outer spaces to make future `a in str` checks faster
            target_line_trimmed = target.line.strip()
            target_line_trimmed_len = len(target_line_trimmed)
            # Ignore target if trimmed part is too short
            if target_line_trimmed_len < self.min_len:
                continue
            target_line_trimmed_lower = target_line_trimmed.lower()
            # Check if have at least one separator character. Otherwise cannot be matched by a keyword
            if any(x in target_line_trimmed for x in Separator.common_as_set):
                keyword_targets.append((target, target_line_trimmed_lower, target_line_trimmed_len))
            # Check if have length not smaller than smallest `min_line_len` in all pattern rules
            if target_line_trimmed_len >= self.min_pattern_len:
                pattern_targets.append((target, target_line_trimmed_lower, target_line_trimmed_len))
            # Check if have "BEGIN" substring. Cannot otherwise ba matched as a PEM key
            if "BEGIN" in target_line_trimmed:
                pem_targets.append((target, target_line_trimmed_lower, target_line_trimmed_len))

        return keyword_targets, pattern_targets, pem_targets

    def scan(self, targets: List[AnalysisTarget]) -> List[Candidate]:
        """Run scanning of list of target lines from 'targets' with set of rule from 'self.rules'.

        Args:
            targets: objects with data to analyse: line, line number,
              filepath and all lines in file

        Return:
            list of all detected credential candidates in analysed targets

        """
        credentials = []
        keyword_targets, pattern_targets, pem_targets = self._select_and_group_targets(targets)
        for rule in self.rules:
            min_line_len = rule.min_line_len
            required_substrings = rule.required_substrings
            scanner = self.__scanner_for_rule[rule.rule_name]
            to_check = self.get_targets_to_check(keyword_targets, pattern_targets, pem_targets, rule)
            # It is almost two times faster to precompute values related to target_line than to compute them in
            # each iteration
            for target, target_line_trimmed_lower, target_line_trimmed_len in to_check:
                if target_line_trimmed_len < min_line_len:
                    continue
                if not any(substring in target_line_trimmed_lower for substring in required_substrings):
                    continue
                new_credential = scanner.run(self.config, target.line, target.line_num, target.file_path, rule,
                                             target.lines)
                if new_credential:
                    logging.debug(f"Credential for rule: {rule.rule_name}"
                                  f" in file: {target.file_path}:{target.line_num} in line: {target.line}")
                    credentials.append(new_credential)
        return credentials

    @classmethod
    def get_scanner(cls, rule: Rule) -> Type[ScanType]:
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
