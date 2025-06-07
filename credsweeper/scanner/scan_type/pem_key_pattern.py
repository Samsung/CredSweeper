import logging
from typing import List

from credsweeper.common.constants import RuleType
from credsweeper.config.config import Config
from credsweeper.credentials.candidate import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.rules.rule import Rule
from credsweeper.scanner.scan_type.scan_type import ScanType
from credsweeper.utils.pem_key_detector import PemKeyDetector

logger = logging.getLogger(__name__)


class PemKeyPattern(ScanType):
    """Scanner detects single PEM private key in target from current line"""

    @classmethod
    def run(cls, config: Config, rule: Rule, target: AnalysisTarget) -> List[Candidate]:
        """Check if target is a PEM key

        Args:
            config: user configs
            rule: Rule object to check current line. Should be a pem-pattern rule
            target: Analysis target

        Return:
            List of Candidate objects if pattern defined in a rule is present in a line
            and filters defined in rule do not remove current line. Empty list - otherwise

        """
        assert rule.rule_type == RuleType.PEM_KEY, \
            "Rules provided to PemKeyPattern.run should have pattern_type equal to PEM_KEY_PATTERN"
        if candidates := cls._get_candidates(config, rule, target):
            candidate = candidates[0]
            if pem_lines := PemKeyDetector.detect_pem_key(config, target):
                candidate.line_data_list = pem_lines
                return [candidate]

        return []
