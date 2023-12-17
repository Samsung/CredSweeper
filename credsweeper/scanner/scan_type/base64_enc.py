import contextlib
import logging
from typing import List

from credsweeper.common.constants import RuleType, ASCII
from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.rules import Rule
from credsweeper.scanner.scan_type import PemKeyPattern
from credsweeper.utils import Util

logger = logging.getLogger(__name__)


class Base64Enc(PemKeyPattern):
    """Check if line is a base64 encoded


    Parameters:
        ignore_starts: Leading lines in pem file that should be ignored
        remove_characters: This characters would be striped from PEM lines before entropy check

    """

    @classmethod
    def run(cls, config: Config, rule: Rule, target: AnalysisTarget) -> List[Candidate]:
        """Check if target has a PEM key inside base64

        Args:
            config: user configs
            rule: Rule object to check current line. Should be a pem-pattern rule
            target: Analysis target

        Return:
            List of Candidate objects if pattern defined in a rule is present in a line
            and filters defined in rule do not remove current line. Empty list - otherwise

        """
        assert rule.rule_type == RuleType.BASE64ENC, \
            "Rules provided to Base64Enc.run should have pattern_type equal to BASE64ENC"

        candidates = cls._get_candidates(config, rule, target)
        if not candidates:
            return []
        with contextlib.suppress(Exception):
            text = Util.decode_base64(candidates[0].line_data_list[0].value, padding_safe=True, urlsafe_detect=True)
            lines = text.decode(ASCII).splitlines()
            lines_pos = [x for x in range(len(lines))]
            for line_pos, line in zip(lines_pos, lines):
                if rule.sub_rule.patterns[0].search(line):
                    new_target = AnalysisTarget(line_pos, lines, lines_pos, target.descriptor)
                    if cls.detect_pem_key(config, rule.sub_rule, new_target):
                        # obtained candidates are not used because not match text
                        return candidates
        return []
