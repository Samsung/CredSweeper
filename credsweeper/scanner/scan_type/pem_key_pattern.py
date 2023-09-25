import logging
import re
import string
from typing import Optional, List

from credsweeper.common.constants import Chars, PEM_BEGIN_PATTERN, PEM_END_PATTERN, RuleType
from credsweeper.config import Config
from credsweeper.credentials import Candidate, LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import ValuePatternCheck, ValuePemPatternCheck
from credsweeper.rules import Rule
from credsweeper.scanner.scan_type import ScanType
from credsweeper.utils.entropy_validator import EntropyValidator

logger = logging.getLogger(__name__)


class PemKeyPattern(ScanType):
    """Check if line is a start of a PEM key.


    Parameters:
        ignore_starts: Leading lines in pem file that should be ignored
        remove_characters: This characters would be striped from PEM lines before entropy check

    """

    ignore_starts = [PEM_BEGIN_PATTERN, "Proc-Type", "Version", "DEK-Info"]
    wrap_characters = "\\'\";,[]#*"
    remove_characters = string.whitespace + wrap_characters
    remove_characters_plus = remove_characters + '+'
    pem_pattern_check: Optional[ValuePatternCheck] = None
    # last line contains 4 symbols, at least
    re_value_pem = re.compile(r"(?P<value>([^-]*" + PEM_END_PATTERN +
                              r"[^-]+-----)|(([a-zA-Z0-9/+=]{64}.*)?[a-zA-Z0-9/+=]{4})+)")

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
        if not cls.pem_pattern_check:
            cls.pem_pattern_check = ValuePemPatternCheck(config)
        if candidates := cls._get_candidates(config, rule, target):
            candidate = candidates[0]
            if pem_lines := cls.detect_pem_key(config, rule, target):
                candidate.line_data_list = pem_lines
                return [candidate]

        return []

    @classmethod
    def detect_pem_key(cls, config: Config, rule: Rule, target: AnalysisTarget) -> List[LineData]:
        """Detects PEM key in single line and with iterative for next lines according
        https://www.rfc-editor.org/rfc/rfc7468

        Args:
            config: Config
            rule: Rule
            target: Analysis target

        Return:
            List of LineData with found PEM

        """
        line_data: List[LineData] = []
        key_data = ""
        # get line with -----BEGIN which may contain full key
        first_line = LineData(config, target.line, target.line_pos, target.line_num, target.file_path, target.file_type,
                              target.info, rule.patterns[0])
        line_data.append(first_line)
        # protection check for case when first line starts from 0
        start_pos = target.line_pos if 0 <= target.line_pos else 0
        finish_pos = min(start_pos + 200, target.lines_len)
        for line_pos in range(start_pos, finish_pos):
            line = target.lines[line_pos]
            if target.line_pos != line_pos:
                _line = LineData(config, line, line_pos, target.line_nums[line_pos], target.file_path, target.file_type,
                                 target.info, cls.re_value_pem)
                line_data.append(_line)
            # replace escaped line ends with real and process them - PEM does not contain '\' sign
            sublines = line.replace("\\r", '\n').replace("\\n", '\n').splitlines()
            for subline in sublines:
                if cls.is_leading_config_line(subline):
                    continue
                elif PEM_END_PATTERN in subline:
                    # Check if entropy is high enough for base64 set with padding sign
                    entropy_validator = EntropyValidator(key_data, Chars.BASE64_CHARS)
                    if not entropy_validator.valid:
                        logger.debug("Filtered with entropy %f '%s'", entropy_validator.entropy, key_data)
                        return []
                    # OPENSSH format has multiple AAAAA pattern
                    if "OPENSSH" not in target.line_strip and cls.pem_pattern_check.equal_pattern_check(key_data):
                        logger.debug("Filtered with ValuePemPatternCheck %s", target)
                        return []
                    # all OK - return line data with all lines which include PEM
                    return line_data
                else:
                    sanitized_line = cls.sanitize_line(subline)
                    # PEM key line should not contain spaces or . (and especially not ...)
                    if ' ' in sanitized_line or "..." in sanitized_line:
                        return []
                    key_data += sanitized_line
        return []

    @classmethod
    def sanitize_line(cls, line: str, recurse_level: int = 5) -> str:
        """Remove common symbols that can surround PEM keys inside code.

        Examples::

            `# ZZAWarrA1`
            `* ZZAWarrA1`
            `  "ZZAWarrA1\\n" + `

        Args:
            line: Line to be cleaned
            recurse_level: to avoid infinite loop in case when removed symbol inside base64 encoded

        Return:
            line with special characters removed from both ends

        """
        recurse_level -= 1

        if 0 > recurse_level:
            return line

        # Note that this strip would remove `\n` but not `\\n`
        line = line.strip(string.whitespace)
        if line.startswith("// "):
            # assume, the commented line has to be separated from base64 code. Otherwise, it may be a part of PEM.
            line = line[3:]
        if line.startswith("/*"):
            line = line[2:]
        if line.endswith("*/"):
            line = line[:-2]
        if '"' in line or "'" in line:
            # remove concatenation only when quotes present
            line = line.strip(cls.remove_characters_plus)
        else:
            line = line.strip(cls.remove_characters)
        # check whether new iteration requires
        for x in string.whitespace:
            if line.startswith(x) or line.endswith(x):
                return cls.sanitize_line(line, recurse_level)

        for x in cls.wrap_characters:
            if x in line:
                return cls.sanitize_line(line, recurse_level)

        return line

    @classmethod
    def is_leading_config_line(cls, line: str) -> bool:
        """Remove non-key lines from the beginning of a list.

        Example lines with non-key leading lines:

        .. code-block:: text

            Proc-Type: 4,ENCRYPTED
            DEK-Info: DEK-Info: AES-256-CBC,2AA219GG746F88F6DDA0D852A0FD3211

            ZZAWarrA1...

        Args:
            line: Line to be checked

        Return:
            True if the line is not a part of encoded data but leading config

        """
        if 0 == len(line):
            return True
        for ignore_string in cls.ignore_starts:
            if ignore_string in line:
                return True
        return False
