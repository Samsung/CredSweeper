import string
from typing import Optional

from credsweeper.common.constants import Chars
from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import ValuePatternCheck, ValuePemPatternCheck
from credsweeper.rules import Rule
from credsweeper.scanner.scan_type import ScanType
from credsweeper.utils import Util


class PemKeyPattern(ScanType):
    """Check if line is a start of a PEM key.


    Parameters:
        ignore_starts: Leading lines in pem file that should be ignored
        remove_characters: This characters would be striped from PEM lines before entropy check

    """

    ignore_starts = ["Proc-Type", "Version", "DEK-Info"]
    wrap_characters = "\\'\";,[]#*"
    remove_characters = string.whitespace + wrap_characters
    remove_characters_plus = remove_characters + '+'
    pem_pattern_check: Optional[ValuePatternCheck] = None

    @classmethod
    def run(cls, config: Config, rule: Rule, target: AnalysisTarget) -> Optional[Candidate]:
        """Check if current line is a start of a PEM key.

        Args:
            config: user configs
            rule: Rule object to check current line. Should be a pem-pattern rule
            target: Analysis target

        Return:
            Candidate object if pattern defined in a rule is present in a line and filters defined in rule do not
            remove current line. None otherwise

        """
        assert rule.pattern_type == rule.PEM_KEY_PATTERN, \
            "Rules provided to PemKeyPattern.run should have pattern_type equal to PEM_KEY_PATTERN"
        if not cls.pem_pattern_check:
            cls.pem_pattern_check = ValuePemPatternCheck(config)
        if finish_line := cls.detect_pem_key(target):
            if candidate := cls._get_candidate(config, rule, target):
                candidate.line_data_list[0].info += f"[{target.line_num}:{finish_line}]"
                return candidate

        return None

    @classmethod
    def detect_pem_key(cls, target: AnalysisTarget) -> int:
        """Check if provided lines is a PEM key.

        Args:
            target: Analysis target

        Return:
            integer. last line number of the detected PEM key

        """
        key_data = ""
        for line_num, line in enumerate(target.lines[target.line_num:]):
            if line_num >= 190:
                return 0
            elif cls.is_leading_config_line(line):
                continue
            elif "-----END" in line:
                # PEM key line should not contain spaces or . (and especially not ...)
                if "..." in key_data:
                    return 0
                # Check if entropy is high enough for base64 set with padding sign
                removed_by_entropy = Util.get_shannon_entropy(key_data, Chars.BASE64_CHARS.value) < 4.5
                if "OPENSSH" in target.line:
                    # the format has multiple AAAAA pattern
                    removed_by_filter = False
                else:
                    # Check whether data have no substring with 5 same consecutive characters (like 'AAAAA')
                    removed_by_filter = cls.pem_pattern_check.equal_pattern_check(key_data)
                if removed_by_entropy or removed_by_filter:
                    return 0
                return target.line_num + line_num + 1
            else:
                sanitized_line = cls.sanitize_line(line)
                if ' ' in sanitized_line:
                    # early return if one space appears in the data
                    return 0
                key_data += sanitized_line

        return 0

    @classmethod
    def sanitize_line(cls, line: str, recursy_level:int=5) -> str:
        """Remove common symbols that can surround PEM keys inside code.

        Examples::

            `# ZZAWarrA1`
            `* ZZAWarrA1`
            `  "ZZAWarrA1\\n" + `

        Args:
            line: Line to be cleaned

        Return:
            line with special characters removed from both ends

        """
        recursy_level-=1

        if 0 > recursy_level:
            return line

        # Note that this strip would remove `\n` but not `\\n`
        line = line.strip(string.whitespace)
        # If line still ends with "\n" - remove last 2 characters and strip again (case of `\\n` in the line)
        if line.endswith("\\n"):
            line = line[:-2]
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
                return cls.sanitize_line(line, recursy_level)

        for x in cls.wrap_characters:
            if x in line:
                return cls.sanitize_line(line, recursy_level)

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
