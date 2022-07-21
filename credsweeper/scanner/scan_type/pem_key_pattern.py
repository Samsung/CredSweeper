from typing import List, Optional

from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import ValuePatternCheck
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
    remove_characters = " '\";,[]\n\r\t\\+#*"

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

        if cls.is_pem_key(target.lines[target.line_num:]):
            return cls._get_candidate(config, rule, target)

        return None

    @classmethod
    def is_pem_key(cls, lines: List[str]) -> bool:
        """Check if provided lines is a PEM key.

        Args:
            lines: Lines to be checked

        Return:
            Boolean. True if PEM key, False otherwise

        """
        lines = cls.strip_lines(lines)
        lines = cls.remove_leading_config_lines(lines)
        key_data = ""
        for line_num, line in enumerate(lines):
            if line_num >= 190:
                return False
            if "-----END" in line:
                # Check if entropy is high enough
                removed_by_entropy = not Util.is_entropy_validate(key_data)
                # Check if have no substring with 5 same consecutive characters (like 'AAAAA')
                pattern_check = ValuePatternCheck(5)
                removed_by_filter = pattern_check.equal_pattern_check(key_data)
                not_removed = not (removed_by_entropy or removed_by_filter)
                return not_removed
            # PEM key line should not contain spaces or . (and especially not ...)
            elif " " in line or "..." in line:
                return False
            else:
                key_data += line

        return False  # Return false if no `-END` section in lines

    @classmethod
    def strip_lines(cls, lines: List[str]) -> List[str]:
        r"""Remove common symbols that can surround PEM keys inside code.

        Examples::

            `# ZZAWarrA1`
            `* ZZAWarrA1`
            `  "ZZAWarrA1\\n" + `

        Args:
            lines: Lines to be striped

        Return:
            lines with special characters removed from both ends

        """
        # Note that this strip would remove `\n` but not `\\n`
        stripped_lines = [line.strip(cls.remove_characters) for line in lines]
        # If line still ends with "\n" - remove last 2 characters and strip again (case of `\\n` in the line)
        stripped_lines = [
            line[:-2].strip(cls.remove_characters) if line.endswith("\\n") else line for line in stripped_lines
        ]
        return stripped_lines

    @classmethod
    def remove_leading_config_lines(cls, lines: List[str]) -> List[str]:
        """Remove non-key lines from the beginning of a list.

        Example lines with non-key leading lines:

        .. code-block:: text

            Proc-Type: 4,ENCRYPTED
            DEK-Info: DEK-Info: AES-256-CBC,2AA219GG746F88F6DDA0D852A0FD3211

            ZZAWarrA1...

        Args:
            lines: Lines to be checked

        Return:
            List of strings without leading non-key lines

        """
        leading_lines = 0

        for line in lines:
            if any(line.startswith(ignore_string) for ignore_string in cls.ignore_starts) or len(line) == 0:
                leading_lines += 1
            else:
                break

        return lines[leading_lines:]
