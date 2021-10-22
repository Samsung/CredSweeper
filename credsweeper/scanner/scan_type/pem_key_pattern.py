from typing import List, Optional

from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.filters import ValuePatternCheck
from credsweeper.rules import Rule
from credsweeper.scanner.scan_type import ScanType
from credsweeper.utils import Util


class PemKeyPattern(ScanType):
    """Check if line is a start of a PEM key

    Attributes:
        MAX_LINE_LENGTH: Int constant. Max line length allowed in Scanner. All lines longer than this will be ignored
        ignore_starts: List of strings. Leading lines in pem file that should be ignored
        remove_characters: List of characters. This characters would be striped from PEM lines before entropy check
    """
    ignore_starts = ["Proc-Type", "Version", "DEK-Info"]
    remove_characters = " '\";,[]\n\r\t\\+#*"

    @classmethod
    def run(cls, config: Config, line: str, line_num: int, file_path: str, rule: Rule,
            lines: List[str]) -> Optional[Candidate]:
        """Check if current line is a start of a PEM key

        Args:
            config: user configs
            line: Line to check
            line_num: Line number of a current line
            file_path: Path to the file that contain current line
            rule: Rule object to check current line. Should be a pem-pattern rule
            lines: All lines if the file

        Return:
            Candidate object if pattern defined in a rule is present in a line and filters defined in rule do not
                remove current line. None otherwise
        """
        assert rule.pattern_type == rule.PEM_KEY_PATTERN, \
            "Rules provided to PemKeyPattern.run should have pattern_type equal to PEM_KEY_PATTERN"
        line_data = cls.get_line_data(config, line, line_num, file_path, rule.patterns[0], rule.filters)

        if line_data is None:
            return None

        if cls.is_pem_key(lines[line_num:]):
            candidate = Candidate([line_data], rule.patterns, rule.rule_name, rule.severity, rule.validations,
                                  rule.use_ml)
            return candidate
        return None

    @classmethod
    def is_pem_key(cls, lines: List[str]) -> bool:
        """Check if provided lines is a PEM key

        Attributes:
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
        """Remove common symbols that can surround PEM keys inside code
        Examples:
            `# ZZAWarrA1`
            `* ZZAWarrA1`
            `  "ZZAWarrA1\\n" + `

        Attributes:
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
        """Remove non-key lines from the beginning of a list
        Example lines with non-key leading lines:
            ```
            Proc-Type: 4,ENCRYPTED
            DEK-Info: DEK-Info: AES-256-CBC,2AA219GG746F88F6DDA0D852A0FD3211

            ZZAWarrA1...
            ```

        Attributes:
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
