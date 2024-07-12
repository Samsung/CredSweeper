import contextlib
import logging
import re
import string
from typing import List

from credsweeper.common.constants import PEM_BEGIN_PATTERN, PEM_END_PATTERN, Chars
from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.utils import Util
from credsweeper.utils.entropy_validator import EntropyValidator

logger = logging.getLogger(__name__)


class PemKeyDetector:
    """Class to detect PEM PRIVATE keys only"""
    base64set = set(string.ascii_uppercase) | set(string.ascii_lowercase) | set(string.digits) | {'+', '/', '='}

    ignore_starts = [PEM_BEGIN_PATTERN, "Proc-Type", "Version", "DEK-Info"]
    wrap_characters = "\\'\";,[]#*!"
    remove_characters = string.whitespace + wrap_characters
    # last line contains 4 symbols, at least
    re_pem_begin = re.compile(r"(?P<value>" + PEM_BEGIN_PATTERN + r"\s(?!ENCRYPTED)[^-]*PRIVATE[^-]*KEY[^-]*-----"
                              r"(.+" + PEM_END_PATTERN + r"[^-]+KEY[^-]*-----)?)")
    re_value_pem = re.compile(r"(?P<value>([^-]*" + PEM_END_PATTERN +
                              r"[^-]+-----)|(([a-zA-Z0-9/+=]{64}.*)?[a-zA-Z0-9/+=]{4})+)")

    @classmethod
    def detect_pem_key(cls, config: Config, target: AnalysisTarget) -> List[LineData]:
        """Detects PEM key in single line and with iterative for next lines according
        https://www.rfc-editor.org/rfc/rfc7468

        Args:
            config: Config
            target: Analysis target

        Return:
            List of LineData with found PEM

        """
        line_data: List[LineData] = []
        key_data = ""
        # get line with -----BEGIN which may contain full key
        first_line = LineData(config, target.line, target.line_pos, target.line_num, target.file_path, target.file_type,
                              target.info, cls.re_pem_begin)
        line_data.append(first_line)
        # protection check for case when first line starts from 0
        start_pos = target.line_pos if 0 <= target.line_pos else 0
        finish_pos = min(start_pos + 200, target.lines_len)
        begin_pattern_not_passed = True
        for line_pos in range(start_pos, finish_pos):
            line = target.lines[line_pos]
            if target.line_pos != line_pos:
                _line = LineData(config, line, line_pos, target.line_nums[line_pos], target.file_path, target.file_type,
                                 target.info, cls.re_value_pem)
                line_data.append(_line)
            # replace escaped line ends with real and process them - PEM does not contain '\' sign
            while "\\\\" in line:
                line = line.replace("\\\\", "\\")
            sublines = line.replace("\\r", '\n').replace("\\n", '\n').splitlines()
            for subline in sublines:
                if begin_pattern_not_passed or cls.is_leading_config_line(subline):
                    if PEM_BEGIN_PATTERN in subline:
                        begin_pattern_not_passed = False
                    continue
                elif PEM_END_PATTERN in subline:
                    if "PGP" in target.line_strip:
                        # Check if entropy is high enough for base64 set with padding sign
                        entropy_validator = EntropyValidator(key_data, Chars.BASE64_CHARS)
                        if entropy_validator.valid:
                            return line_data
                        logger.debug("Filtered with entropy %f '%s'", entropy_validator.entropy, key_data)
                    if "OPENSSH" in target.line_strip:
                        # Check whether the key is encrypted
                        with contextlib.suppress(Exception):
                            decoded = Util.decode_base64(key_data, urlsafe_detect=True)
                            if 32 < len(decoded) and b"bcrypt" not in decoded:
                                # 256 bits is the minimal size of Ed25519 keys
                                # all OK - the key is not encrypted in this top level
                                return line_data
                        logger.debug("Filtered with size or bcrypt '%s'", key_data)
                    else:
                        with contextlib.suppress(Exception):
                            decoded = Util.decode_base64(key_data, urlsafe_detect=True)
                            if Util.is_asn1(decoded):
                                # all OK - the key is not encrypted in this top level
                                return line_data
                        logger.debug("Filtered with non asn1 '%s'", key_data)
                    return []
                else:
                    sanitized_line = cls.sanitize_line(subline)
                    # PEM key line should not contain spaces or . (and especially not ...)
                    for i in sanitized_line:
                        if i not in cls.base64set:
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
        if line.startswith("//"):
            # simplify first condition for speed-up of doxygen style processing
            if line.startswith("// ") or line.startswith("/// "):
                # Assume that the commented line is to be separated from base64 code, it may be a part of PEM, otherwise
                line = line[3:]
        if line.startswith("/*"):
            line = line[2:]
        if line.endswith("*/"):
            line = line[:-2]
        if line.endswith("\\"):
            # line carry in many languages
            line = line[:-1]

        # remove concatenation carefully only when it is not part of base64
        if line.startswith('+') and 1 < len(line) and line[1] not in cls.base64set:
            line = line[1:]
        if line.endswith('+') and 2 < len(line) and line[-2] not in cls.base64set:
            line = line[:-1]

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
