import contextlib
import logging
import re
import string
from typing import List

from credsweeper.common.constants import PEM_BEGIN_PATTERN, PEM_END_PATTERN, Chars, MAX_LINE_LENGTH
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class PemKeyDetector:
    """Class to detect PEM PRIVATE keys only"""
    BASE64_CHARS_SET = set(Chars.BASE64STDPAD_CHARS.value)
    RE_BASE64_CHARS = re.compile(fr"[{re.escape(Chars.BASE64STDPAD_CHARS.value)}]+")

    ENTROPY_LIMIT_BASE64 = 4.5

    # the limit is huge with possible prefixes and escaping
    MAX_PEM_LENGTH = 4 * MAX_LINE_LENGTH

    IGNORE_STARTS = [PEM_BEGIN_PATTERN, "Proc-Type", "Version", "DEK-Info"]
    WRAP_CHARACTERS = "\\'\"`;,[]#*!"
    REMOVE_CHARACTERS = string.whitespace + WRAP_CHARACTERS
    # last line contains 4 symbols, at least
    RE_PEM_BEGIN = re.compile(r"(?P<value>" + PEM_BEGIN_PATTERN +
                              r"(?![^-]{1,80}ENCRYPTED)[^-]{0,80}PRIVATE[^-]{1,80}KEY[^-]{0,80}-----"
                              r"(.{1,8000}" + PEM_END_PATTERN + r"[^-]{1,80}KEY[^-]{0,80}-----)?)")
    RE_PEM_VALUE = re.compile(fr"(?P<value>.{{0,{MAX_PEM_LENGTH}}})")

    def __init__(self, config: Config):
        self.__config = config
        self._barrier_pos: int = -2
        self._barrier_cut: int = -2
        self._barrier: str = ''

    def cut_barrier(self, line: str) -> str:
        """Cut off barrier if detected"""
        if self._barrier and 0 <= self._barrier_pos < self._barrier_cut < len(line):
            if line[self._barrier_pos] == self._barrier:
                return line[self._barrier_cut:]
            self._barrier = ''
            self._barrier_pos = self._barrier_cut = -1
        return line

    def set_barrier(self, line: str, start=0, end=MAX_LINE_LENGTH):
        """Detects barrier with offset of RE_PEM_BEGIN"""
        self._barrier = ''
        self._barrier_cut = line.find(PEM_END_PATTERN, start, end)
        self._barrier_pos = self._barrier_cut - 1
        if 0 <= self._barrier_pos < self._barrier_cut < len(line):
            barrier = line[self._barrier_pos]
            if barrier not in PemKeyDetector.BASE64_CHARS_SET:
                self._barrier = barrier

    def detect_pem_key(self, first_line: LineData, target: AnalysisTarget) -> List[LineData]:
        """Detects PEM key in single line and with iterative for next lines according
        https://www.rfc-editor.org/rfc/rfc7468

        Args:
            first_line: detected -----BEGIN from rule pattern
            target: Analysis target

        Return:
            List of LineData with found PEM

        """
        line_data_list: List[LineData] = []
        key_data_list: List[str] = []
        # escaped key in one line with prefixes
        pem_end_limit = min(target.line_len, first_line.value_start + PemKeyDetector.MAX_PEM_LENGTH)
        first_line_end_pattern_start = target.line.find(PEM_END_PATTERN, first_line.value_start, pem_end_limit)
        first_line_end_pattern_end = (  #
            target.line.find("-----", first_line_end_pattern_start + 5, first_line_end_pattern_start + 80)  #
            if 0 <= first_line_end_pattern_start else -2)
        if first_line.value_start < first_line_end_pattern_start < first_line_end_pattern_end:
            # the whole PEM in single line
            pem_text = target.line[first_line.value_start:first_line_end_pattern_end + 5]
            first_line.value = pem_text
            first_line.value_end = first_line.value_start + len(pem_text)
            line_data_list.append(first_line)
        else:
            line_data_list.append(first_line)
            pem_text = first_line.line[first_line.value_start:first_line.value_start + PemKeyDetector.MAX_PEM_LENGTH]
            # perhaps, in next lines
            start_pos = max(0, target.line_pos) + 1
            end_pos = min(start_pos + 200, target.lines_len)
            for line_pos in range(start_pos, end_pos):
                target_line = target.lines[line_pos]
                end_pattern_start = target_line.find(PEM_END_PATTERN, 0, PemKeyDetector.MAX_PEM_LENGTH)
                end_pattern_end = (5 + target_line.find("-----", end_pattern_start + 5, end_pattern_start + 80)
                                   if 0 <= end_pattern_start else -2)
                if 0 <= end_pattern_start < end_pattern_end:
                    pem_line = target_line[:end_pattern_end]
                else:
                    pem_line = target_line[:PemKeyDetector.MAX_PEM_LENGTH]
                next_line = LineData(self.__config, target_line, line_pos, target.line_nums[line_pos], target.file_path,
                                     target.file_type, target.info, PemKeyDetector.RE_PEM_VALUE)
                line_data_list.append(next_line)
                pem_text += f"\n{pem_line}"
                if PEM_END_PATTERN in pem_line:
                    break
                if PemKeyDetector.MAX_PEM_LENGTH < len(pem_text):
                    logger.warning("PEM text oversize")
                    return []
            else:
                logger.warning("PEM end not found")
                return []

        while "\\\\" in pem_text:
            # reduce JSON escaping sequences of backslash
            pem_text = pem_text.replace("\\\\", '\\')

        # replace escaped line ends with real and process them - PEM does not contain '\' sign
        pem_text = pem_text.replace("\\r\\n", '\n').replace("\\r", '\n').replace("\\n", '\n').replace("\\t", '\t')
        pem_lines = pem_text.splitlines()
        self.set_barrier(pem_lines[-1])
        for subline in pem_lines:
            if PemKeyDetector.is_leading_config_line(subline):
                continue
            _subline = self.cut_barrier(subline)
            if sanitized_line := PemKeyDetector.sanitize_line(_subline):
                if PEM_END_PATTERN in sanitized_line:
                    return PemKeyDetector.finalize(line_data_list, key_data_list, sanitized_line)
                # the end is not reached - sanitize the data
                # PEM key line should not contain spaces or . (and especially not ...)
                if not PemKeyDetector.RE_BASE64_CHARS.fullmatch(sanitized_line):
                    return []
                key_data_list.append(sanitized_line)
        return []

    @staticmethod
    def finalize(line_data_list: List[LineData], key_data_list: List[str], last_line: str) -> List[LineData]:
        """Checks collected key_data according the key type"""
        if len(key_data_list) < len(line_data_list):
            PemKeyDetector.sanitize_line_data_list(line_data_list, key_data_list, last_line)
        key_data = ''.join(key_data_list)
        if "PGP" in line_data_list[0].value:
            # Check if entropy is high enough for base64 set with padding sign
            entropy = Util.get_shannon_entropy(key_data)
            if PemKeyDetector.ENTROPY_LIMIT_BASE64 <= entropy:
                return line_data_list
            logger.debug("Filtered with entropy %f '%s'", entropy, key_data)
        if "OPENSSH" in line_data_list[0].value:
            # Check whether the key is encrypted
            with contextlib.suppress(Exception):
                decoded = Util.decode_base64(key_data, urlsafe_detect=True)
                if 32 < len(decoded) and b"bcrypt" not in decoded:
                    # 256 bits is the minimal size of Ed25519 keys
                    # all OK - the key is not encrypted in this top level
                    return line_data_list
            logger.debug("Filtered with size or bcrypt '%s'", key_data)
        else:
            with contextlib.suppress(Exception):
                if decoded := Util.decode_base64(key_data, padding_safe=True, urlsafe_detect=True):
                    if len(decoded) == Util.get_asn1_size(decoded):
                        # all OK - the key is not encrypted in this top level
                        return line_data_list
            logger.debug("Filtered with non asn1 '%s'", key_data)
        return []

    @staticmethod
    def sanitize_line_data_list(line_data_list: List[LineData], key_data_list: List[str], last_line: str):
        """Sanitize line_data_list to keep only valuable values"""
        for value in key_data_list:
            if 64 <= len(value):
                # normal value length should not have a collision
                for line_data in line_data_list:
                    if value == line_data.value:
                        # plain case - no sanitize necessary
                        break
                    value_start = line_data.value.find(value)
                    if 0 <= value_start:
                        line_data.value = value
                        line_data.value_start = value_start
                        line_data.value_end = value_start + len(value)
                        break
            else:
                # end of pem may be short and have collisions in long lines
                value_pattern = re.compile(fr".*[^0-9A-Za-z+/=]?({re.escape(value)})[^0-9A-Za-z+/=]?.*")
                for line_data in line_data_list:
                    if value == line_data.value:
                        # plain case - no sanitize necessary
                        break
                    if value_match := value_pattern.fullmatch(line_data.value):
                        line_data.value = value_match.group(1)
                        line_data.value_start, line_data.value_end = value_match.span(1)
                        break
        if last_line.startswith(PEM_END_PATTERN) and last_line.endswith("-----"):
            last_line_data = line_data_list[-1]
            last_value_start = last_line_data.value.find(last_line, 0, PemKeyDetector.MAX_PEM_LENGTH)
            if 0 <= last_line_data.value_start <= last_value_start:
                # left barrier was sanitized
                last_line_data.value = last_line
                last_line_data.value_start = last_value_start
                last_line_data.value_end = last_value_start + len(last_line)

    @staticmethod
    def sanitize_line(line: str, recurse_level: int = 5) -> str:
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
        while line.startswith(("// ", "//\t")):
            line = line[3:]
        while line.startswith(("/// ", "///\t")):
            line = line[4:]
        while line.startswith("/*"):
            line = line[2:]
        while line.endswith("*/"):
            line = line[:-2]
        while line.endswith("\\"):
            # line carry in many languages
            line = line[:-1]

        # remove concatenation carefully only when it is not part of base64
        if line.startswith('+') and 1 < len(line) and line[1] not in PemKeyDetector.BASE64_CHARS_SET:
            line = line[1:]
        if line.endswith('+') and 2 < len(line) and line[-2] not in PemKeyDetector.BASE64_CHARS_SET:
            line = line[:-1]

        line = line.strip(PemKeyDetector.REMOVE_CHARACTERS)
        # check whether new iteration requires
        for x in PemKeyDetector.WRAP_CHARACTERS:
            if x in line:
                return PemKeyDetector.sanitize_line(line, recurse_level=recurse_level)

        return line

    @staticmethod
    def is_leading_config_line(line: str) -> bool:
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
        if not line:
            return True
        for ignore_string in PemKeyDetector.IGNORE_STARTS:
            if ignore_string in line:
                return True
        return False
