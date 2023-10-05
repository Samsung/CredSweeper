import re
from enum import Enum
from typing import Optional, Union


class KeywordPattern:
    """Pattern set of keyword types"""
    key_left = r"(?P<variable>(([`'\"]+[^:='\"`<>]*|[^:='\"`<>\s\(]*)" \
               r"(?P<keyword>"
    # there will be inserted a keyword
    key_right = r")[^:='\"`<>\?\!]*)[`'\"]*)"  # <variable>
    separator = r"\s*\]?\s*(?P<separator>=|:=|:|=>)((?!\s*ENC(\(|\[))(\s|\w)*\((\s|\w|=|\()*|\s*)"
    value = r"(?P<value_leftquote>((b|r|br|rb|u|f|rf|fr|\\)?[`'\"])+)?" \
            r"(?P<value>(?(value_leftquote)(?:\\[nrux0-7][0-9a-f]*|[^`'\"\\])|(?:\\n|\\r|\\?[^\s`'\"\\]))+)" \
            r"(?P<value_rightquote>(\\?[`'\"])+)?"

    @classmethod
    def get_keyword_pattern(cls, keyword: str) -> re.Pattern:
        """Returns compiled regex pattern"""
        expression = "".join([cls.key_left, keyword, cls.key_right, cls.separator, cls.value])
        return re.compile(expression, flags=re.IGNORECASE)


class Severity(Enum):
    """Severity of candidate"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other) -> bool:
        if self == Severity.INFO:
            return other is not Severity.INFO
        elif self == Severity.LOW:
            return other in [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        elif self == Severity.MEDIUM:
            return other in [Severity.HIGH, Severity.CRITICAL]
        elif self == Severity.HIGH:
            return other is Severity.CRITICAL
        return False

    @staticmethod
    def get(severity: Union[str, "Severity"]) -> Optional["Severity"]:
        """returns Severity value from string or None"""
        if isinstance(severity, Severity):
            return severity
        if isinstance(severity, str):
            value = getattr(Severity, severity.strip().upper(), None)
            if isinstance(value, Severity):
                return value
        return None


class Base(Enum):
    """Stores types of character sets in lower case"""
    base36 = "base36"
    base64 = "base64"
    hex = "hex"


class Chars(Enum):
    """Stores three types characters sets.
    """

    # set of characters, hexadecimal numeral system (Base16). Upper- and lowercase
    HEX_CHARS = "0123456789ABCDEFabcdef"
    # set of 32 characters, used in Base32 encoding
    BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    # set of 36 characters, used in Base36 encoding
    BASE36_CHARS = "abcdefghijklmnopqrstuvwxyz1234567890"
    # standard base64 with padding sign
    BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    # URL- and filename-safe standard
    BASE64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    # standard base64
    BASE64STD_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


ENTROPY_LIMIT_BASE64 = 4.5
ENTROPY_LIMIT_BASE3x = 3


class KeyValidationOption(Enum):
    """API validation state"""
    INVALID_KEY = 0
    VALIDATED_KEY = 1
    UNDECIDED = 2
    NOT_AVAILABLE = 3


class GroupType(Enum):
    """Group type - used in Group constructor for load predefined set of filters"""
    KEYWORD = "keyword"
    PATTERN = "pattern"
    # for empty filter set
    DEFAULT = "default"


class RuleType(Enum):
    """Rule type"""
    # combine pattern with predefined structure
    KEYWORD = "keyword"
    # use patterns as-is. all patterns must be found in target (line)
    PATTERN = "pattern"
    # single value to detect pem format with specific scanner
    PEM_KEY = "pem_key"
    # When first pattern found - second will be searched in adjoining lines
    MULTI = "multi"


class ThresholdPreset(Enum):
    """Preset threshold to simplify precision/recall selection for the user."""
    lowest = "lowest"
    low = "low"
    medium = "medium"
    high = "high"
    highest = "highest"


class DiffRowType(Enum):
    """Diff type of row"""
    ADDED = "added"
    DELETED = "deleted"


MIN_VARIABLE_LENGTH = 1
MIN_SEPARATOR_LENGTH = 1
MIN_VALUE_LENGTH = 4
MAX_LINE_LENGTH = 2000
""" values according https://docs.python.org/3/library/codecs.html """
UTF_8 = "utf_8"
UTF_16 = "utf_16"
LATIN_1 = "latin_1"

DEFAULT_ENCODING = UTF_8

# LATIN_1 has to be placed at end to apply binary file detection
AVAILABLE_ENCODINGS = [UTF_8, UTF_16, LATIN_1]

# to limit memory usage in case of recursive scan
RECURSIVE_SCAN_LIMITATION = 1 << 30

# default value for config and ValuePatternCheck
DEFAULT_PATTERN_LEN = 4

# default value for config and ValuePemPatternCheck
DEFAULT_PEM_PATTERN_LEN = 5

# PEM x509 patterns
PEM_BEGIN_PATTERN = "-----BEGIN"
PEM_END_PATTERN = "-----END"
