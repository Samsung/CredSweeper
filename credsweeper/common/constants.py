import string
import typing
from enum import Enum
from typing import Optional, Union


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


class Confidence(Enum):
    """Confidence of candidate"""
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"

    def __lt__(self, other) -> bool:
        if self == Confidence.WEAK:
            return other is not Confidence.WEAK
        elif self == Confidence.MODERATE:
            return other is Confidence.STRONG
        return False

    @staticmethod
    def get(confidence: Union[str, "Confidence"]) -> Optional["Confidence"]:
        """returns Confidence value from string or None"""
        if isinstance(confidence, Confidence):
            return confidence
        if isinstance(confidence, str):
            value = getattr(Confidence, confidence.strip().upper(), None)
            if isinstance(value, Confidence):
                return value
        return None


BASE64COMMON = string.ascii_uppercase + string.ascii_lowercase + string.digits


class Chars(Enum):
    """Stores enumeration of characters sets of encoding dictionaries"""

    # set of characters, hexadecimal numeral system (Base16). Upper- and lowercase
    HEX_CHARS = string.digits + "ABCDEFabcdef"
    # UUID charset in uppercase
    UUID_UPPER_CHARS = string.digits + "ABCDEF-"
    # UUID charset in lowercase
    UUID_LOWER_CHARS = string.digits + "abcdef-"
    # set of characters, hexadecimal numeral system (Base16). Uppercase
    BASE16UPPER = string.digits + "ABCDEF"
    # set of characters, hexadecimal numeral system (Base16). Lowercase
    BASE16LOWER = string.digits + "abcdef"
    # set of 32 characters, used in Base32 encoding
    BASE32_CHARS = string.ascii_uppercase + "234567"
    # set of 36 characters, used in Base36 encoding
    BASE36_CHARS = string.digits + string.ascii_lowercase
    # base62 set https://en.wikipedia.org/wiki/Base62
    BASE62_CHARS = string.digits + string.ascii_uppercase + string.ascii_lowercase
    # URL- and filename-safe standard
    BASE64URL_CHARS = BASE64COMMON + "-_"
    # URL- and filename-safe standard plus padding sign
    BASE64URLPAD_CHARS = BASE64COMMON + "-_="
    # standard base64 charset
    BASE64STD_CHARS = BASE64COMMON + "+/"
    # standard base64 plus padding sign
    BASE64STDPAD_CHARS = BASE64COMMON + "+/="
    # except whitespaces
    ASCII_VISIBLE = string.digits + string.ascii_letters + string.punctuation
    # all printable symbols
    ASCII_PRINTABLE = string.printable


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


StartEnd = typing.NamedTuple("StartEnd", [("start", int), ("end", int)])

MIN_VARIABLE_LENGTH = 1
MIN_SEPARATOR_LENGTH = 1
MIN_VALUE_LENGTH = 4
# if the line is oversize - it will be scanned by chunks with overlapping
MAX_LINE_LENGTH = 8000
# the size for overlapping chunks must be less than MAX_LINE_LENGTH
CHUNK_SIZE = 4000
OVERLAP_SIZE = 1000
CHUNK_STEP_SIZE = CHUNK_SIZE - OVERLAP_SIZE
# ML hunk size to limit of variable or value size and get substring near value
ML_HUNK = 64

# values according https://docs.python.org/3/library/codecs.html
UTF_8 = "utf_8"
UTF_16 = "utf_16"
LATIN_1 = "latin_1"
ASCII = "ascii"

DEFAULT_ENCODING = UTF_8

# LATIN_1 has to be placed at end to apply binary file detection
AVAILABLE_ENCODINGS = [UTF_8, UTF_16, LATIN_1]

# to limit memory usage in case of recursive scan
RECURSIVE_SCAN_LIMITATION = 1 << 30

# default value for config and ValuePatternCheck
DEFAULT_PATTERN_LEN = 4

# PEM x509 patterns
PEM_BEGIN_PATTERN = "-----BEGIN"
PEM_END_PATTERN = "-----END"

# similar min_line_len in rule_template - no real credential in data less than 8 bytes
MIN_DATA_LEN = 8
