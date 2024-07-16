import re
from enum import Enum
from typing import Optional, Union


class KeywordPattern:
    """Pattern set of keyword types"""
    key_left = r"(\\[nrt])?(?P<variable>(([`'\"]+[^:='\"`}<>\\/&?]*|[^:='\"`}<>\s()\\/&?]*)" \
               r"(?P<keyword>"
    # there will be inserted a keyword
    key_right = r")" \
                r"[^:='\"`<>{?!&]*)[`'\"]*)"  # <variable>
    separator = r"\s*\]?\s*" \
                r"(?P<separator>:( [a-z]{3,9}[?]? )?=" \
                r"|:|=>|!=|===|==|=)" \
                r"((?!\s*ENC(\(|\[))(\s|\w)*\((\s|\w|=|\()*|\s*)"
    # Authentication scheme ( oauth | basic | bearer | apikey ) precedes to credential
    value = r"(?P<value_leftquote>((b|r|br|rb|u|f|rf|fr|\\{0,8})?[`'\"]){1,4})?" \
            r"( ?(oauth|bot|basic|bearer|apikey|accesskey) )?" \
            r"(?P<value>" \
            r"(?(value_leftquote)(?:\\[tnrux0-7][0-9a-f]*|[^`'\"\\])|(?:\\n|\\r|\\?[^\s`'\"\\,;])){3,8000}" \
            r"|(?:\{[^}]{3,8000}\})|(?:<[^>]{3,8000}>)" \
            r")" \
            r"(?(value_leftquote)(?P<value_rightquote>(\\{0,8}[`'\"]){1,4})?)"

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


class Base(Enum):
    """Stores types of character sets in lower case"""
    base16upper = "base16upper"
    base16lower = "base16lower"
    base32 = "base32"
    base36 = "base36"
    base64 = "base64"
    base64std = "base64std"
    base64url = "base64url"
    hex = "hex"


class Chars(Enum):
    """Stores three types characters sets.
    """

    # set of characters, hexadecimal numeral system (Base16). Upper- and lowercase
    HEX_CHARS = "0123456789ABCDEFabcdef"
    # set of characters, hexadecimal numeral system (Base16). Uppercase
    BASE16UPPER = "0123456789ABCDEF"
    # set of characters, hexadecimal numeral system (Base16). Lowercase
    BASE16LOWER = "0123456789abcdef"
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
# if the line is oversize - it will be scanned by chunks with overlapping
MAX_LINE_LENGTH = 8000
# the size for overlapping chunks must be less than MAX_LINE_LENGTH
CHUNK_SIZE = 4000
OVERLAP_SIZE = 1000
CHUNK_STEP_SIZE = CHUNK_SIZE - OVERLAP_SIZE
# ML hunk size to limit of variable or value size and get substring near value
ML_HUNK = 80
""" values according https://docs.python.org/3/library/codecs.html """
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

# default value for config and ValuePemPatternCheck
DEFAULT_PEM_PATTERN_LEN = 5

# PEM x509 patterns
PEM_BEGIN_PATTERN = "-----BEGIN"
PEM_END_PATTERN = "-----END"
