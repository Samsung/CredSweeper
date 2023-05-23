from enum import Enum
from typing import Optional, Union


class KeywordPattern:
    """Pattern set of keyword types"""
    key = r"(?P<variable>((('|\"|`)[^:='\"`<>]*|[^:='\"`<>\s\(]*)(?P<keyword>{})[^:='\"`<>\?\!]*)('|\"|`)?)"
    separator = r"\s*\]?\s*(?P<separator>{})((?!\s*ENC(\(|\[))(\s|\w)*\((\s|\w|=|\()*|\s*)"
    value = r"(?P<value_leftquote>(\\)*(b|r)?('|\"|`))?" \
            r"(?P<value>[^'\"`\\]{0,1000})(?P<value_rightquote>(\\)*('|\"|`))?"


class Separator:
    """Separators collection"""
    common = "=|:=|:"
    # All unique non-regex characters from `common`
    common_as_set = "=:"
    c = "="
    java = "="
    json = ":"
    php = "=>"


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

    Parameters:
        HEX_CHARS: set of characters, hexadecimal numeral system (Base16)
        BASE36_CHARS: set of 36 characters, used in Base36 encoding
        BASE64_CHARS: set of 64 characters, used in Base64 encoding

    """
    HEX_CHARS = "1234567890abcdefABCDEF"
    BASE36_CHARS = "abcdefghijklmnopqrstuvwxyz1234567890"
    BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="


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
    KEYWORD = "keyword"
    PATTERN = "pattern"
    PEM_KEY = "pem_key"


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
    ADDED_ACCOMPANY = "added_accompany"
    DELETED_ACCOMPANY = "deleted_accompany"


MIN_VARIABLE_LENGTH = 1
MIN_SEPARATOR_LENGTH = 1
MIN_VALUE_LENGTH = 4
MAX_LINE_LENGTH = 1500
""" values according https://docs.python.org/3/library/codecs.html """
UTF_8 = "utf_8"
UTF_16 = "utf_16"
LATIN_1 = "latin_1"

DEFAULT_ENCODING = UTF_8

# LATIN_1 has to be placed at end to apply binary file detection
AVAILABLE_ENCODINGS = [UTF_8, UTF_16, LATIN_1]

# to limit memory usage in case of recursive scan
RECURSIVE_SCAN_LIMITATION = 1 << 30

# the limit of complexity allows separate weak token which might be a variable name
TOKEN_BASE32_COMPLEXITY = 0.7
