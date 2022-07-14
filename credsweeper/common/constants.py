from enum import Enum


class KeywordPattern:
    """Pattern set of keyword types"""
    key = r"(?P<variable>((('|\"|`)[^:='\"`<>]*|[^:='\"`<>\s\(]*)(?P<keyword>{})[^:='\"`<>]*)('|\"|`)?)"
    separator = r"\s*\]?\s*(?P<separator>{})((\s|\w)*\((\s|\w|=|\()*|\s*)"
    value = r"(?P<value_leftquote>(\\)*(b|r)?('|\"|`))?" \
            r"(?P<value>[^'\"`(\\\')(\\\")]{0,1000})(?P<value_rightquote>(\\)*('|\"|`))?"


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
    """Group type"""
    KEYWORD = "keyword"
    PATTERN = "pattern"


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


class DiffRowType:
    """Diff type of row"""
    ADDED = "added"
    DELETED = "deleted"
    ADDED_ACCOMPANY = "added_accompany"
    DELETED_ACCOMPANY = "deleted_accompany"


MIN_VARIABLE_LENGTH = 1
MIN_SEPARATOR_LENGTH = 1
MIN_VALUE_LENGTH = 4
MAX_LINE_LENGTH = 1500

DEFAULT_ENCODING = "utf8"

AVAILABLE_ENCODINGS = ("utf8", "utf16", "latin_1")

# to limit memory usage in case of recursive scan
RECURSIVE_SCAN_LIMITATION = 1 << 30
