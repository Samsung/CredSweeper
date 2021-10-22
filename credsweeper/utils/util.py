import math
import os
from typing import List

from regex import regex

from credsweeper.common.constants import Chars, KeywordPattern, Separator


class Util:
    """
    Class that contains different useful methods
    """

    @classmethod
    def get_extension(cls, file_path: str) -> str:
        _, extension = os.path.splitext(file_path)
        return extension

    @classmethod
    def get_keyword_pattern(cls, keyword: str, separator: Separator = Separator.common) -> regex.Pattern:
        return regex.compile(KeywordPattern.key.format(keyword) + KeywordPattern.separator.format(separator) +
                             KeywordPattern.value,
                             flags=regex.IGNORECASE)

    @classmethod
    def get_regex_combine_or(cls, regex_strs: List[str]) -> str:
        result = "(?:"

        for elem in regex_strs:
            result += elem + "|"

        if result[-1] == "|":
            result = result[:-1]
        result += ")"

        return result

    @classmethod
    def is_entropy_validate(cls, data: str) -> bool:
        if cls.get_shannon_entropy(data, Chars.BASE64_CHARS) > 4.5 or \
           cls.get_shannon_entropy(data, Chars.HEX_CHARS) > 3 or \
           cls.get_shannon_entropy(data, Chars.BASE36_CHARS) > 3:
            return True
        return False

    @classmethod
    def get_shannon_entropy(cls, data: str, iterator: Chars) -> float:
        """
        Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
        """
        if not data:
            return 0

        entropy = 0
        for x in iterator:
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)

        return entropy
