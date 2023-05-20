from functools import cached_property
from typing import Set

from credsweeper.app import APP_PATH


class KeywordChecklist:
    """KeywordsChecklist contains words 3 or more letters length"""
    __keyword_set: Set[str]
    __morpheme_set: Set[str]
    KEYWORD_PATH = APP_PATH / "common" / "keyword_checklist.txt"
    MORPHEME_PATH = APP_PATH / "common" / "morpheme_checklist.txt"

    def __init__(self) -> None:
        # used suggested text read style. split() is preferred because it strips 0x0A on end the file
        self.__keyword_set = set(self.KEYWORD_PATH.read_text().split())
        # The list of morphemes can be combined to form words.
        # The value is considered a variable if at least two exist.
        self.__morpheme_set = set(self.MORPHEME_PATH.read_text().split())

    @cached_property
    def keyword_set(self) -> Set[str]:
        """Get set with keywords.

        Return:
            Set of strings

        """
        return self.__keyword_set

    @cached_property
    def keyword_len(self) -> int:
        """Length of keyword_set"""
        return len(self.__keyword_set)

    @cached_property
    def morpheme_set(self) -> Set[str]:
        """Get extended set with keywords.

        Return:
            Extended set of strings

        """
        return self.__morpheme_set

    @cached_property
    def morpheme_len(self) -> int:
        """Length of morpheme_set"""
        return len(self.__morpheme_set)
