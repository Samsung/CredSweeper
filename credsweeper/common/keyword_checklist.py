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
        with open(self.KEYWORD_PATH, 'r') as f:
            self.__keyword_set = set(f.read().split())

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
