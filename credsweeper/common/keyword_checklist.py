from functools import cached_property
from pathlib import Path
from typing import Set

from credsweeper.utils import Util


class KeywordChecklist:
    """KeywordsChecklist contains words 3 or more letters length"""
    __keyword_set: Set[str]
    __morpheme_set: Set[str]
    KEYWORD_PATH = Path(__file__).parent / "keyword_checklist.txt"
    MORPHEME_PATH = Path(__file__).parent / "morpheme_checklist.txt"

    def __init__(self) -> None:
        # set is used to avoid extra transformations
        keyword_checklist_data = Util.read_data(self.KEYWORD_PATH)
        # split() is preferred because it strips 0x0A on end the file
        self.__keyword_set = set(keyword_checklist_data.decode().split())
        # optimized separately list with morphemes - only substring which may be separated words or 4-chars ending
        morpheme_checklist_data = Util.read_data(self.MORPHEME_PATH)
        self.__morpheme_set = set(morpheme_checklist_data.decode().split())

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
