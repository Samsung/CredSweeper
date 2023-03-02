import os
from typing import List, Set

from credsweeper.utils import Util


class KeywordChecklist:
    __keyword_list: List[str] = []

    def __init__(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(dir_path, "keyword_checklist.txt")
        self.set_list(Util.read_file(file_path))

    def get_list(self) -> List[str]:
        """Get list with keywords.

        Return:
            List of strings

        """
        return self.__keyword_list

    def set_list(self, keyword_list: List[str]) -> None:
        """Remove old keywords and setup new one.

        Args:
            keyword_list: list of keywords to be added

        """
        keyword_set: Set[str] = set()
        for i in keyword_list:
            if 3 <= len(i):
                keyword_set.add(i)
        self.__keyword_list = list(keyword_set)
