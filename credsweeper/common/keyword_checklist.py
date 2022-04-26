import os
from typing import List

from credsweeper.common.constants import DEFAULT_ENCODING


class KeywordChecklist:
    __keyword_list: List[str] = []

    def __init__(self) -> None:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path, "keyword_checklist.txt"), "r", encoding=DEFAULT_ENCODING) as f:
            self.set_list(f.read().splitlines())

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
        self.__keyword_list = keyword_list
