import logging
from typing import List, Optional

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import Util

logger = logging.getLogger(__name__)


class TextContentProvider(ContentProvider):
    """Provide access to analysis targets for full-text file scanning.

    Parameters:
        file_path: string, path to file

    """

    def __init__(
            self,
            file_path: str,  #
            file_type: Optional[str] = None,  #
            info: Optional[str] = None) -> None:
        super().__init__(file_path=file_path, file_type=file_type, info=info)
        self.__data: Optional[bytes] = None
        self.__lines: Optional[List[str]] = None

    @property
    def data(self) -> Optional[bytes]:
        """data getter"""
        if not self.__data:
            self.__data = Util.read_data(self.file_path)
        return self.__data

    @data.setter
    def data(self, data: Optional[bytes]) -> None:
        """data setter"""
        self.__data = data

    @property
    def lines(self) -> List[str]:
        """data getter"""
        if self.__lines is None:
            self.__lines = Util.decode_bytes(self.data)
        return self.__lines if self.__lines is not None else []

    @lines.setter
    def lines(self, lines: List[str]) -> None:
        """data setter"""
        self.__lines = lines

    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Load and preprocess file content to scan.

        Return:
            list of analysis targets based on every row in file

        """
        lines: Optional[List[str]] = None
        line_nums: List[int] = []

        if Util.get_extension(self.file_path) == ".xml":
            try:
                # append line ending for correct xml line numeration
                xml_lines = [f"{line}\n" for line in self.lines]
                lines, line_nums = Util.get_xml_from_lines(xml_lines)
            except Exception as exc:
                logger.error(f"Cannot parse to xml {exc}")

        if lines is None:
            lines = self.lines

        return self.lines_to_targets(lines, line_nums)
