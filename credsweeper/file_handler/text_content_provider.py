import io
import logging
from pathlib import Path
from typing import List, Optional, Union, Tuple, Generator

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils import Util

logger = logging.getLogger(__name__)


class TextContentProvider(ContentProvider):
    """Provide access to analysis targets for full-text file scanning.

    Parameters:
        file_path: string, path to file

    """

    def __init__(self,
                 file_path: Union[str, Path, Tuple[Union[str, Path], io.BytesIO]],
                 file_type: Optional[str] = None,
                 info: Optional[str] = None) -> None:
        _path = str(file_path[0]) if isinstance(file_path, tuple) else str(file_path)
        self.__io = file_path[1] if isinstance(file_path, tuple) else None
        self.__data: Optional[bytes] = None
        self.__lines: Optional[List[str]] = None
        super().__init__(file_path=_path, file_type=file_type, info=info)

    @property
    def data(self) -> Optional[bytes]:
        """data getter for TextContentProvider"""
        if self.__data is None:
            if isinstance(self.__io, io.BytesIO) and self.__io:
                self.__data = self.__io.read()
            else:
                self.__data = Util.read_data(self.file_path)
        return self.__data

    @data.setter
    def data(self, data: Optional[bytes]) -> None:
        """data setter for TextContentProvider"""
        self.__data = data

    @property
    def lines(self) -> Optional[List[str]]:
        """lines getter for TextContentProvider"""
        if self.__lines is None:
            self.__lines = Util.decode_bytes(self.data)
        return self.__lines if self.__lines is not None else []

    @lines.setter
    def lines(self, lines: Optional[List[str]]) -> None:
        """lines setter for TextContentProvider"""
        self.__lines = lines

    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Load and preprocess file content to scan.

        Args:
            min_len: minimal line length to scan

        Return:
            list of analysis targets based on every row in file

        """
        lines: Optional[List[str]] = None
        line_nums: Optional[List[int]] = None

        if Util.get_extension(self.file_path) == ".xml":
            try:
                # append line ending for correct xml line numeration
                xml_lines = [f"{line}\n" for line in self.lines]
                lines, line_nums = Util.get_xml_from_lines(xml_lines)
            except Exception as exc:
                logger.error(f"Cannot parse to xml {exc}")

        if lines is None:
            lines = self.lines

        return self.lines_to_targets(min_len, lines, line_nums)
