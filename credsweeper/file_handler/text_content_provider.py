import io
import logging
from functools import cached_property
from pathlib import Path
from typing import List, Optional, Union, Tuple, Generator

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.content_provider import ContentProvider
from credsweeper.utils.util import Util

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

    @cached_property
    def data(self) -> Optional[bytes]:
        """data RO getter for TextContentProvider"""
        if self.__data is None:
            if isinstance(self.__io, io.BytesIO) and self.__io:
                self.__data = self.__io.read()
            else:
                self.__data = Util.read_data(self.file_path)
        return self.__data

    def free(self) -> None:
        """free data after scan to reduce memory usage"""
        self.__data = None
        if "data" in self.__dict__:
            delattr(self, "data")
        self.__lines = None
        if "lines" in self.__dict__:
            delattr(self, "lines")
        if isinstance(self.__io, io.BytesIO) and self.__io and not self.__io.closed:
            self.__io.close()

    @cached_property
    def lines(self) -> Optional[List[str]]:
        """lines getter for TextContentProvider"""
        if self.__lines is None:
            text = Util.decode_text(self.data)
            if text is None:
                logger.warning("Binary file detected %s %s %s", self.file_path, self.info,
                               repr(self.__data[:32]) if isinstance(self.__data, bytes) else "NONE")
                self.__lines = []
            else:
                self.__lines = Util.split_text(text)
        return self.__lines if self.__lines is not None else []

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
