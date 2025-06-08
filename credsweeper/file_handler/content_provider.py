import logging
from abc import ABC, abstractmethod
from functools import cached_property
from typing import List, Optional, Generator

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class ContentProvider(ABC):
    """Base class to provide access to analysis targets for scanned object."""

    def __init__(
            self,  #
            file_path: Optional[str] = None,  #
            file_type: Optional[str] = None,  #
            info: Optional[str] = None) -> None:
        """
        Parameters:
            file_path: optional string. Might be specified if you know the file name where data were taken from.
            file_type: optional string. File extension e.g. ".java". It might be obtained from file_path if not given.
            info: optional string. Any information to help understand how a credential was found.

        """
        _file_path: str = file_path or ""
        _file_type: str = file_type if file_type is not None else Util.get_extension(file_path)
        _info: str = info or ""
        self.__descriptor = Descriptor(_file_path, _file_type, _info)

    @abstractmethod
    def yield_analysis_target(self, min_len: int) -> Generator[AnalysisTarget, None, None]:
        """Load and preprocess file diff data to scan.

        Args:
            min_len: minimal line length to scan

        Return:
            row objects to analysing

        """
        raise NotImplementedError()

    @cached_property
    def descriptor(self) -> Descriptor:
        """descriptor getter"""
        return self.__descriptor

    @cached_property
    def file_path(self) -> str:
        """file_path getter"""
        return self.__descriptor.path

    @cached_property
    def file_type(self) -> str:
        """file_type getter"""
        return self.__descriptor.extension

    @cached_property
    def info(self) -> str:
        """info getter"""
        return self.__descriptor.info

    @cached_property
    @abstractmethod
    def data(self) -> Optional[bytes]:
        """abstract data getter"""
        raise NotImplementedError(__name__)

    @abstractmethod
    def free(self) -> None:
        """free data after scan to reduce memory usage"""
        raise NotImplementedError(__name__)

    def lines_to_targets(
            self,  #
            min_len: int,
            lines: List[str],  #
            line_nums: Optional[List[int]] = None) -> Generator[AnalysisTarget, None, None]:
        """Creates list of targets with multiline concatenation"""
        lines_range = range(len(lines))
        if line_nums is None or len(line_nums) != len(lines):
            if line_nums is not None:
                logger.warning(
                    f"line numerations {len(line_nums)} does not match lines {len(lines)}. Plain numeration applied")
            line_nums = [1 + x for x in lines_range]

        for line_pos in lines_range:
            line = lines[line_pos]
            if min_len > len(line.strip()):
                # Ignore target if stripped part is too short for all types
                continue
            if MAX_LINE_LENGTH < len(line):
                for chunk_start, chunk_end in Util.get_chunks(len(line)):
                    target = AnalysisTarget(
                        line_pos=line_pos,  #
                        lines=lines,  #
                        line_nums=line_nums,  #
                        descriptor=self.descriptor,  #
                        line=line[chunk_start:chunk_end],  #
                        offset=chunk_start)
                    yield target
            else:
                target = AnalysisTarget(line_pos, lines, line_nums, self.descriptor)
                yield target
