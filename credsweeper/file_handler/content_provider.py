import logging
from abc import ABC, abstractmethod
from functools import cached_property
from typing import List, Optional, Generator

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.utils import Util

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
    def yield_analysis_target(self) -> Generator[AnalysisTarget, None, None]:
        """Load and preprocess file diff data to scan.

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

    @property
    @abstractmethod
    def data(self) -> Optional[bytes]:
        """abstract data getter"""
        raise NotImplementedError(__name__)

    @data.setter
    @abstractmethod
    def data(self, data: Optional[bytes]) -> None:
        """abstract data setter"""
        raise NotImplementedError(__name__)

    def lines_to_targets(
            self,  #
            lines: List[str],  #
            line_nums: Optional[List[int]] = None) -> Generator[AnalysisTarget, None, None]:
        """Creates list of targets with multiline concatenation"""
        if line_nums and len(line_nums) == len(lines):
            for line_pos in range(len(lines)):
                target = AnalysisTarget(line_pos, lines, line_nums, self.descriptor)
                yield target
        else:
            if line_nums and len(line_nums) != len(lines):
                logger.warning(f"line numerations {len(line_nums)} does not match lines {len(lines)}")
            _line_nums = [x + 1 for x in range(len(lines))]
            for line_pos in range(len(lines)):
                target = AnalysisTarget(line_pos, lines, _line_nums, self.descriptor)
                yield target
