from abc import abstractmethod, ABC
from typing import List

from credsweeper.config import Config
from credsweeper.credentials import Candidate
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider
from credsweeper.scanner import Scanner


class AbstractScanner(ABC):
    """Base abstract class for all recursive scanners"""

    @property
    @abstractmethod
    def config(self) -> Config:
        """Abstract property to be defined in DeepScanner"""
        raise NotImplementedError(__name__)

    @property
    @abstractmethod
    def scanner(self) -> Scanner:
        """Abstract property to be defined in DeepScanner"""
        raise NotImplementedError(__name__)

    @abstractmethod
    def recursive_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int = 0,  #
            recursive_limit_size: int = 0) -> List[Candidate]:
        """Abstract method to be defined in DeepScanner"""
        raise NotImplementedError(__name__)

    @abstractmethod
    def structure_scan(
            self,  #
            struct_provider: StructContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Abstract method to be defined in DeepScanner"""
        raise NotImplementedError(__name__)
