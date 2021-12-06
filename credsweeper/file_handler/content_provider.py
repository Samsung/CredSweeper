from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from credsweeper.file_handler.analysis_target import AnalysisTarget


class ContentProvider(ABC):
    """Base class to provide access to analysis targets for scanned object"""
    @abstractmethod
    def __init__(self,
                 file_path: str,
                 change_type: Optional[str] = None,
                 diff: Optional[List[Dict]] = None) -> None:
        raise NotImplementedError()

    def get_file_path(self) -> str:
        return self.file_path

    @abstractmethod
    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Load and preprocess file diff data to scan

        Return:
            list of AnalysisTarget, row objects to analyse"""
        raise NotImplementedError()
