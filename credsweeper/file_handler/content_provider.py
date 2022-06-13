from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from credsweeper.file_handler.analysis_target import AnalysisTarget


class ContentProvider(ABC):
    """Base class to provide access to analysis targets for scanned object."""

    file_path: str = NotImplemented
    change_type: Optional[str] = NotImplemented
    diff: Optional[List[Dict]] = NotImplemented

    @abstractmethod
    def __init__(self) -> None:
        raise NotImplementedError()

    @abstractmethod
    def get_analysis_target(self) -> List[AnalysisTarget]:
        """Load and preprocess file diff data to scan.

        Return:
            row objects to analysing

        """
        raise NotImplementedError()
