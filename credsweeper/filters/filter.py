from abc import abstractmethod

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget


class Filter:
    """Base class for all filters that operates on 'line_data' objects."""

    @abstractmethod
    def __init__(self, config: Config):
        raise NotImplementedError()

    @abstractmethod
    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        raise NotImplementedError()
