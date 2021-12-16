from abc import abstractmethod

from credsweeper.credentials import LineData


class Filter:
    """Base class for all filters that operates on 'line_data' objects."""

    @abstractmethod
    def run(self, line_data: LineData) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data

        Return:
            True, if need to filter candidate and False if left

        """
        raise NotImplementedError()
