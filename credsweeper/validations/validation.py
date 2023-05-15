from abc import ABC, abstractmethod
from typing import List

from credsweeper.common.constants import KeyValidationOption
from credsweeper.credentials.line_data import LineData


class Validation(ABC):
    """Abstract class for verify method"""

    @classmethod
    @abstractmethod
    def verify(cls, line_data_list: List[LineData]) -> KeyValidationOption:
        """Verify line_data_list with external API.

        Args:
            line_data_list: List of LineData objects, data in current credential candidate

        Return:
            Enum object, returns the validation status for the passed value
            can take values: VALIDATED_KEY, INVALID_KEY or UNDECIDED

        """
        raise NotImplementedError()
