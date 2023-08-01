import contextlib

from schwifty import IBAN
from schwifty.exceptions import SchwiftyException

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueIbanCheck(Filter):
    """Check that value is an IBAN"""

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if the sequence has to be filtered

        """
        if line_data.value is None:
            return True

        with contextlib.suppress(SchwiftyException):
            # https://en.wikipedia.org/wiki/International_Bank_Account_Number
            if IBAN(line_data.value):
                # Correctly parsed and recognized
                return False

        # return TRUE when the sequence is not an IBAN
        return True
