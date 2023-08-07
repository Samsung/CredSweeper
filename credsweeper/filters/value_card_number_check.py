from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueCardNumberCheck(Filter):
    """Check that value is a credit card number."""

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            False, if the sequence is not card number. True if it is

        """
        if line_data.value is None \
                or 16 != len(line_data.value) \
                or line_data.value.startswith("00"):
            return True
        try:
            s = 0
            # https://en.wikipedia.org/wiki/Luhn_algorithm
            for n in range(0, 16):
                x = int(line_data.value[n])
                if 0 == (1 & n):  # Only for odd numbers (with 0 as a start index)
                    x *= 2
                    if x > 9:
                        x -= 9
                s += x

            if 0 == s % 10:
                return False
        except ValueError:
            pass

        # return False when the sequence is not a credit card number
        return True
