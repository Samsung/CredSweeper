import contextlib

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueVinCheck(Filter):
    """Check that value is a VIN"""
    WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
    TRANSLITERATIONS = {
        "0": 0,
        "1": 1,
        "2": 2,
        "3": 3,
        "4": 4,
        "5": 5,
        "6": 6,
        "7": 7,
        "8": 8,
        "9": 9,
        "A": 1,
        "B": 2,
        "C": 3,
        "D": 4,
        "E": 5,
        "F": 6,
        "G": 7,
        "H": 8,
        "J": 1,
        "K": 2,
        "L": 3,
        "M": 4,
        "N": 5,
        "P": 7,
        "R": 9,
        "S": 2,
        "T": 3,
        "U": 4,
        "V": 5,
        "W": 6,
        "X": 7,
        "Y": 8,
        "Z": 9,
    }

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
        if line_data.value is None or 17 != len(line_data.value):
            return True

        with contextlib.suppress(Exception):
            int(line_data.value)
            return True

        # NHTSA (National Highway Traffic Safety Administration)
        # https://en.wikipedia.org/wiki/Vehicle_identification_number
        with contextlib.suppress(Exception):
            s = 0
            for w, v in zip(ValueVinCheck.WEIGHTS, line_data.value):
                s += w * ValueVinCheck.TRANSLITERATIONS[v]
            r = s % 11
            c = line_data.value[8]
            if "X" == c and 10 == r:
                return False
            elif ValueVinCheck.TRANSLITERATIONS[c] == r:
                return False

        # return False when the sequence has wrong check digit
        return True
