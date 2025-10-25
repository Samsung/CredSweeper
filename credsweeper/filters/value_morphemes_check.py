from typing import Optional

from credsweeper.common import static_keyword_checklist
from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueMorphemesCheck(Filter):
    """Check value for a threshold of morphemes count"""

    THRESHOLDS_X3 = int(MAX_LINE_LENGTH).bit_length()
    # one morpheme is very likely to be random generated even for 3 symbols
    MAX_MORPHEMES_LIMIT = max(1, THRESHOLDS_X3 - 4)

    def __init__(self, config: Optional[Config] = None, threshold: Optional[int] = None) -> None:
        # threshold - minimum morphemes number in a value
        if threshold is None:
            # use dynamic thresholds
            self.thresholds = [max(1, x - 4) for x in range(ValueMorphemesCheck.THRESHOLDS_X3)]
        elif isinstance(threshold, int) and 0 <= threshold:
            # constant thresholds for any pattern
            self.thresholds = [threshold] * ValueMorphemesCheck.THRESHOLDS_X3
        else:
            raise ValueError(f"Wrong type of pattern length {type(threshold)} = {repr(threshold)}")

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        threshold_id = len(line_data.value).bit_length()
        # use the last (max) threshold in very huge value
        threshold = self.thresholds[threshold_id] if len(self.thresholds) > threshold_id else self.thresholds[-1]
        return static_keyword_checklist.check_morphemes(line_data.value.lower(), threshold)
