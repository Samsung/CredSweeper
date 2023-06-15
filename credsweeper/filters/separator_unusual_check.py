from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class SeparatorUnusualCheck(Filter):
    """Check that candidate have no double symbol ops (like ++, --, <<) or comparison ops (like != or ==) as separator.

    Example:
        `pwd == 'value'`
        `pwd != 'value'`
        `pwd << value`

    """

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received credential candidate data 'line_data'.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """
        if line_data.separator is None:
            return True

        try:
            separator_idx = line_data.separator_span[0]
            if line_data.separator == line_data.line[separator_idx + 1] or \
                    (line_data.separator == "=" and line_data.line[separator_idx - 1] == "!"):
                return True
        except IndexError:
            return True

        return False
