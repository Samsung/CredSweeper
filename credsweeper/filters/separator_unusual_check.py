import logging

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter

logger = logging.getLogger(__name__)


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

        if 1 > line_data.separator_start:
            logger.warning(f"Wrong separator start position {line_data}")
            return True

        try:
            if line_data.separator == line_data.line[line_data.separator_start + 1] or \
                    (line_data.separator == "=" and line_data.line[line_data.separator_start - 1] == "!"):
                return True
        except IndexError:
            return True

        return False
