import contextlib

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueDiscordBotCheck(Filter):
    """Discord bot Token"""

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        with contextlib.suppress(Exception):
            # . must be in value according regex
            dot_separator_index = line_data.value.index('.')
            id_part = line_data.value[:dot_separator_index]
            if int(Util.decode_base64(id_part, padding_safe=True, urlsafe_detect=True)):
                return False
        return True
