import contextlib
from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.filters.value_entropy_base64_check import ValueEntropyBase64Check
from credsweeper.utils.util import Util


class ValueDiscordBotCheck(Filter):
    """Discord bot Token"""

    def __init__(self, config: Optional[Config] = None) -> None:
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
            discord_id = int(Util.decode_base64(id_part, padding_safe=True, urlsafe_detect=True))
            entropy_part = line_data.value[dot_separator_index:]
            entropy = Util.get_shannon_entropy(entropy_part)
            min_entropy = ValueEntropyBase64Check.get_min_data_entropy(len(entropy_part))
            if 1000 <= discord_id and min_entropy <= entropy:
                return False
        return True
