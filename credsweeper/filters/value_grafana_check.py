import contextlib
import json
from typing import Optional

from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.utils.util import Util


class ValueGrafanaCheck(Filter):
    """Grafana Provisioned API Key and Access Policy Token"""

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
            if line_data.value.startswith("glc_"):
                # Grafana Access Policy Token
                decoded = Util.decode_base64(line_data.value[4:], padding_safe=True, urlsafe_detect=True)
                keys = ["o", "n", "k", "m"]
            else:
                # Grafana Provisioned API Key
                decoded = Util.decode_base64(line_data.value, padding_safe=True, urlsafe_detect=True)
                keys = ["n", "k", "id"]
            if payload := json.loads(decoded):
                for key in keys:
                    if key not in payload:
                        return True
                return False
        return True
