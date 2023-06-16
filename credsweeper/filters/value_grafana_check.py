import base64
import contextlib
import json

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter


class ValueGrafanaCheck(Filter):
    """Grafana Provisioned API Key and Access Policy Token"""

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
        if not line_data.value:
            return True
        with contextlib.suppress(Exception):
            if line_data.value.startswith("glc_"):
                # Grafana Access Policy Token
                decoded = base64.b64decode(line_data.value[4:])
                keys = ["o", "n", "k", "m"]
            else:
                # Grafana Provisioned API Key
                decoded = base64.b64decode(line_data.value)
                keys = ["n", "k", "id"]
            if payload := json.loads(decoded):
                for key in keys:
                    if key not in payload:
                        return True
                return False
        return True
