from typing import Optional

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter


class ValueSealedSecretCheck(Filter):
    """
    Check that candidate may be a sealed secret
    https://github.com/bitnami-labs/sealed-secrets/blob/main/docs/developer/crypto.md
    """
    MAX_SEARCH_MARGIN = 100

    def __init__(self, config: Optional[Config] = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received value and check context for sealed secret markers.
        Can be applied effective for plain scan when the value is full and the target has lines around.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """

        if (value := line_data.value) and (value.startswith('Ag') and 700 < len(value) and 'A' <= value[2] <= 'D'
                                           or value.startswith('AQ') and 350 < len(value) and 'A' <= value[2] <= 'D'):
            from_line = max(0, line_data.line_pos - ValueSealedSecretCheck.MAX_SEARCH_MARGIN)
            to_line = min(len(target.lines), line_data.line_pos + ValueSealedSecretCheck.MAX_SEARCH_MARGIN)
            sealed_secret_marker = encrypted_data_marker = bitnami_marker = False
            for line in target.lines[from_line:to_line]:
                if not sealed_secret_marker and 0 <= line.find("SealedSecret", 0, MAX_LINE_LENGTH):
                    sealed_secret_marker = True
                if not encrypted_data_marker and 0 <= line.find("encryptedData", 0, MAX_LINE_LENGTH):
                    encrypted_data_marker = True
                if not bitnami_marker and 0 <= line.find("bitnami", 0, MAX_LINE_LENGTH):
                    bitnami_marker = True
                if sealed_secret_marker and encrypted_data_marker and bitnami_marker:
                    return True
        return False
