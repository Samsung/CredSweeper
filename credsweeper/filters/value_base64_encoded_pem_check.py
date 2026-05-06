import logging
from typing import Optional

from credsweeper.common.constants import ASCII, PEM_BEGIN_PATTERN, MAX_LINE_LENGTH, PEM_END_PATTERN
from credsweeper.config.config import Config
from credsweeper.credentials.line_data import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters.filter import Filter
from credsweeper.utils.pem_key_detector import PemKeyDetector
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class ValueBase64EncodedPem(Filter):
    """Check that candidate contains base64 encoded pem private key"""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, if need to filter candidate and False if left

        """

        try:
            text = Util.decode_base64(line_data.value, padding_safe=True, urlsafe_detect=True).decode(ASCII)
            pem_text = ''
            pem_end_found = False
            for line in text.splitlines():
                if pem_text:
                    pem_text += f"\n{line}"
                    if PEM_END_PATTERN in line:
                        pem_end_found = True
                else:
                    if PEM_BEGIN_PATTERN in line:
                        if PemKeyDetector.RE_PEM_BEGIN.search(line, 0, MAX_LINE_LENGTH):
                            pem_text = line
                            if PEM_END_PATTERN in line:
                                pem_end_found = True
                if pem_end_found:
                    new_target = AnalysisTarget(0, [pem_text], [1], target.descriptor)
                    first_line = LineData(self.config, pem_text, 0, 1, target.file_path, target.file_type, target.info,
                                          PemKeyDetector.RE_PEM_BEGIN)
                    if PemKeyDetector(self.config).detect_pem_key(first_line, new_target):
                        # obtained candidates are not used because not match text
                        return False
                    # drop the candidate and continue search
                    pem_text = ''
                    pem_end_found = False
        except Exception as exc:
            logger.warning(exc)
        return True
