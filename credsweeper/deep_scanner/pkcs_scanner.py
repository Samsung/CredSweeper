import base64
import logging
from abc import ABC
from typing import List, Optional

from credsweeper.common.constants import Severity, Confidence
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.utils.util import Util

logger = logging.getLogger(__name__)


class PkcsScanner(AbstractScanner, ABC):
    """Implements pkcs12 scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan PKCS12 to open with standard password"""
        for pw_probe in self.config.bruteforce_list:
            try:
                password = pw_probe.encode() if pw_probe else None
                if pkey := Util.load_pk(data_provider.data, password):
                    if not Util.check_pk(pkey):
                        logger.debug("False alarm %s", data_provider.info)
                        return []
                    candidate = Candidate.get_dummy_candidate(
                        self.config,  #
                        data_provider.file_path,  #
                        data_provider.file_type,  #
                        info=f"{data_provider.info}|PKCS_PASSWORD:{repr(password)}",  #
                        rule_name=f"PKCS with password {repr(pw_probe)}" if pw_probe else "PKCS without password")
                    candidate.line_data_list[0].line = base64.b64encode(data_provider.data).decode()
                    candidate.line_data_list[0].value = repr(password)
                    # high severity is assigned to private key rules
                    candidate.severity = Severity.HIGH
                    candidate.confidence = Confidence.STRONG
                    return [candidate]
            except Exception as pkcs_exc:
                logger.debug(f"{data_provider.file_path}:{pw_probe}:{pkcs_exc}")
        return None
