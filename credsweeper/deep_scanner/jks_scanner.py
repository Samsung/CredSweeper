import logging
from abc import ABC
from typing import List, Optional

import jks

from credsweeper.common.constants import Severity, Confidence
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class JksScanner(AbstractScanner, ABC):
    """Implements jks scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan JKS to open with standard password"""
        for pw_probe in self.config.bruteforce_list:
            value = repr(pw_probe)
            try:
                keystore = jks.KeyStore.loads(data_provider.data, pw_probe, try_decrypt_keys=True)
                # the password probe has passed, it will be the value
                if keystore.private_keys or keystore.secret_keys:
                    severity = Severity.HIGH
                    confidence = Confidence.STRONG
                    info = f"{data_provider.info}|JKS:default password"
                    rule_name = f"JKS private key with password {value}"
                else:
                    severity = Severity.LOW
                    confidence = Confidence.WEAK
                    info = f"{data_provider.info}|JKS:sensitive data"
                    rule_name = f"JKS sensitive data with password {value}"
                candidate = Candidate.get_dummy_candidate(
                    self.config,  #
                    data_provider.file_path,  #
                    data_provider.file_type,  #
                    info,  #
                    rule_name)
                candidate.severity = severity
                candidate.confidence = confidence
                candidate.line_data_list[0].line = candidate.line_data_list[0].value = value
                candidate.line_data_list[0].value_start = 0
                candidate.line_data_list[0].value_end = len(value)
                return [candidate]
            except Exception as jks_exc:
                logger.debug(f"{data_provider.file_path}:{pw_probe}:{jks_exc}")
        return None
