import logging
from abc import ABC
from typing import List

import jks

from credsweeper.credentials import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class JksScanner(AbstractScanner, ABC):
    """Implements jks scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> List[Candidate]:
        """Tries to scan JKS to open with standard password"""
        candidates = []
        for pw_probe in ["", "changeit", "changeme"]:
            try:
                keystore = jks.KeyStore.loads(data_provider.data, pw_probe, try_decrypt_keys=True)
                if keystore.private_keys or keystore.secret_keys:
                    candidate = Candidate.get_dummy_candidate(self.config, data_provider.file_path,
                                                              data_provider.file_type,
                                                              f"{data_provider.info}:'{pw_probe}' - has keys")
                else:
                    candidate = Candidate.get_dummy_candidate(self.config, data_provider.file_path,
                                                              data_provider.file_type,
                                                              f"{data_provider.info}:'{pw_probe}' - default password")
                candidates.append(candidate)
            except Exception as jks_exc:
                logger.debug(f"{data_provider.file_path}:{pw_probe}:{jks_exc}")
        return candidates
