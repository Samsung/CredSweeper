import logging
from abc import ABC
from typing import List, Optional

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
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan JKS to open with standard password"""
        candidates = []
        for pw_probe in self.config.bruteforce_list:
            try:
                keystore = jks.KeyStore.loads(data_provider.data, pw_probe, try_decrypt_keys=True)
                # the password probe has passed, it will be the value
                info = (f"{data_provider.info}|JKS:"
                        f"{'sensitive data' if keystore.private_keys or keystore.secret_keys else 'default password'}")
                candidate = Candidate.get_dummy_candidate(
                    self.config,  #
                    data_provider.file_path,  #
                    data_provider.file_type,  #
                    info,  #
                    "Java Key Storage")
                value = pw_probe or "<EMPTY PASSWORD>"
                candidate.line_data_list[0].line = f"'{value}' is the password"
                candidate.line_data_list[0].value = pw_probe or "<EMPTY PASSWORD>"
                candidate.line_data_list[0].value_start = 1
                candidate.line_data_list[0].value_end = 1 + len(candidate.line_data_list[0].value)
                candidates.append(candidate)
                break
            except Exception as jks_exc:
                logger.debug(f"{data_provider.file_path}:{pw_probe}:{jks_exc}")
        return candidates
