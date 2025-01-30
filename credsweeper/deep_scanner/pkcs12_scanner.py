import logging
from abc import ABC
from typing import List, Optional

import cryptography.hazmat.primitives.serialization.pkcs12

from credsweeper.credentials import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class Pkcs12Scanner(AbstractScanner, ABC):
    """Implements pkcs12 scanning"""

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to scan PKCS12 to open with standard password"""
        candidates = []
        for pw_probe in self.config.bruteforce_list:
            try:
                (private_key, certificate, additional_certificates) \
                    = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(data_provider.data,
                                                                                                    pw_probe.encode())
                # the password probe has passed, it will be the value
                value = pw_probe or "<EMPTY PASSWORD>"
                info = (f"{data_provider.info}|PKCS12:"
                        f"'{value}' {'sensitive data' if private_key else 'default password'}")
                candidate = Candidate.get_dummy_candidate(
                    self.config,  #
                    data_provider.file_path,  #
                    data_provider.file_type,  #
                    info,  #
                    "PKCS12")
                candidate.line_data_list[0].line = f"'{value}' is the password"
                candidate.line_data_list[0].value = value
                candidate.line_data_list[0].value_start = 1
                candidate.line_data_list[0].value_end = 1 + len(candidate.line_data_list[0].value)
                candidates.append(candidate)
                break
            except Exception as pkcs_exc:
                logger.debug(f"{data_provider.file_path}:{pw_probe}:{pkcs_exc}")
        return candidates
