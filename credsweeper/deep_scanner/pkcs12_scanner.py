import logging
from abc import ABC
from typing import List

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
            recursive_limit_size: int) -> List[Candidate]:
        """Tries to scan PKCS12 to open with standard password"""
        candidates = []
        for pw_probe in [b"", b"changeit", b"changeme"]:
            try:
                (private_key, certificate, additional_certificates) \
                    = cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates(data_provider.data,
                                                                                                    pw_probe)
                if private_key:
                    candidate = Candidate.get_dummy_candidate(
                        self.config,  #
                        data_provider.file_path,  #
                        data_provider.file_type,  #
                        f"{data_provider.info}:'{pw_probe.decode()}' - has keys PKCS12")
                else:
                    candidate = Candidate.get_dummy_candidate(
                        self.config,  #
                        data_provider.file_path,  #
                        data_provider.file_type,  #
                        f"{data_provider.info}:'{pw_probe.decode()}' - default password PKCS12")
                candidates.append(candidate)
            except Exception as pkcs_exc:
                logger.debug(f"{data_provider.file_path}:{pw_probe.decode()}:{pkcs_exc}")
        return candidates
