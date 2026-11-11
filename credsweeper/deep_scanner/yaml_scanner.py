import logging
from abc import ABC
from typing import List, Optional

import yaml

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider
from credsweeper.logger import TRACE

logger = logging.getLogger(__name__)


class YamlScanner(AbstractScanner, ABC):
    """Implements scanning of data if it is YAML"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """Applied in represent_as_structure"""
        if 0 < data.find(b':', 0, MAX_LINE_LENGTH) or 0 <= data.find(b"!!", 0, MAX_LINE_LENGTH) \
                or 2 < data.count(b'\n', 0, MAX_LINE_LENGTH):
            return True
        return False

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Tries to represent data as markup language and scan as structure"""
        try:
            structure = yaml.safe_load(data_provider.text)
            if isinstance(structure, (bytes, dict, list, set)):
                # simple data may be scanned as plain text
                struct_data_provider = StructContentProvider(struct=structure,
                                                             file_path=data_provider.file_path,
                                                             file_type=data_provider.file_type,
                                                             info=f"{data_provider.info}|YAML")
                new_limit = recursive_limit_size - len(data_provider.data)
                candidates = self.structure_scan(struct_data_provider, depth, new_limit)
                return candidates
        except yaml.error.YAMLError as yaml_exc:
            logger.log(TRACE, "Cannot parse as yaml %s %s", yaml_exc, data_provider.descriptor)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # fallback
            logger.warning("Cannot parse as yaml %s:%s %s", type(exc), exc, data_provider.descriptor)
        return None
