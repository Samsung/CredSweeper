import base64
import logging
import struct
from abc import ABC
from typing import List, Optional, Callable

from credsweeper.common.constants import Severity, Confidence, ASCII
from credsweeper.credentials.candidate import Candidate
from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider

logger = logging.getLogger(__name__)


class SnkScanner(AbstractScanner, ABC):
    """Implements Snk files scanning"""

    @staticmethod
    def match(data: bytes | bytearray) -> bool:
        """https://github.com/dotnet/runtime/blob/main/docs/project/strong-name-signing.md"""
        if data.startswith(b"\x07\x02\x00\x00\x00$\x00\x00RSA2"):
            return True
        return False

    @staticmethod
    def extract(data: bytes) -> None | str:
        """Extracts RSA parameters from .snk file and transform they into JWK representation

        Args:
            data: content of .snk file

        Return:
            JWK string if successful format recognized or None if fail
        """
        bit_len = struct.unpack_from("<I", data, offset=12)[0]
        if 0xF & bit_len or not 64 <= bit_len <= 65536:
            logger.warning("Wrong bits length %d", bit_len)
            return None
        o_size = bit_len // 8
        h_size = bit_len // 16
        offset = 20
        components_size = 9 * h_size
        if len(data) != offset + components_size:
            logger.warning("Components size %d mismatches buffer %d", components_size, len(data))
            return None
        _pub_exp = data[16:offset]
        pub_exp = struct.unpack_from("<I", _pub_exp)[0]

        _modulus = data[offset:offset + o_size]
        offset += o_size
        modulus = int.from_bytes(_modulus, byteorder="little", signed=False)

        _prime1 = data[offset:offset + h_size]
        offset += h_size
        prime1 = int.from_bytes(_prime1, byteorder="little", signed=False)

        _prime2 = data[offset:offset + h_size]
        offset += h_size
        prime2 = int.from_bytes(_prime2, byteorder="little", signed=False)

        _exponent1 = data[offset:offset + h_size]
        offset += h_size
        exponent1 = int.from_bytes(_exponent1, byteorder="little", signed=False)

        _exponent2 = data[offset:offset + h_size]
        offset += h_size
        exponent2 = int.from_bytes(_exponent2, byteorder="little", signed=False)

        _coefficient = data[offset:offset + h_size]
        offset += h_size
        coefficient = int.from_bytes(_coefficient, byteorder="little", signed=False)

        _private_exponent = data[offset:offset + o_size]
        private_exponent = int.from_bytes(_private_exponent, byteorder="little", signed=False)

        # simple mutual check
        if modulus == prime1 * prime2 \
                and (phi := (prime1 - 1) * (prime2 - 1)) \
                and 1 == (pub_exp * private_exponent) % phi \
                and exponent1 == private_exponent % (prime1 - 1) \
                and exponent2 == private_exponent % (prime2 - 1) \
                and 1 == (coefficient * prime2) % prime1:
            # JWK representation
            __bytes4jwk: Callable[[bytes], str] = \
                lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode(ASCII, errors="strict")
            return (f'{{"kty":"RSA","e":"{__bytes4jwk(_pub_exp)}",'
                    f'"n":"{__bytes4jwk(_modulus)}","d":"{__bytes4jwk(_private_exponent)}",'
                    f'"p":"{__bytes4jwk(_prime1)}","q":"{__bytes4jwk(_prime2)}",'
                    f'"dp":"{__bytes4jwk(_exponent1)}","dq":"{__bytes4jwk(_exponent2)}",'
                    f'"qi":"{__bytes4jwk(_coefficient)}"}}')

        logger.warning("Components consistency check fail")
        return None

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Scan .snk data for full (private+public) keys"""
        try:
            if value := SnkScanner.extract(data_provider.data):
                # RSA key components are consistent
                candidate = Candidate.get_dummy_candidate(
                    self.config,  #
                    data_provider.file_path,  #
                    data_provider.file_type,  #
                    f"{data_provider.info}|SNK",  #
                    "Strong Name Key")
                candidate.severity = Severity.HIGH
                candidate.confidence = Confidence.STRONG
                candidate.line_data_list[0].line = candidate.line_data_list[0].value = value
                candidate.line_data_list[0].value_start = 0
                candidate.line_data_list[0].value_end = len(value)
                return [candidate]
        except Exception as exc:
            logger.warning(exc)
        return None
