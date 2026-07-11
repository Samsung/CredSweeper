import base64
import logging
import struct
from abc import ABC
from typing import List, Optional

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

    def data_scan(
            self,  #
            data_provider: DataContentProvider,  #
            depth: int,  #
            recursive_limit_size: int) -> Optional[List[Candidate]]:
        """Scan .snk data for full (private+public) keys"""
        try:
            bit_len = struct.unpack_from("<I", data_provider.data, offset=12)[0]
            if 0xF & bit_len or not 16 < bit_len < 32768:
                raise ValueError(f"Wrong bits length ({bit_len})")
            o_size = bit_len // 8
            h_size = bit_len // 16
            offset = 20
            components_size = 9 * h_size
            if offset + components_size > len(data_provider.data):
                raise ValueError(f"Components size ({components_size}) is over buffer (len(data_provider.data))")
            _pub_exp = data_provider.data[16:offset]
            pub_exp = struct.unpack_from("<I", _pub_exp)[0]

            _modulus = data_provider.data[offset:offset + o_size]
            offset += o_size
            modulus = int.from_bytes(_modulus, byteorder="little", signed=False)

            _prime1 = data_provider.data[offset:offset + h_size]
            offset += h_size
            prime1 = int.from_bytes(_prime1, byteorder="little", signed=False)

            _prime2 = data_provider.data[offset:offset + h_size]
            offset += h_size
            prime2 = int.from_bytes(_prime2, byteorder="little", signed=False)

            _exponent1 = data_provider.data[offset:offset + h_size]
            offset += h_size
            exponent1 = int.from_bytes(_exponent1, byteorder="little", signed=False)

            _exponent2 = data_provider.data[offset:offset + h_size]
            offset += h_size
            exponent2 = int.from_bytes(_exponent2, byteorder="little", signed=False)

            _coefficient = data_provider.data[offset:offset + h_size]
            offset += h_size
            coefficient = int.from_bytes(_coefficient, byteorder="little", signed=False)

            _private_exponent = data_provider.data[offset:offset + o_size]
            private_exponent = int.from_bytes(_private_exponent, byteorder="little", signed=False)

            # simple mutual check
            if modulus == prime1 * prime2 \
                    and (phi := (prime1 - 1) * (prime2 - 1)) \
                    and 1 == (pub_exp * private_exponent) % phi \
                    and exponent1 == private_exponent % (prime1 - 1) \
                    and exponent2 == private_exponent % (prime2 - 1) \
                    and 1 == (coefficient * prime2) % prime1:
                # RSA key components are consistent
                candidate = Candidate.get_dummy_candidate(
                    self.config,  #
                    data_provider.file_path,  #
                    data_provider.file_type,  #
                    f"{data_provider.info}|SNK",  #
                    "Strong Name Key")
                candidate.severity = Severity.HIGH
                candidate.confidence = Confidence.STRONG

                # JWK representation
                def __bytes4jwk(data: bytes) -> str:
                    return base64.urlsafe_b64encode(data).rstrip(b"=").decode(ASCII, errors="strict")

                value = (f'{{"kty":"RSA","e":"{__bytes4jwk(_pub_exp)}",'
                         f'"n":"{__bytes4jwk(_modulus)}","d":"{__bytes4jwk(_private_exponent)}",'
                         f'"p":"{__bytes4jwk(_prime1)}","q":"{__bytes4jwk(_prime2)}",'
                         f'"dp":"{__bytes4jwk(_exponent1)}","dq":"{__bytes4jwk(_exponent2)}",'
                         f'"qi":"{__bytes4jwk(_coefficient)}"}}')
                candidate.line_data_list[0].line = candidate.line_data_list[0].value = value
                candidate.line_data_list[0].value_start = 0
                candidate.line_data_list[0].value_end = len(value)
                return [candidate]

            logger.debug("Components consistency check fail")
        except Exception as exc:
            logger.debug(exc)
        return None
