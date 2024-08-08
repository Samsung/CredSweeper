import contextlib
import json

from credsweeper.config import Config
from credsweeper.credentials import LineData
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.filters import Filter
from credsweeper.utils import Util


class ValueJsonWebTokenCheck(Filter):
    """
    Check that candidate is JWT which starts usually from 'eyJ'
    registered keys are checked to be in the JWT parts
    https://www.iana.org/assignments/jose/jose.xhtml
    """
    header_keys = {
        "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "alg", "enc", "zip", "jku",
        "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "epk", "apu", "apv", "iv", "tag", "p2s",
        "p2c", "iss", "sub", "aud", "b64", "ppt", "url", "nonce", "svt"
    }
    payload_keys = {
        "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "kty", "use", "key_ops", "alg", "enc", "zip", "jku", "jwk",
        "kid", "x5u", "x5c", "x5t", "x5t#S256", "crv", "x", "y", "d", "n", "e", "d", "p", "q", "dp", "dq", "qi", "oth",
        "k", "crv", "d", "x", "ext", "crit", "keys", "id", "role", "token", "secret", "password", "nonce"
    }

    def __init__(self, config: Config = None) -> None:
        pass

    def run(self, line_data: LineData, target: AnalysisTarget) -> bool:
        """Run filter checks on received token which might be structured.

        Args:
            line_data: credential candidate data
            target: multiline target from which line data was obtained

        Return:
            True, when need to filter candidate and False if left

        """
        header_check = False
        payload_check = False
        signature_check = False
        with contextlib.suppress(Exception):
            jwt_parts = line_data.value.split('.')
            for part in jwt_parts:
                data = Util.decode_base64(part, padding_safe=True, urlsafe_detect=True)
                if part.startswith("eyJ"):
                    # open part - just base64 encoded
                    json_keys = json.loads(data).keys()
                    # header will be checked first
                    if not header_check:
                        header_check = bool(ValueJsonWebTokenCheck.header_keys.intersection(json_keys))
                    # payload follows the header
                    elif not payload_check:
                        payload_check = bool(ValueJsonWebTokenCheck.payload_keys.intersection(json_keys))
                        # any other payloads are allowed
                elif header_check and payload_check and not signature_check:
                    # signature check or skip encrypted part
                    signature_check = not Util.is_ascii_entropy_validate(data)
                else:
                    break
        if header_check and payload_check and signature_check:
            return False
        else:
            return True
